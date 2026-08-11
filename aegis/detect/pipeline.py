"""End-to-end detection pipeline.

Wraps the registry with the pre/post-processing every caller needs:

1. run all detectors (parallel, timeout-isolated) via :class:`DetectorRegistry`;
2. merge duplicate observations (noisy-OR confidence) and drop low-confidence
   noise;
3. rank, cap and summarise the result;
4. write the aggregate risk back onto the :class:`EvaluationContext` so the
   policy engine can reference ``risk`` / ``risk_score`` conditions.

This is the single function the gateway and MCP proxy call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from ..core.config import Settings, get_settings
from ..core.logging import get_logger
from ..core.types import (
    DetectorKind,
    EvaluationContext,
    Finding,
    RiskLevel,
    Severity,
    utc_now,
)
from ..core.utils import Stopwatch
from .base import DetectorResult
from .dedupe import cap_findings, dedupe_findings, rank_findings, summarise
from .registry import DetectorRegistry

LOGGER = get_logger("detect.pipeline")

#: Hard cap on how many findings survive one evaluation.
MAX_FINDINGS = 50


@dataclass
class DetectionReport:
    """Everything one detection pass produced.

    Attributes:
        findings: Deduplicated, ranked findings.
        results: Per-detector execution metadata (timings, errors, timeouts).
        risk: Aggregate risk band derived from the findings.
        risk_score: Aggregate score in ``[0, 100]``.
        duration_ms: Total wall-clock time of the pass.
        errors: Names of detectors that failed or timed out.
    """

    findings: List[Finding] = field(default_factory=list)
    results: List[DetectorResult] = field(default_factory=list)
    risk: RiskLevel = RiskLevel.NONE
    risk_score: float = 0.0
    duration_ms: float = 0.0
    errors: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=utc_now)

    @property
    def blocked_recommended(self) -> bool:
        """True when the aggregate risk warrants blocking by default."""
        return self.risk.at_least(RiskLevel.HIGH)

    @property
    def worst(self) -> Optional[Finding]:
        """Highest weighted-score finding, if any."""
        return self.findings[0] if self.findings else None

    def kinds(self) -> List[str]:
        """Distinct detector kinds represented in the findings."""
        return sorted({f.kind.value for f in self.findings})

    def to_dict(self) -> Dict[str, Any]:
        """JSON-safe rendering for the API and the audit ledger."""
        return {
            "risk": self.risk.value,
            "risk_score": round(self.risk_score, 2),
            "duration_ms": round(self.duration_ms, 3),
            "findings": len(self.findings),
            "errors": list(self.errors),
            "summary": summarise(self.findings),
            "detectors": [r.to_dict() for r in self.results],
        }


def aggregate_risk(findings: Sequence[Finding]) -> float:
    """Combine findings into a single 0-100 risk score.

    The strongest finding dominates; every additional independent finding adds a
    decaying contribution so a pile of medium signals can still reach HIGH
    without a single one of them being decisive.
    """
    if not findings:
        return 0.0
    scores = sorted((f.weighted_score for f in findings), reverse=True)
    total = scores[0]
    for index, score in enumerate(scores[1:8], start=1):
        total += score * (0.5 ** index)
    return round(min(100.0, total), 2)


class DetectionPipeline:
    """Runs the registry and post-processes its output."""

    def __init__(
        self,
        registry: Optional[DetectorRegistry] = None,
        *,
        min_confidence: float = 0.35,
        max_findings: int = MAX_FINDINGS,
        cross_detector_dedupe: bool = True,
    ) -> None:
        """Args:
        registry: Detector registry; a default one is built when omitted.
        min_confidence: Findings below this confidence are discarded.
        max_findings: Cap applied after ranking.
        cross_detector_dedupe: Merge identical observations across detectors.
        """
        self.registry = registry or DetectorRegistry.default()
        self.min_confidence = float(min_confidence)
        self.max_findings = int(max_findings)
        self.cross_detector_dedupe = bool(cross_detector_dedupe)

    @classmethod
    def from_settings(cls, settings: Optional[Settings] = None) -> "DetectionPipeline":
        """Build a pipeline from the ``detection`` configuration section."""
        settings = settings or get_settings()
        detection = settings.section("detection")
        registry = DetectorRegistry.from_settings(settings)
        return cls(
            registry,
            min_confidence=float(detection.get("min_confidence", 0.35)),
        )

    def run(self, ctx: EvaluationContext, *, mutate_context: bool = True) -> DetectionReport:
        """Execute the full pass and (optionally) enrich the context.

        Args:
            ctx: Evaluation context under judgement.
            mutate_context: Write findings / risk back onto ``ctx`` so downstream
                policy conditions can reference them.

        Returns:
            A :class:`DetectionReport`.
        """
        watch = Stopwatch()
        with watch:
            results = self.registry.run_detailed(ctx)
            raw: List[Finding] = []
            errors: List[str] = []
            for result in results:
                if not result.ok:
                    errors.append(f"{result.detector}: {result.error or 'timeout'}")
                raw.extend(result.findings)
            kept = [f for f in raw if f.confidence >= self.min_confidence]
            merged = dedupe_findings(kept, cross_detector=self.cross_detector_dedupe)
            ranked = cap_findings(rank_findings(merged), self.max_findings)
            score = aggregate_risk(ranked)

        report = DetectionReport(
            findings=ranked,
            results=results,
            risk=RiskLevel.from_score(score),
            risk_score=score,
            duration_ms=watch.elapsed_ms,
            errors=errors,
        )
        if mutate_context:
            self.apply(ctx, report)
        if errors:
            LOGGER.warning("detectors reported failures", count=len(errors), detail=";".join(errors[:3]))
        return report

    def apply(self, ctx: EvaluationContext, report: DetectionReport) -> None:
        """Copy a report's conclusions onto the evaluation context."""
        ctx.findings = list(report.findings)
        ctx.risk_score = report.risk_score
        ctx.risk = report.risk
        ctx.extra.setdefault("detection", {})
        if isinstance(ctx.extra["detection"], dict):
            ctx.extra["detection"].update(report.to_dict())

    def scan_text(self, text: str, location: str = "text") -> List[Finding]:
        """Ad-hoc content scan outside of any tool call (CLI / connect-time).

        Only detectors implementing :meth:`Detector.analyze_text` contribute.
        """
        findings: List[Finding] = []
        for name in self.registry.enabled_names():
            detector = self.registry.get(name)
            if detector is None:
                continue
            try:
                findings.extend(detector.analyze_text(text, location) or [])
            except Exception as exc:  # noqa: BLE001 - isolation
                LOGGER.warning("text scan failed", detector=name, error=str(exc))
        kept = [f for f in findings if f.confidence >= self.min_confidence]
        return cap_findings(rank_findings(dedupe_findings(kept, cross_detector=True)), self.max_findings)

    def stats(self) -> Dict[str, Any]:
        """Registry statistics plus pipeline tuning."""
        data = self.registry.stats()
        data["min_confidence"] = self.min_confidence
        data["max_findings"] = self.max_findings
        return data

    def close(self) -> None:
        """Release the registry's worker pool."""
        self.registry.close()


def detect(ctx: EvaluationContext, *, settings: Optional[Settings] = None) -> DetectionReport:
    """Convenience one-shot: build a pipeline from settings and run it once.

    Prefer keeping a long-lived :class:`DetectionPipeline` in the request path;
    this helper exists for scripts, tests and the CLI.
    """
    return DetectionPipeline.from_settings(settings).run(ctx)
