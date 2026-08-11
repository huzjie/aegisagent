"""Weighted-vote ensemble over the four prompt-injection detectors.

The sub-detectors have very different precision/recall profiles:

============================  ======  ==========================================
Detector                      Weight  Rationale
============================  ======  ==========================================
``structural``                 0.30   Highest precision - hidden markup carrying
                                      an instruction has almost no benign cause.
``unicode``                    0.28   Very high precision; tag characters and
                                      zero-width binary channels are never
                                      accidental.
``heuristic``                  0.27   Broadest recall, moderate precision; the
                                      only detector that catches plain-language
                                      attacks.
``llm_judge``                  0.15   Catches paraphrase the rules miss, but is
                                      itself injectable and usually disabled.
============================  ======  ==========================================

The ensemble emits **one** aggregated finding so the approval UI shows a single
verdict, while every contributing finding is preserved in ``evidence`` and in
:attr:`EnsembleInjectionDetector.last_children` for the audit record.

Aggregation formula::

    raw   = Σ (weight_d × max_confidence_d)        over detectors that fired
    boost = 1 + 0.12 × (distinct_detectors - 1)    independent corroboration
    score = min(0.99, raw × boost / Σ weights_fired) ... normalised, then
            re-scaled so a single strong detector cannot alone exceed its cap

Normalising by the weights that actually fired (rather than by the total)
prevents the ensemble from silently under-reporting when the judge is disabled.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from ...core.types import DetectorKind, EvaluationContext, Finding, Severity
from ...core.utils import truncate
from ..base import Detector
from ..dedupe import rank_findings
from .heuristic import HeuristicInjectionDetector
from .llm_judge import LlmJudgeDetector
from .structural import StructuralInjectionDetector
from .unicode_attack import UnicodeAttackDetector

__all__ = ["EnsembleInjectionDetector", "DEFAULT_WEIGHTS", "EnsembleVote"]

#: Per-detector vote weights; overridable through the constructor or config.
DEFAULT_WEIGHTS: Dict[str, float] = {
    "prompt_injection.structural": 0.30,
    "prompt_injection.unicode": 0.28,
    "prompt_injection.heuristic": 0.27,
    "prompt_injection.llm_judge": 0.15,
}

#: Extra confidence per additional independent detector that agreed.
CORROBORATION_BONUS = 0.12

#: A single detector alone can never push the ensemble above this.
SINGLE_DETECTOR_CAP = 0.85

_SEVERITY_ORDER = {
    Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4,
}


@dataclass
class EnsembleVote:
    """One detector's contribution to the aggregate.

    Attributes:
        detector: Sub-detector name.
        weight: Configured vote weight.
        confidence: Highest confidence that detector reported.
        severity: Highest severity that detector reported.
        findings: The underlying findings, retained as sub-evidence.
    """

    detector: str
    weight: float
    confidence: float
    severity: Severity
    findings: List[Finding] = field(default_factory=list)

    @property
    def contribution(self) -> float:
        """Weighted contribution to the raw score."""
        return self.weight * self.confidence

    def summary(self) -> str:
        """Compact one-line rendering used as ensemble evidence."""
        titles = "; ".join(dict.fromkeys(f.title for f in self.findings))[:120]
        return (
            f"[vote:{self.detector}] w={self.weight:.2f} conf={self.confidence:.2f} "
            f"sev={self.severity.value} :: {titles}"
        )


class EnsembleInjectionDetector(Detector):
    """Combines the heuristic, unicode, structural and judge detectors."""

    name = "prompt_injection"
    kind = DetectorKind.PROMPT_INJECTION
    default_severity = Severity.HIGH
    references = (
        "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
        "https://atlas.mitre.org/techniques/AML.T0051",
    )

    def __init__(
        self,
        *,
        enabled: bool = True,
        heuristic: Optional[HeuristicInjectionDetector] = None,
        unicode_detector: Optional[UnicodeAttackDetector] = None,
        structural: Optional[StructuralInjectionDetector] = None,
        judge: Optional[LlmJudgeDetector] = None,
        weights: Optional[Dict[str, float]] = None,
        threshold: float = 0.4,
        emit_children: bool = False,
        **options: object,
    ) -> None:
        """Args:
        enabled: Registry enable flag.
        heuristic / unicode_detector / structural / judge: Sub-detector
            instances; defaults are constructed when omitted.
        weights: Override :data:`DEFAULT_WEIGHTS` (partial overrides merge).
        threshold: Minimum aggregate score before a finding is emitted.
        emit_children: When ``True`` the child findings are returned alongside
            the aggregate (useful for debugging, noisy in production).
        """
        super().__init__(enabled=enabled, **options)
        self.heuristic = heuristic or HeuristicInjectionDetector()
        self.unicode = unicode_detector or UnicodeAttackDetector()
        self.structural = structural or StructuralInjectionDetector()
        self.judge = judge or LlmJudgeDetector(enabled=False)
        self.weights: Dict[str, float] = {**DEFAULT_WEIGHTS, **(weights or {})}
        self.threshold = float(threshold)
        self.emit_children = bool(emit_children)
        self.last_children: List[Finding] = []

    # ------------------------------------------------------------------ #
    # Composition
    # ------------------------------------------------------------------ #
    @property
    def children(self) -> Tuple[Detector, ...]:
        """The sub-detectors in vote order."""
        return (self.structural, self.unicode, self.heuristic, self.judge)

    def analyze(self, ctx: EvaluationContext) -> List[Finding]:
        """Run all sub-detectors and fuse their verdicts."""
        collected: Dict[str, List[Finding]] = {}
        for child in self.children:
            if not child.enabled:
                continue
            result = child.run(ctx)
            if result.findings:
                collected[child.name] = result.findings
        return self._fuse(collected, location=self._dominant_location(collected))

    def analyze_text(self, text: str, location: str = "text") -> List[Finding]:
        """Run all sub-detectors over a bare string and fuse the verdicts."""
        collected: Dict[str, List[Finding]] = {}
        for child in self.children:
            if not child.enabled:
                continue
            try:
                findings = child.analyze_text(text, location) or []
            except Exception as exc:  # noqa: BLE001 - isolation
                self._log.warning("sub-detector failed", child=child.name, error=str(exc))
                continue
            if findings:
                collected[child.name] = findings
        return self._fuse(collected, location=location)

    # ------------------------------------------------------------------ #
    # Fusion
    # ------------------------------------------------------------------ #
    def _fuse(self, collected: Dict[str, List[Finding]], location: str) -> List[Finding]:
        """Turn per-detector findings into one aggregated finding."""
        self.last_children = [f for group in collected.values() for f in group]
        if not collected:
            return []

        votes = self._build_votes(collected)
        score = self.aggregate_score(votes)
        if score < self.threshold:
            return []

        severity = self._aggregate_severity(votes, score)
        evidence = [vote.summary() for vote in votes]
        for finding in rank_findings(self.last_children)[:4]:
            evidence.append(f"[sub:{finding.detector}] {truncate('; '.join(finding.evidence) or finding.title, 180)}")

        tags = sorted({tag for f in self.last_children for tag in f.tags} | {"prompt-injection", "ensemble"})
        detectors = ", ".join(vote.detector.rsplit(".", 1)[-1] for vote in votes)
        aggregate = self.make_finding(
            title=f"提示注入综合判定（{len(votes)} 个检测器投票命中）",
            description=(
                f"加权投票得分 {score:.2f}（阈值 {self.threshold:.2f}），"
                f"命中检测器：{detectors}。"
                + "; ".join(dict.fromkeys(f.description for f in self.last_children))[:400]
            ),
            severity=severity,
            confidence=score,
            evidence=evidence,
            location=location,
            remediation="将该内容源标记为不可信；阻断由其驱动的工具调用并要求人工审批",
            tags=tags,
        )
        return [aggregate, *self.last_children] if self.emit_children else [aggregate]

    def _build_votes(self, collected: Dict[str, List[Finding]]) -> List[EnsembleVote]:
        """Reduce each detector's findings to a single weighted vote."""
        votes: List[EnsembleVote] = []
        for detector, findings in collected.items():
            if not findings:
                continue
            best_confidence = max(f.confidence for f in findings)
            best_severity = max((f.severity for f in findings), key=lambda s: _SEVERITY_ORDER[s])
            votes.append(
                EnsembleVote(
                    detector=detector,
                    weight=self.weights.get(detector, 0.2),
                    confidence=best_confidence,
                    severity=best_severity,
                    findings=list(findings),
                )
            )
        votes.sort(key=lambda v: v.contribution, reverse=True)
        return votes

    def aggregate_score(self, votes: Sequence[EnsembleVote]) -> float:
        """Compute the normalised, corroboration-boosted ensemble score.

        Args:
            votes: One vote per detector that produced findings.

        Returns:
            Score in ``[0, 0.99]``.  A lone detector is capped at
            :data:`SINGLE_DETECTOR_CAP` so no single component can assert
            certainty by itself.
        """
        if not votes:
            return 0.0
        weight_sum = sum(vote.weight for vote in votes) or 1.0
        raw = sum(vote.contribution for vote in votes) / weight_sum
        boost = 1.0 + CORROBORATION_BONUS * (len(votes) - 1)
        score = raw * boost
        if len(votes) == 1:
            score = min(score, SINGLE_DETECTOR_CAP)
        return round(max(0.0, min(0.99, score)), 4)

    @staticmethod
    def _aggregate_severity(votes: Sequence[EnsembleVote], score: float) -> Severity:
        """Highest child severity, escalated when several detectors agree."""
        if not votes:
            return Severity.LOW
        severity = max((vote.severity for vote in votes), key=lambda s: _SEVERITY_ORDER[s])
        if len(votes) >= 3 and score >= 0.8 and _SEVERITY_ORDER[severity] < _SEVERITY_ORDER[Severity.CRITICAL]:
            return Severity.CRITICAL
        if len(votes) >= 2 and _SEVERITY_ORDER[severity] < _SEVERITY_ORDER[Severity.HIGH]:
            return Severity.HIGH
        return severity

    @staticmethod
    def _dominant_location(collected: Dict[str, List[Finding]]) -> str:
        """Most frequently reported location across all child findings."""
        counts: Dict[str, int] = {}
        for findings in collected.values():
            for finding in findings:
                if finding.location:
                    counts[finding.location] = counts.get(finding.location, 0) + 1
        if not counts:
            return "content"
        return max(counts.items(), key=lambda item: item[1])[0]

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #
    def set_weight(self, detector: str, weight: float) -> None:
        """Adjust one detector's vote weight at runtime."""
        self.weights[detector] = max(0.0, float(weight))

    def describe(self) -> Dict[str, object]:
        data = super().describe()
        data["threshold"] = self.threshold
        data["weights"] = dict(self.weights)
        data["children"] = [child.describe() for child in self.children]
        return data
