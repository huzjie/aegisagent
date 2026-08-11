"""Detector abstraction shared by every analysis module.

A detector is a stateless-ish object that turns an :class:`EvaluationContext`
(or a bare string) into zero or more :class:`Finding` objects.  The base class
provides the boring parts - identity, enable flag, evidence truncation, finding
construction - so concrete detectors contain only detection logic.

Two composition helpers live here as well:

``CompositeDetector``
    Runs a fixed list of detectors sequentially and concatenates the findings.
    Used to expose a family (e.g. all prompt-injection sub-detectors) as one
    registry entry.

``DetectorResult``
    Wraps findings with timing/error metadata so the registry can report which
    detector was slow or crashed without losing the successful results.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence

from ..core.errors import DetectionError
from ..core.logging import get_logger
from ..core.types import DetectorKind, EvaluationContext, Finding, Severity, utc_now
from ..core.utils import Stopwatch, truncate

__all__ = [
    "Detector",
    "CompositeDetector",
    "DetectorResult",
    "EVIDENCE_LIMIT",
    "MAX_EVIDENCE_ITEMS",
    "clamp_confidence",
]

LOGGER = get_logger("detect.base")

#: Maximum characters kept per evidence string.
EVIDENCE_LIMIT = 240

#: Maximum number of evidence entries attached to one finding.
MAX_EVIDENCE_ITEMS = 12


def clamp_confidence(value: float) -> float:
    """Clamp a confidence into ``[0.0, 1.0]`` and round for stable output."""
    return round(max(0.0, min(1.0, float(value))), 4)


@dataclass
class DetectorResult:
    """Outcome of running one detector, including failure metadata.

    Attributes:
        detector: Detector name.
        findings: Findings produced (empty on error or timeout).
        duration_ms: Wall-clock execution time.
        error: Error message when the detector raised.
        timed_out: Whether the registry cancelled it on the deadline.
        skipped: Whether it was skipped (disabled or not applicable).
    """

    detector: str
    findings: List[Finding] = field(default_factory=list)
    duration_ms: float = 0.0
    error: str = ""
    timed_out: bool = False
    skipped: bool = False

    @property
    def ok(self) -> bool:
        """True when the detector ran to completion."""
        return not self.error and not self.timed_out

    @property
    def count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detector": self.detector,
            "findings": self.count,
            "duration_ms": round(self.duration_ms, 3),
            "error": self.error,
            "timed_out": self.timed_out,
            "skipped": self.skipped,
        }


class Detector(abc.ABC):
    """Base class for all AegisAgent detectors.

    Subclasses must set :attr:`name` / :attr:`kind` and implement
    :meth:`analyze`.  Implementing :meth:`analyze_text` as well is recommended
    so the detector can also be used for ad-hoc content scanning (CLI, red-team
    harness, MCP tool-description scanning at connect time).
    """

    #: Stable identifier used in config, metrics and finding attribution.
    name: str = "detector"

    #: Which family this detector belongs to.
    kind: DetectorKind = DetectorKind.CONTENT

    #: Severity used by :meth:`make_finding` when none is supplied.
    default_severity: Severity = Severity.MEDIUM

    #: Confidence below which the detector drops its own findings.
    min_confidence: float = 0.0

    #: Reference links attached to every finding this detector emits.
    references: Sequence[str] = ()

    def __init__(self, *, enabled: bool = True, **options: Any) -> None:
        """Initialise the detector.

        Args:
            enabled: When ``False`` the registry skips this detector entirely.
            **options: Detector-specific tuning, retained on :attr:`options`.
        """
        self.enabled = bool(enabled)
        self.options: Dict[str, Any] = dict(options)
        self._log = get_logger(f"detect.{self.name}")

    # ------------------------------------------------------------------ #
    # Contract
    # ------------------------------------------------------------------ #
    @abc.abstractmethod
    def analyze(self, ctx: EvaluationContext) -> List[Finding]:
        """Inspect a full evaluation context.

        Args:
            ctx: The tool call plus its surrounding session/tool metadata.

        Returns:
            Findings, possibly empty.  Implementations must not raise for
            ordinary "nothing found" cases; raise :class:`DetectionError` only
            for genuine internal failures.
        """

    def analyze_text(self, text: str, location: str = "text") -> List[Finding]:
        """Inspect a bare string outside of any tool call.

        The default implementation returns nothing; detectors whose logic is
        purely textual override this and route :meth:`analyze` through it.

        Args:
            text: Content to scan.
            location: Provenance label recorded on findings.
        """
        return []

    def iter_targets(self, ctx: EvaluationContext) -> "Iterator[tuple[str, str]]":
        """Yield ``(location, text)`` pairs worth scanning for this detector.

        The default implementation covers every surface a tool call can carry
        untrusted content through: the request arguments, third-party
        ``untrusted_content`` / ``tool_result`` stashed in ``ctx.extra``, and the
        tool's own declared surface (description + parameter docs, the surface
        abused by tool-poisoning).  Subclasses reuse it instead of re-deriving
        the same traversal.
        """
        from .text_sources import iter_spans

        for span in iter_spans(ctx):
            text = span.text
            if text:
                yield (span.location, text)
    # ------------------------------------------------------------------ #
    # Helpers for subclasses
    # ------------------------------------------------------------------ #
    def make_finding(
        self,
        title: str,
        *,
        description: str = "",
        severity: Optional[Severity] = None,
        confidence: float = 0.5,
        evidence: Optional[Iterable[str]] = None,
        location: str = "",
        remediation: str = "",
        tags: Optional[Iterable[str]] = None,
        references: Optional[Iterable[str]] = None,
        kind: Optional[DetectorKind] = None,
    ) -> Finding:
        """Build a :class:`Finding` with this detector's identity applied.

        Evidence strings are truncated and capped so a noisy match cannot blow
        up the audit ledger, and confidence is clamped into ``[0, 1]``.
        """
        items = [truncate(str(item), EVIDENCE_LIMIT) for item in (evidence or []) if str(item).strip()]
        return Finding(
            detector=self.name,
            kind=kind or self.kind,
            severity=severity or self.default_severity,
            title=title,
            description=description or title,
            confidence=clamp_confidence(confidence),
            evidence=items[:MAX_EVIDENCE_ITEMS],
            location=location,
            remediation=remediation,
            references=list(references) if references is not None else list(self.references),
            tags=sorted({str(t) for t in (tags or [])}),
            created_at=utc_now(),
        )

    def filter_findings(self, findings: Sequence[Finding]) -> List[Finding]:
        """Drop findings below :attr:`min_confidence`, preserving order."""
        threshold = self.min_confidence
        return [f for f in findings if f.confidence >= threshold]

    def run(self, ctx: EvaluationContext) -> DetectorResult:
        """Execute :meth:`analyze` with timing and exception containment.

        A detector that raises must never break the enforcement path: the
        exception is recorded on the result and an empty finding list returned.
        """
        if not self.enabled:
            return DetectorResult(detector=self.name, skipped=True)
        watch = Stopwatch()
        try:
            with watch:
                findings = self.filter_findings(self.analyze(ctx) or [])
            return DetectorResult(detector=self.name, findings=findings, duration_ms=watch.elapsed_ms)
        except DetectionError as exc:
            self._log.warning("detector failed", detector=self.name, error=str(exc))
            return DetectorResult(detector=self.name, duration_ms=watch.elapsed_ms, error=str(exc))
        except Exception as exc:  # noqa: BLE001 - isolation is the whole point
            self._log.warning(
                "detector raised unexpectedly", detector=self.name, error=f"{type(exc).__name__}: {exc}"
            )
            return DetectorResult(
                detector=self.name,
                duration_ms=watch.elapsed_ms,
                error=f"{type(exc).__name__}: {exc}",
            )

    # ------------------------------------------------------------------ #
    # Dunders
    # ------------------------------------------------------------------ #
    def describe(self) -> Dict[str, Any]:
        """Machine-readable summary used by ``/v1/detectors`` and the CLI."""
        return {
            "name": self.name,
            "kind": self.kind.value,
            "enabled": self.enabled,
            "default_severity": self.default_severity.value,
            "min_confidence": self.min_confidence,
            "options": {k: v for k, v in self.options.items() if not k.startswith("_")},
            "doc": (self.__class__.__doc__ or "").strip().splitlines()[0] if self.__class__.__doc__ else "",
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        state = "on" if self.enabled else "off"
        return f"<{self.__class__.__name__} name={self.name} kind={self.kind.value} {state}>"


class CompositeDetector(Detector):
    """Runs several detectors as a single logical unit.

    Child failures are contained: a broken member contributes no findings but
    the others still run.  The composite reports the union of their findings.
    """

    def __init__(
        self,
        name: str,
        children: Sequence[Detector],
        *,
        kind: Optional[DetectorKind] = None,
        enabled: bool = True,
        **options: Any,
    ) -> None:
        """Args:
        name: Registry name for the composite.
        children: Member detectors, executed in the given order.
        kind: Overrides the kind (defaults to the first child's kind).
        enabled: Enable flag for the whole group.
        """
        self.name = name
        self.children: List[Detector] = list(children)
        self.kind = kind or (self.children[0].kind if self.children else DetectorKind.CONTENT)
        super().__init__(enabled=enabled, **options)

    def analyze(self, ctx: EvaluationContext) -> List[Finding]:
        """Concatenate findings from every enabled child."""
        out: List[Finding] = []
        for child in self.children:
            if not child.enabled:
                continue
            result = child.run(ctx)
            out.extend(result.findings)
        return out

    def analyze_text(self, text: str, location: str = "text") -> List[Finding]:
        """Concatenate text-mode findings from every enabled child."""
        out: List[Finding] = []
        for child in self.children:
            if not child.enabled:
                continue
            try:
                out.extend(child.analyze_text(text, location) or [])
            except Exception as exc:  # noqa: BLE001
                self._log.warning("child detector failed", child=child.name, error=str(exc))
        return out

    def add(self, detector: Detector) -> "CompositeDetector":
        """Append a child detector and return self for chaining."""
        self.children.append(detector)
        return self

    def describe(self) -> Dict[str, Any]:
        data = super().describe()
        data["children"] = [child.describe() for child in self.children]
        return data
