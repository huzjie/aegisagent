"""Finding deduplication, merging and ranking.

Running fifteen detectors over the same text guarantees overlap: a base64
payload containing ``ignore previous instructions`` fires the heuristic
detector, the signature pack and the ensemble.  Presenting three near-identical
alerts to an approver destroys signal, so the pipeline collapses them.

Merge semantics
---------------
Findings are grouped by ``(detector, kind, location, normalised title)``.
Within a group the survivor keeps the **highest severity** and the
**noisy-OR combined confidence** - two independent weak observations of the
same thing are jointly stronger than either alone, which is exactly the
behaviour we want and what a simple ``max`` would lose.  Evidence and tags are
unioned with caps.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..core.types import Finding, Severity
from .base import MAX_EVIDENCE_ITEMS

__all__ = [
    "merge_findings",
    "dedupe_findings",
    "rank_findings",
    "noisy_or",
    "group_key",
    "summarise",
    "cap_findings",
]

_WHITESPACE = re.compile(r"\s+")
_SEVERITY_ORDER = {s.value: s.score for s in Severity}


def noisy_or(confidences: Sequence[float]) -> float:
    """Combine independent confidences with the noisy-OR rule.

    ``P = 1 - prod(1 - p_i)``.  Two 0.6 observations become 0.84; a single 0.6
    stays 0.6.  Values are clamped to ``[0, 0.99]`` beforehand so the result
    never reaches an unjustified certainty of 1.0.
    """
    product = 1.0
    for value in confidences:
        product *= 1.0 - max(0.0, min(0.99, float(value)))
    return round(1.0 - product, 4)


def group_key(finding: Finding) -> Tuple[str, str, str, str]:
    """Grouping key: same detector, kind, location and (normalised) title."""
    title = _WHITESPACE.sub(" ", (finding.title or "").strip().lower())
    return finding.detector, finding.kind.value, finding.location or "", title


def merge_findings(findings: Iterable[Finding]) -> List[Finding]:
    """Collapse duplicate findings, keeping the strongest interpretation.

    The first finding of each group is mutated in place and returned; later
    duplicates contribute their evidence, tags, references and confidence.

    Args:
        findings: Raw findings from all detectors.

    Returns:
        One finding per group, in first-seen order.
    """
    groups: Dict[Tuple[str, str, str, str], Finding] = {}
    confidences: Dict[Tuple[str, str, str, str], List[float]] = {}
    order: List[Tuple[str, str, str, str]] = []

    for finding in findings:
        key = group_key(finding)
        if key not in groups:
            groups[key] = finding
            confidences[key] = [finding.confidence]
            order.append(key)
            continue
        survivor = groups[key]
        confidences[key].append(finding.confidence)
        if _SEVERITY_ORDER[finding.severity.value] > _SEVERITY_ORDER[survivor.severity.value]:
            survivor.severity = finding.severity
        seen_evidence = set(survivor.evidence)
        for item in finding.evidence:
            if item not in seen_evidence and len(survivor.evidence) < MAX_EVIDENCE_ITEMS:
                survivor.evidence.append(item)
                seen_evidence.add(item)
        survivor.tags = sorted(set(survivor.tags) | set(finding.tags))
        survivor.references = list(dict.fromkeys([*survivor.references, *finding.references]))[:8]
        if not survivor.remediation and finding.remediation:
            survivor.remediation = finding.remediation
        if len(finding.description) > len(survivor.description):
            survivor.description = finding.description

    for key in order:
        values = confidences[key]
        if len(values) > 1:
            groups[key].confidence = noisy_or(values)
    return [groups[key] for key in order]


def dedupe_findings(findings: Iterable[Finding], *, cross_detector: bool = False) -> List[Finding]:
    """Remove duplicates, optionally across detector boundaries.

    Args:
        findings: Findings to deduplicate.
        cross_detector: When ``True``, two detectors reporting the same title at
            the same location collapse into one (the higher weighted score
            wins).  Off by default because attribution is usually worth keeping.
    """
    merged = merge_findings(findings)
    if not cross_detector:
        return merged
    best: Dict[Tuple[str, str, str], Finding] = {}
    order: List[Tuple[str, str, str]] = []
    for finding in merged:
        title = _WHITESPACE.sub(" ", (finding.title or "").strip().lower())
        key = (finding.kind.value, finding.location or "", title)
        current = best.get(key)
        if current is None:
            best[key] = finding
            order.append(key)
        elif finding.weighted_score > current.weighted_score:
            finding.evidence = list(dict.fromkeys([*finding.evidence, *current.evidence]))[:MAX_EVIDENCE_ITEMS]
            finding.tags = sorted(set(finding.tags) | set(current.tags))
            best[key] = finding
    return [best[key] for key in order]


def rank_findings(findings: Sequence[Finding]) -> List[Finding]:
    """Sort by weighted score, then severity, then confidence - all descending.

    Ties fall back to the title so ordering is deterministic across runs, which
    matters for reproducible audit records.
    """
    return sorted(
        findings,
        key=lambda f: (-f.weighted_score, -_SEVERITY_ORDER[f.severity.value], -f.confidence, f.title),
    )


def cap_findings(findings: Sequence[Finding], limit: int = 50) -> List[Finding]:
    """Keep the highest-ranked ``limit`` findings.

    Always preserves at least one finding per severity tier present in the
    input, so a flood of medium alerts can never hide the single critical one.
    """
    if len(findings) <= limit:
        return list(findings)
    ranked = rank_findings(findings)
    kept: List[Finding] = []
    seen_severities: set[str] = set()
    for finding in ranked:
        if finding.severity.value not in seen_severities:
            kept.append(finding)
            seen_severities.add(finding.severity.value)
    for finding in ranked:
        if len(kept) >= limit:
            break
        if finding not in kept:
            kept.append(finding)
    return rank_findings(kept)[:limit]


def filter_by_confidence(findings: Sequence[Finding], threshold: float) -> List[Finding]:
    """Drop findings below ``threshold``, except CRITICAL ones.

    A critical finding with low confidence still deserves human eyes; silently
    dropping it is how gateways miss real incidents.
    """
    return [
        f for f in findings
        if f.confidence >= threshold or f.severity is Severity.CRITICAL
    ]


def summarise(findings: Sequence[Finding]) -> Dict[str, object]:
    """Aggregate counts used by the decision explanation and the API."""
    by_severity: Dict[str, int] = {}
    by_kind: Dict[str, int] = {}
    by_detector: Dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity.value] = by_severity.get(finding.severity.value, 0) + 1
        by_kind[finding.kind.value] = by_kind.get(finding.kind.value, 0) + 1
        by_detector[finding.detector] = by_detector.get(finding.detector, 0) + 1
    top = rank_findings(findings)[:3]
    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_kind": by_kind,
        "by_detector": by_detector,
        "max_score": round(max((f.weighted_score for f in findings), default=0.0), 2),
        "top": [{"title": f.title, "severity": f.severity.value, "confidence": f.confidence} for f in top],
    }


def highest_severity(findings: Sequence[Finding], default: Severity = Severity.INFO) -> Severity:
    """Strictest severity present in ``findings``."""
    if not findings:
        return default
    return max(findings, key=lambda f: _SEVERITY_ORDER[f.severity.value]).severity


def find_by_kind(findings: Sequence[Finding], kind: str) -> List[Finding]:
    """All findings of a given :class:`DetectorKind` value."""
    return [f for f in findings if f.kind.value == kind]


def optional_first(findings: Sequence[Finding]) -> Optional[Finding]:
    """Highest-ranked finding, or ``None`` when the list is empty."""
    ranked = rank_findings(findings)
    return ranked[0] if ranked else None
