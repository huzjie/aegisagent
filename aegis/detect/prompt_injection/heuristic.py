"""Heuristic (pattern + statistics) prompt-injection detector.

This is the workhorse detector: cheap, explainable and language-aware.  It
combines nine weighted technique families from :mod:`.patterns` with two
statistical checks (repetition flooding, oversized tokens) and a de-obfuscation
pass that re-scans base64 / hex / URL / ROT13 layers.

Scoring
-------
Rather than "any pattern matched -> alert", technique weights are combined with
noisy-OR so that several independent weak signals accumulate into a strong one
while a single generic phrase stays low-confidence::

    confidence = 1 - Π(1 - weight_i)     over distinct techniques that fired

Two adjustments follow:

* **Trust multiplier** - the same sentence is far more suspicious inside
  retrieved web content (``untrusted``) than inside an argument the user typed.
* **Decode bonus** - a payload that was hidden behind an encoding layer is
  intentional obfuscation, so ``+0.15`` and severity floor of HIGH.

Severity is taken from the highest-severity technique that fired.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ...core.types import DetectorKind, EvaluationContext, Finding, Severity
from ...core.utils import truncate
from ..base import Detector
from ..dedupe import noisy_or
from ..normalizer import canonical_text, decoded_variants
from ..text_sources import TextSpan, iter_spans
from .patterns import IMPERATIVE_RE, LONG_TOKEN_RE, REPETITION_RE, TECHNIQUES, Technique

__all__ = ["HeuristicInjectionDetector", "TechniqueHit"]

#: Confidence multipliers per span trust bucket.
TRUST_WEIGHTS: Dict[str, float] = {
    "untrusted": 1.0,
    "semi_trusted": 0.85,
    "declared": 0.7,
}

#: Extra confidence when the payload only became visible after decoding.
DECODE_BONUS = 0.15

#: Weight of the statistical (non-pattern) signals.
REPETITION_WEIGHT = 0.25
LONG_TOKEN_WEIGHT = 0.20
IMPERATIVE_WEIGHT = 0.10


class TechniqueHit:
    """One technique firing on one span, with its matched fragments."""

    __slots__ = ("technique", "fragments", "via")

    def __init__(self, technique: Technique, fragments: Sequence[str], via: str = "") -> None:
        """Args:
        technique: The technique that fired.
        fragments: Matched substrings (already truncated by the caller).
        via: Decode chain that exposed the payload, empty when plaintext.
        """
        self.technique = technique
        self.fragments = list(fragments)
        self.via = via

    @property
    def evidence(self) -> str:
        """One-line evidence, annotated with the decode chain when relevant."""
        prefix = f"[{self.technique.name}]"
        if self.via:
            prefix += f"[via {self.via}]"
        return f"{prefix} {truncate(' | '.join(self.fragments), 180)}"


class HeuristicInjectionDetector(Detector):
    """Weighted multi-technique prompt-injection detector (EN + ZH)."""

    name = "prompt_injection.heuristic"
    kind = DetectorKind.PROMPT_INJECTION
    default_severity = Severity.HIGH
    references = (
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    )

    def __init__(
        self,
        *,
        enabled: bool = True,
        min_confidence: float = 0.35,
        decode_layers: int = 2,
        scan_descriptor: bool = True,
        max_spans: int = 40,
        **options: object,
    ) -> None:
        """Args:
        enabled: Registry enable flag.
        min_confidence: Findings below this are dropped.
        decode_layers: How many encoding layers to peel before re-scanning.
        scan_descriptor: Also scan MCP tool/parameter descriptions.
        max_spans: Upper bound on spans examined per call.
        """
        super().__init__(enabled=enabled, **options)
        self.min_confidence = float(min_confidence)
        self.decode_layers = max(0, int(decode_layers))
        self.scan_descriptor = bool(scan_descriptor)
        self.max_spans = max(1, int(max_spans))

    # ------------------------------------------------------------------ #
    # Detector contract
    # ------------------------------------------------------------------ #
    def analyze(self, ctx: EvaluationContext) -> List[Finding]:
        """Scan every argument / retrieved-content / descriptor span."""
        findings: List[Finding] = []
        spans = iter_spans(ctx, include_descriptor=self.scan_descriptor, min_length=8)
        for span in spans[: self.max_spans]:
            finding = self._analyse_span(span)
            if finding is not None:
                findings.append(finding)
        return findings

    def analyze_text(self, text: str, location: str = "text") -> List[Finding]:
        """Scan a bare string (CLI ``aegis scan``, red-team harness)."""
        span = TextSpan(text=text or "", location=location, trust="untrusted", weight=1.0)
        finding = self._analyse_span(span)
        return [finding] if finding else []

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    def _analyse_span(self, span: TextSpan) -> Optional[Finding]:
        """Evaluate one span and build a finding when the score clears the bar."""
        if len(span.text) < 8:
            return None
        surface = canonical_text(span.text)
        hits = self._collect_hits(surface, span.text)
        statistical = self._statistical_signals(surface)
        if not hits and not statistical:
            return None

        weights = [hit.technique.weight for hit in self._distinct(hits)]
        weights.extend(weight for _, weight, _ in statistical)
        confidence = noisy_or(weights)

        decoded_via = {hit.via for hit in hits if hit.via}
        if decoded_via:
            confidence = min(0.99, confidence + DECODE_BONUS)
        confidence *= TRUST_WEIGHTS.get(span.trust, 0.85) * span.weight
        if confidence < self.min_confidence:
            return None

        severity = self._severity(hits, bool(decoded_via))
        technique_names = sorted({hit.technique.name for hit in hits})
        evidence = [hit.evidence for hit in hits[:8]]
        evidence.extend(note for note, _, _ in ((n, w, t) for n, w, t in statistical))
        evidence.append(f"span={span.location} trust={span.trust} len={len(span.text)}")

        labels = "; ".join(dict.fromkeys(hit.technique.label for hit in hits))
        description = labels or "检测到提示注入的统计学特征（重复填充 / 超长 token）"
        if decoded_via:
            description += f"（载荷经 {', '.join(sorted(decoded_via))} 编码隐藏）"

        remediation = next((h.technique.remediation for h in hits if h.technique.remediation), "")
        return self.make_finding(
            title=f"疑似提示注入：{technique_names[0] if technique_names else 'statistical'}",
            description=description,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            location=span.location,
            remediation=remediation or "将该内容标记为不可信数据，禁止其触发工具调用",
            tags=["prompt-injection", *technique_names, *(["encoded"] if decoded_via else [])],
        )

    def _collect_hits(self, surface: str, raw: str) -> List[TechniqueHit]:
        """Match techniques on the plaintext and on every decoded variant."""
        hits: List[TechniqueHit] = []
        for technique in TECHNIQUES:
            fragments = technique.search(surface)
            if fragments:
                hits.append(TechniqueHit(technique, fragments))

        if self.decode_layers:
            for variant in decoded_variants(raw, max_depth=self.decode_layers, max_variants=6):
                decoded_surface = canonical_text(variant.text)
                for technique in TECHNIQUES:
                    fragments = technique.search(decoded_surface)
                    if fragments:
                        hits.append(TechniqueHit(technique, fragments, via=variant.label))
        return hits

    @staticmethod
    def _distinct(hits: Iterable[TechniqueHit]) -> List[TechniqueHit]:
        """One hit per technique - repeated matches must not inflate the score."""
        seen: Dict[str, TechniqueHit] = {}
        for hit in hits:
            seen.setdefault(hit.technique.name, hit)
        return list(seen.values())

    @staticmethod
    def _statistical_signals(text: str) -> List[Tuple[str, float, str]]:
        """Non-pattern signals: flooding, oversized tokens, imperative density.

        Returns:
            ``(evidence_note, weight, tag)`` triples.
        """
        out: List[Tuple[str, float, str]] = []
        repetition = REPETITION_RE.search(text)
        if repetition:
            out.append((
                f"[repetition] token {repetition.group(1)!r} 连续重复 >=15 次（上下文淹没）",
                REPETITION_WEIGHT,
                "flooding",
            ))
        long_token = LONG_TOKEN_RE.search(text)
        if long_token:
            out.append((
                f"[long_token] 存在长度 {len(long_token.group(0))} 的连续无空白 token",
                LONG_TOKEN_WEIGHT,
                "flooding",
            ))
        imperatives = len(IMPERATIVE_RE.findall(text))
        if imperatives >= 4:
            out.append((
                f"[imperative] 命令式句首出现 {imperatives} 次，疑似注入指令块",
                IMPERATIVE_WEIGHT,
                "imperative",
            ))
        return out

    @staticmethod
    def _severity(hits: Sequence[TechniqueHit], decoded: bool) -> Severity:
        """Highest technique severity, floored at HIGH for encoded payloads."""
        if not hits:
            return Severity.LOW if not decoded else Severity.MEDIUM
        order = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
        worst = max((hit.technique.severity for hit in hits), key=lambda s: order[s])
        if decoded and order[worst] < order[Severity.HIGH]:
            return Severity.HIGH
        return worst
