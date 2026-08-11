"""Unicode-layer prompt smuggling detector.

Five distinct techniques hide instructions from humans and naive filters while
remaining perfectly legible to the model:

1. **Zero-width characters** (U+200B/C/D, U+FEFF, U+00AD ...) interleaved with a
   payload, or used as an invisible separator inside a keyword.
2. **Bidirectional overrides** (U+202E RLO, U+2066-2069 isolates) that make
   displayed text read differently from its logical order - the trick behind
   "Trojan Source" and used to disguise ``exe.txt`` style arguments.
3. **Homoglyphs** - Cyrillic/Greek lookalikes defeating exact-match rules.
4. **Variation selectors** (U+FE00-FE0F, U+E0100-E01EF) appended to characters,
   invisible but preserved through tokenisation.
5. **Tag characters** (U+E0000 block) - a full invisible ASCII alphabet.  This
   is the most dangerous variant because an entire English instruction can be
   encoded with zero visible output.

Crucially the detector **recovers** the hidden text: findings carry the decoded
instruction as evidence, so an analyst sees the actual payload rather than
"suspicious unicode detected".
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from ...core.types import DetectorKind, EvaluationContext, Finding, Severity
from ...core.utils import count_invisible, truncate
from ..base import Detector
from ..homoglyphs import confusable_characters, detect_mixed_script, skeleton
from ..text_sources import TextSpan, iter_spans
from .patterns import TECHNIQUES

__all__ = ["UnicodeAttackDetector", "UnicodeAnomaly", "decode_tag_characters", "extract_hidden_text"]

#: Zero-width and soft-hyphen characters used as invisible filler.
ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\u2060\ufeff\u180e\u00ad\u2061\u2062\u2063\u2064"

#: Bidirectional control characters.  RLO/LRO actively reorder rendering.
BIDI_CONTROLS = {
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "POP DIRECTIONAL FORMATTING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
    "\u2068": "FIRST STRONG ISOLATE",
    "\u2069": "POP DIRECTIONAL ISOLATE",
    "\u061c": "ARABIC LETTER MARK",
    "\u200e": "LEFT-TO-RIGHT MARK",
    "\u200f": "RIGHT-TO-LEFT MARK",
}

#: The overrides that actually flip rendering order (higher severity than marks).
BIDI_OVERRIDES = {"\u202d", "\u202e", "\u2066", "\u2067"}

#: Unicode Tag block - maps 1:1 onto printable ASCII.
TAG_BLOCK_START = 0xE0000
TAG_BLOCK_END = 0xE007F

_VARIATION_SELECTOR_RE = re.compile(r"[\ufe00-\ufe0f\U000e0100-\U000e01ef]")
_ZERO_WIDTH_RE = re.compile(f"[{ZERO_WIDTH_CHARS}]")
_TAG_RE = re.compile(r"[\U000e0000-\U000e007f]+")

#: Ratio of invisible characters above which even a benign-looking string is
#: treated as a carrier.
INVISIBLE_RATIO_THRESHOLD = 0.08


@dataclass
class UnicodeAnomaly:
    """One unicode-layer anomaly found in a span.

    Attributes:
        technique: ``zero_width`` / ``bidi`` / ``homoglyph`` /
            ``variation_selector`` / ``tag_characters``.
        label: Chinese description shown to the analyst.
        severity: Severity contributed by this anomaly.
        weight: Confidence contribution.
        evidence: Evidence lines, including any recovered plaintext.
        recovered: Text decoded out of the hidden channel (may be empty).
    """

    technique: str
    label: str
    severity: Severity
    weight: float
    evidence: List[str]
    recovered: str = ""


def decode_tag_characters(text: str) -> str:
    """Decode U+E0000-block tag characters back into ASCII.

    ``U+E0041`` is the tag form of ``A``.  An attacker can therefore write a
    complete instruction that renders as nothing at all.
    """
    out: List[str] = []
    for ch in text or "":
        code = ord(ch)
        if TAG_BLOCK_START <= code <= TAG_BLOCK_END:
            ascii_code = code - TAG_BLOCK_START
            if 0x20 <= ascii_code <= 0x7E:
                out.append(chr(ascii_code))
    return "".join(out)


def _decode_zero_width_bits(text: str) -> str:
    """Decode a zero-width binary channel (ZWSP=0, ZWNJ=1) into ASCII.

    A recognised smuggling scheme encodes each byte as eight zero-width
    characters.  Only returns a result when the decode yields printable ASCII.
    """
    bits = []
    for ch in text or "":
        if ch == "\u200b":
            bits.append("0")
        elif ch == "\u200c":
            bits.append("1")
    if len(bits) < 16:
        return ""
    stream = "".join(bits)
    chars: List[str] = []
    for index in range(0, len(stream) - 7, 8):
        value = int(stream[index: index + 8], 2)
        if not (0x20 <= value <= 0x7E):
            return ""
        chars.append(chr(value))
    return "".join(chars) if len(chars) >= 3 else ""


def extract_hidden_text(text: str) -> Dict[str, str]:
    """Recover every hidden channel found in ``text``.

    Returns:
        Mapping of channel name to recovered plaintext; empty channels are
        omitted.  Channels: ``tag_characters``, ``zero_width_bits``,
        ``zero_width_interleaved``, ``homoglyph_skeleton``.
    """
    out: Dict[str, str] = {}
    tags = decode_tag_characters(text)
    if tags:
        out["tag_characters"] = tags
    bits = _decode_zero_width_bits(text)
    if bits:
        out["zero_width_bits"] = bits
    stripped = _ZERO_WIDTH_RE.sub("", text or "")
    if stripped != text and stripped.strip():
        out["zero_width_interleaved"] = stripped
    folded = skeleton(text or "")
    if folded != text:
        out["homoglyph_skeleton"] = folded
    return out


class UnicodeAttackDetector(Detector):
    """Detects invisible / confusable character smuggling of instructions."""

    name = "prompt_injection.unicode"
    kind = DetectorKind.PROMPT_INJECTION
    default_severity = Severity.HIGH
    references = (
        "https://trojansource.codes/",
        "https://www.unicode.org/reports/tr36/",
        "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    )

    def __init__(
        self,
        *,
        enabled: bool = True,
        min_confidence: float = 0.3,
        min_invisible: int = 3,
        check_homoglyphs: bool = True,
        **options: object,
    ) -> None:
        """Args:
        enabled: Registry enable flag.
        min_confidence: Drop findings below this confidence.
        min_invisible: Number of invisible characters before flagging.
        check_homoglyphs: Enable mixed-script / confusable analysis.
        """
        super().__init__(enabled=enabled, **options)
        self.min_confidence = float(min_confidence)
        self.min_invisible = max(1, int(min_invisible))
        self.check_homoglyphs = bool(check_homoglyphs)

    def analyze(self, ctx: EvaluationContext) -> List[Finding]:
        """Scan all spans for unicode-layer smuggling."""
        findings: List[Finding] = []
        for span in iter_spans(ctx, min_length=4):
            findings.extend(self._analyse_span(span))
        return findings

    def analyze_text(self, text: str, location: str = "text") -> List[Finding]:
        """Scan a bare string."""
        return self._analyse_span(TextSpan(text=text or "", location=location))

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    def _analyse_span(self, span: TextSpan) -> List[Finding]:
        """Collect anomalies for one span and emit at most one finding."""
        text = span.text
        if not text:
            return []
        anomalies: List[UnicodeAnomaly] = []
        for probe in (
            self._check_tag_characters,
            self._check_zero_width,
            self._check_bidi,
            self._check_variation_selectors,
        ):
            anomaly = probe(text)
            if anomaly is not None:
                anomalies.append(anomaly)
        if self.check_homoglyphs:
            anomaly = self._check_homoglyphs(text)
            if anomaly is not None:
                anomalies.append(anomaly)
        if not anomalies:
            return []

        confidence = 1.0
        for anomaly in anomalies:
            confidence *= 1.0 - anomaly.weight
        confidence = round(1.0 - confidence, 4) * span.weight
        if confidence < self.min_confidence:
            return []

        order = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
        severity = max((a.severity for a in anomalies), key=lambda s: order[s])
        evidence: List[str] = []
        for anomaly in anomalies:
            evidence.extend(anomaly.evidence)

        recovered = " || ".join(a.recovered for a in anomalies if a.recovered)
        if recovered and self._recovered_is_instruction(recovered):
            severity = Severity.CRITICAL
            confidence = min(0.99, confidence + 0.2)
            evidence.insert(0, f"[recovered-instruction] {truncate(recovered, 200)}")

        techniques = sorted({a.technique for a in anomalies})
        return [
            self.make_finding(
                title=f"Unicode 隐藏指令走私：{'/'.join(techniques)}",
                description="; ".join(dict.fromkeys(a.label for a in anomalies)),
                severity=severity,
                confidence=confidence,
                evidence=evidence,
                location=span.location,
                remediation="对入模内容执行 NFKC 规范化并剥离不可见字符；拒绝含 Tag 字符的输入",
                tags=["prompt-injection", "unicode", *techniques],
            )
        ]

    @staticmethod
    def _recovered_is_instruction(recovered: str) -> bool:
        """True when recovered hidden text matches a known injection technique."""
        return any(technique.matches(recovered) for technique in TECHNIQUES)

    # -- individual probes --------------------------------------------- #
    def _check_tag_characters(self, text: str) -> Optional[UnicodeAnomaly]:
        """U+E0000-block tag characters: an invisible ASCII channel."""
        matches = _TAG_RE.findall(text)
        if not matches:
            return None
        decoded = decode_tag_characters(text)
        count = sum(len(m) for m in matches)
        evidence = [f"[tag_characters] 发现 {count} 个 U+E0000 区 Tag 字符（渲染为空）"]
        if decoded:
            evidence.append(f"[tag_characters] 解出隐藏文本: {truncate(decoded, 200)}")
        return UnicodeAnomaly(
            technique="tag_characters",
            label="Tag 字符走私：使用 U+E0000 区不可见 ASCII 编码隐藏指令",
            severity=Severity.CRITICAL,
            weight=0.9,
            evidence=evidence,
            recovered=decoded,
        )

    def _check_zero_width(self, text: str) -> Optional[UnicodeAnomaly]:
        """Zero-width filler, either as a binary channel or keyword splitter."""
        count = count_invisible(text)
        zero_width_only = len(_ZERO_WIDTH_RE.findall(text))
        if zero_width_only < self.min_invisible:
            return None
        ratio = count / max(1, len(text))
        bits = _decode_zero_width_bits(text)
        stripped = _ZERO_WIDTH_RE.sub("", text)
        evidence = [
            f"[zero_width] {zero_width_only} 个零宽字符，占比 {ratio:.1%}",
        ]
        recovered = ""
        weight = 0.45
        severity = Severity.MEDIUM
        if bits:
            evidence.append(f"[zero_width] 零宽二进制通道解码: {truncate(bits, 200)}")
            recovered = bits
            weight, severity = 0.85, Severity.CRITICAL
        elif ratio >= INVISIBLE_RATIO_THRESHOLD:
            weight, severity = 0.7, Severity.HIGH
            evidence.append("[zero_width] 不可见字符占比异常，疑似关键词拆分绕过")
        if stripped != text and any(t.matches(stripped) for t in TECHNIQUES):
            recovered = recovered or stripped
            weight, severity = 0.9, Severity.CRITICAL
            evidence.append(f"[zero_width] 剥离零宽字符后命中注入模式: {truncate(stripped, 200)}")
        return UnicodeAnomaly(
            technique="zero_width",
            label="零宽字符隐藏：使用不可见字符夹带或拆分指令",
            severity=severity,
            weight=weight,
            evidence=evidence,
            recovered=recovered,
        )

    def _check_bidi(self, text: str) -> Optional[UnicodeAnomaly]:
        """Bidirectional controls that desynchronise display from logic."""
        present = [ch for ch in text if ch in BIDI_CONTROLS]
        if not present:
            return None
        overrides = [ch for ch in present if ch in BIDI_OVERRIDES]
        names = sorted({BIDI_CONTROLS[ch] for ch in present})
        evidence = [f"[bidi] 检测到 {len(present)} 个双向控制符: {', '.join(names[:5])}"]
        if overrides:
            visual = "".join(reversed([c for c in text if c not in BIDI_CONTROLS]))
            evidence.append(f"[bidi] 存在强制覆盖符，逻辑序与显示序不一致；反序视图: {truncate(visual, 160)}")
            return UnicodeAnomaly(
                technique="bidi_override",
                label="双向文本覆盖：RTL/LTR override 使显示内容与实际内容不符",
                severity=Severity.HIGH,
                weight=0.75,
                evidence=evidence,
                recovered="",
            )
        return UnicodeAnomaly(
            technique="bidi_mark",
            label="双向文本标记：存在方向控制字符",
            severity=Severity.LOW,
            weight=0.25,
            evidence=evidence,
        )

    def _check_variation_selectors(self, text: str) -> Optional[UnicodeAnomaly]:
        """Variation selectors appended as an invisible, tokeniser-visible tag."""
        matches = _VARIATION_SELECTOR_RE.findall(text)
        if len(matches) < 2:
            return None
        codepoints = ", ".join(sorted({f"U+{ord(m):04X}" for m in matches})[:6])
        return UnicodeAnomaly(
            technique="variation_selector",
            label="变体选择符走私：附加不可见变体选择符携带额外信息",
            severity=Severity.MEDIUM if len(matches) < 8 else Severity.HIGH,
            weight=0.4 if len(matches) < 8 else 0.65,
            evidence=[f"[variation_selector] {len(matches)} 个变体选择符: {codepoints}"],
        )

    def _check_homoglyphs(self, text: str) -> Optional[UnicodeAnomaly]:
        """Confusable characters spoofing ASCII keywords or hostnames."""
        confusables = confusable_characters(text, limit=12)
        mixed = detect_mixed_script(text)
        if not confusables and not mixed:
            return None
        folded = skeleton(text)
        evidence: List[str] = []
        if confusables:
            sample = ", ".join(f"{ch!r}->{ascii_ch} ({name})" for _, ch, ascii_ch, name in confusables[:4])
            evidence.append(f"[homoglyph] {len(confusables)} 个同形异义字: {sample}")
        if mixed:
            words = ", ".join(word for word, _ in mixed[:4])
            evidence.append(f"[homoglyph] 混合书写系统的词: {truncate(words, 160)}")
        weight, severity = 0.4, Severity.MEDIUM
        recovered = ""
        if folded != text and any(t.matches(folded) for t in TECHNIQUES):
            weight, severity = 0.85, Severity.CRITICAL
            recovered = folded
            evidence.append(f"[homoglyph] 折叠为 ASCII 后命中注入模式: {truncate(folded, 200)}")
        elif mixed:
            weight, severity = 0.55, Severity.HIGH
        return UnicodeAnomaly(
            technique="homoglyph",
            label="同形异义字冒充：西里尔/希腊字母伪装拉丁字符绕过匹配",
            severity=severity,
            weight=weight,
            evidence=evidence,
            recovered=recovered,
        )

    # ------------------------------------------------------------------ #
    # Utility exposed for the CLI
    # ------------------------------------------------------------------ #
    @staticmethod
    def describe_characters(text: str, limit: int = 20) -> List[Tuple[str, str]]:
        """List non-ASCII characters with their Unicode names, for triage."""
        out: List[Tuple[str, str]] = []
        for ch in text or "":
            if ch.isascii():
                continue
            try:
                name = unicodedata.name(ch)
            except ValueError:
                name = f"U+{ord(ch):04X} (unnamed)"
            entry = (f"U+{ord(ch):04X}", name)
            if entry not in out:
                out.append(entry)
            if len(out) >= limit:
                break
        return out
