"""Exfiltration detector.

Catches attempts to ship data off to attacker-controlled infrastructure: request
capture services (webhook.site, requestbin ...), anonymous paste bins, reverse
tunnels (ngrok, cloudflared) and URL shorteners used to hide a destination.  It
also flags natural-language exfiltration *instructions* embedded in untrusted
retrieved content, which is the indirect-prompt-injection flavour of the same
attack.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence

from ..core.logging import get_logger
from ..core.types import DetectorKind, EvaluationContext, Finding, Severity
from ..core.utils import extract_urls
from .base import Detector
from .indicators import classify_host

LOGGER = get_logger("detect.exfiltration")

#: Phrases that, inside retrieved content, instruct the agent to send data out.
_EXFIL_INSTRUCTION_RE = re.compile(
    r"(?:send|exfiltrat\w*|upload\w*|transmit\w*|post\w*|forward\w*|leak\w*|beam\w*)\b"
    r"[^.?!]{0,80}?\b(?:to|at|via|into|toward)\b[^.?!]{0,80}?"
    r"(?:webhook|requestbin|pastebin|ngrok|pipedream|hook|tunnel|http|https|dns|callback|bot)",
    re.IGNORECASE,
)

#: A credential / secret placeholder about to be shipped somewhere.
_SECRET_TOKEN_RE = re.compile(
    r"(?:api[_-]?key|token|secret|password|passwd|access[_-]?key|private[_-]?key|auth)\b['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9\-_+/=]{8,}",
    re.IGNORECASE,
)

_SINK_SEVERITY: Dict[str, Severity] = {
    "webhook_sink": Severity.HIGH,
    "paste_site": Severity.HIGH,
    "tunnel": Severity.CRITICAL,
    "shortener": Severity.MEDIUM,
}


class ExfiltrationDetector(Detector):
    """Flags data flowing to external collection / drop endpoints."""

    name = "exfiltration"
    kind = DetectorKind.EXFILTRATION
    default_severity = Severity.HIGH

    def __init__(
        self,
        *,
        enabled: bool = True,
        min_confidence: float = 0.4,
        scan_instructions: bool = True,
        **options: Any,
    ) -> None:
        """Args:
        enabled: Registry enable flag.
        min_confidence: Drop findings below this confidence.
        scan_instructions: Also scan untrusted text for exfil *instructions*.
        """
        super().__init__(enabled=enabled, **options)
        self.min_confidence = float(min_confidence)
        self.scan_instructions = bool(scan_instructions)

    def analyze(self, ctx: EvaluationContext) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._scan_urls(ctx))
        if self.scan_instructions:
            findings.extend(self._scan_instructions(ctx))
        return findings

    def _scan_urls(self, ctx: EvaluationContext) -> List[Finding]:
        from .text_sources import iter_argument_spans, iter_untrusted_spans

        findings: List[Finding] = []
        seen: set[str] = set()
        for span in list(iter_argument_spans(ctx)) + list(iter_untrusted_spans(ctx)):
            for url in extract_urls(span.text):
                info = classify_host(url)
                sink = info.get("sink")
                if not sink:
                    continue
                category, domain = sink
                if domain in seen:
                    continue
                seen.add(domain)
                severity = _SINK_SEVERITY.get(category, Severity.HIGH)
                confidence = 0.85 if category == "tunnel" else 0.7
                findings.append(
                    self.make_finding(
                        f"Exfiltration sink reached: {category}",
                        description=(
                            f"Argument references a known data-collection endpoint "
                            f"'{domain}' ({category})."
                        ),
                        severity=severity,
                        confidence=confidence,
                        evidence=[f"url={url}", f"host={info.get('host')}"],
                        location=span.location,
                        remediation="Block egress to attacker-controlled collectors; require approval for any external POST.",
                        tags=["exfiltration", category, "egress"],
                    )
                )
        return findings

    def _scan_instructions(self, ctx: EvaluationContext) -> List[Finding]:
        from .text_sources import iter_untrusted_spans

        findings: List[Finding] = []
        for span in iter_untrusted_spans(ctx):
            if _EXFIL_INSTRUCTION_RE.search(span.text) or _SECRET_TOKEN_RE.search(span.text):
                export = _SECRET_TOKEN_RE.search(span.text) is not None
                findings.append(
                    self.make_finding(
                        "Exfiltration instruction in untrusted content",
                        description=(
                            "Retrieved content contains language instructing the agent to "
                            "send data or credentials to an external endpoint - a classic "
                            "indirect prompt-injection exfiltration attempt."
                        ),
                        severity=Severity.CRITICAL if export else Severity.HIGH,
                        confidence=0.8 if export else 0.65,
                        evidence=[span.preview],
                        location=span.location,
                        remediation="Treat retrieved content as untrusted; never act on outbound instructions without approval.",
                        tags=["exfiltration", "prompt_injection", "indirect"],
                    )
                )
        return findings

    def analyze_text(self, text: str, location: str = "text") -> List[Finding]:
        findings: List[Finding] = []
        for url in extract_urls(text):
            info = classify_host(url)
            if info.get("sink"):
                category, domain = info["sink"]
                findings.append(
                    self.make_finding(
                        f"Exfiltration sink referenced: {category}",
                        description=f"Text references data-collection endpoint '{domain}'.",
                        severity=_SINK_SEVERITY.get(category, Severity.HIGH),
                        confidence=0.7,
                        evidence=[f"url={url}"],
                        location=location,
                        tags=["exfiltration", category],
                    )
                )
        if self.scan_instructions and _EXFIL_INSTRUCTION_RE.search(text):
            findings.append(
                self.make_finding(
                    "Exfiltration instruction in text",
                    description="Text contains language directing data to an external endpoint.",
                    severity=Severity.HIGH,
                    confidence=0.6,
                    evidence=[text[:200]],
                    location=location,
                    tags=["exfiltration", "instruction"],
                )
            )
        return findings
