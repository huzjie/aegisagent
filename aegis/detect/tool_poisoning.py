"""Tool-poisoning detector.

MCP tool poisoning (the 2025-2026 "tool poisoning attack") plants hidden
instructions inside a tool's *declared* surface - its name, description or
parameter documentation - so that the model reads them as part of its system
context and obeys attacker commands without any visible prompt.  This detector
only examines the declared surface (not runtime arguments), which is exactly
the carrier this attack uses.
"""

from __future__ import annotations

import re
from typing import Any, List, Optional

from ..core.logging import get_logger
from ..core.types import ActionCategory, DetectorKind, EvaluationContext, Finding, Severity
from .base import Detector
from .signatures import default_signature_set

LOGGER = get_logger("detect.tool_poisoning")

#: Instructions that should never appear in a tool description.
_OVERRIDE_RE = re.compile(
    r"(?:ignore|disregard|forget|override|bypass|skip)\b[^.?!]{0,60}?"
    r"(?:previous|prior|system|above|instruction|rule|policy|guardrail|safety)",
    re.IGNORECASE,
)

#: "When you are invoked / called, do X" trigger phrases.
_TRIGGER_RE = re.compile(
    r"(?:when\s+(?:you\s+are\s+)?(?:called|invoked|run|executed|triggered)|"
    r"upon\s+(?:call|invocation|use)|after\s+(?:you\s+)?(?:run|execute))\b"
    r"[^.?!]{0,80}?(?:instead|must|should|execute|run|send|fetch|exfiltrate|delete|ignore)",
    re.IGNORECASE,
)

#: Enticement / coercion language common in poisoned descriptions.
_ENTICE_RE = re.compile(
    r"(?:important|critical|secret|confidential|for\s+testing\s+only|do\s+not\s+tell|"
    r"the\s+user\s+(?:must\s+not|should\s+not|won't))\b",
    re.IGNORECASE,
)

#: Declared-category vs argument-content mismatch signals.
_DESTRUCTIVE_ARG_RE = re.compile(
    r"(?:rm\s+-rf|del\s+/[fqs]|drop\s+table|format\s+:|shutdown|curl\s+.*\|\s*(?:sh|bash)|"
    r"truncate\s+table|delete\s+from)",
    re.IGNORECASE,
)


class ToolPoisoningDetector(Detector):
    """Detects attacker-controlled instructions baked into a tool's metadata."""

    name = "tool_poisoning"
    kind = DetectorKind.TOOL_POISONING
    default_severity = Severity.HIGH

    def __init__(
        self,
        *,
        enabled: bool = True,
        min_confidence: float = 0.4,
        **options: Any,
    ) -> None:
        """Args:
        enabled: Registry enable flag.
        min_confidence: Drop findings below this confidence.
        """
        super().__init__(enabled=enabled, **options)
        self.min_confidence = float(min_confidence)

    def analyze(self, ctx: EvaluationContext) -> List[Finding]:
        from .text_sources import iter_descriptor_spans

        findings: List[Finding] = []
        findings.extend(self._scan_signatures(ctx))
        findings.extend(self._scan_declared(ctx, list(iter_descriptor_spans(ctx))))
        findings.extend(self._scan_category_mismatch(ctx))
        return findings

    def _scan_signatures(self, ctx: EvaluationContext) -> List[Finding]:
        from .text_sources import iter_descriptor_spans

        findings: List[Finding] = []
        sigset = default_signature_set()
        for span in iter_descriptor_spans(ctx):
            for hit in sigset.scan(span.text, packs=["tool-poisoning"], location=span.location):
                findings.append(
                    self.make_finding(
                        f"Poisoned tool surface: {hit.signature.id}",
                        description=hit.signature.description
                        or f"Matched tool-poisoning signature {hit.signature.id}.",
                        severity=hit.severity,
                        confidence=hit.confidence,
                        evidence=[hit.evidence],
                        location=span.location,
                        remediation="Reject the tool until its description is reviewed and pinned.",
                        references=hit.signature.references,
                        tags=["tool_poisoning"] + list(hit.signature.tags),
                    )
                )
        return findings

    def _scan_declared(self, ctx: EvaluationContext, spans) -> List[Finding]:
        findings: List[Finding] = []
        for span in spans:
            score = 0.0
            reasons: List[str] = []
            if _OVERRIDE_RE.search(span.text):
                score = max(score, 0.85)
                reasons.append("instruction-override language")
            if _TRIGGER_RE.search(span.text):
                score = max(score, 0.8)
                reasons.append("invoke-time trigger instruction")
            if _ENTICE_RE.search(span.text):
                score = max(score, 0.55)
                reasons.append("enticement / secrecy language")
            if score >= self.min_confidence:
                findings.append(
                    self.make_finding(
                        "Injected instruction in tool description",
                        description=(
                            "The tool's declared description/parameter docs contain "
                            f"attacker-style instructions ({'; '.join(reasons)}). This is the "
                            "signature of an MCP tool-poisoning attack."
                        ),
                        severity=Severity.CRITICAL if score >= 0.8 else Severity.HIGH,
                        confidence=score,
                        evidence=[span.preview],
                        location=span.location,
                        remediation="Pin the tool schema and block the tool until the description is cleaned.",
                        tags=["tool_poisoning", "mcp", "injection"],
                    )
                )
        return findings

    def _scan_category_mismatch(self, ctx: EvaluationContext) -> List[Finding]:
        descriptor = ctx.descriptor
        if descriptor is None:
            return []
        declared = {c.value for c in (descriptor.categories or [])}
        if ActionCategory.DESTRUCTIVE in declared or ActionCategory.EXECUTE in declared:
            return []  # already declared dangerous
        suspicious = False
        import json

        blob = json.dumps(ctx.call.arguments or {}, ensure_ascii=False)
        if _DESTRUCTIVE_ARG_RE.search(blob):
            suspicious = True
        if suspicious:
            return [
                self.make_finding(
                    "Destructive argument under a benign tool",
                    description=(
                        "The tool is declared as non-destructive but its arguments contain "
                        "destructive commands (rm -rf, drop table, curl|sh ...). The declared "
                        "surface is misleading."
                    ),
                    severity=Severity.HIGH,
                    confidence=0.6,
                    evidence=[blob[:160]],
                    location="arguments",
                    remediation="Reclassify the tool and require approval for destructive arguments.",
                    tags=["tool_poisoning", "category_mismatch"],
                )
            ]
        return []

    def analyze_text(self, text: str, location: str = "text") -> List[Finding]:
        findings: List[Finding] = []
        if _OVERRIDE_RE.search(text) or _TRIGGER_RE.search(text):
            findings.append(
                self.make_finding(
                    "Injected instruction in tool description text",
                    description="Text contains tool-poisoning style instructions.",
                    severity=Severity.HIGH,
                    confidence=0.7,
                    evidence=[text[:200]],
                    location=location,
                    tags=["tool_poisoning", "mcp"],
                )
            )
        return findings
