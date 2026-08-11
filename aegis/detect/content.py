"""Generic content detector.

The catch-all pass that runs every signature pack not owned by a specialised
detector, plus a small set of structural content checks (oversized payloads,
control characters, embedded executables, dangerous file extensions).  It gives
operators a place to drop new YAML signatures and have them enforced immediately
without writing Python.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence

from ..core.logging import get_logger
from ..core.types import DetectorKind, EvaluationContext, Finding, Severity
from ..core.utils import count_invisible
from .base import Detector
from .signatures import default_signature_set

LOGGER = get_logger("detect.content")

#: Packs already covered by a dedicated detector - skipped here to avoid
#: duplicate findings for the same match.
_OWNED_PACKS = frozenset(
    {"prompt-injection", "exfiltration", "secrets", "tool-poisoning", "egress", "supply-chain"}
)

#: Magic prefixes of executable / archive content smuggled through a text field.
_MAGIC_PREFIXES: Dict[str, str] = {
    "MZ": "windows_pe",
    "\x7fELF": "elf_binary",
    "PK\x03\x04": "zip_archive",
    "\x1f\x8b": "gzip_stream",
    "%PDF-": "pdf_document",
    "#!/": "shebang_script",
}

#: File extensions whose presence in an argument implies code execution.
_DANGEROUS_EXT_RE = re.compile(
    r"\.(?:exe|dll|scr|bat|cmd|ps1|vbs|jar|msi|so|dylib|sh|com|pif|hta|apk)\b",
    re.IGNORECASE,
)

#: C0 control characters (excluding tab/newline/carriage return).
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

#: Payload size above which a single argument is inherently suspicious.
_LARGE_PAYLOAD = 32_768


class ContentDetector(Detector):
    """Runs operator-supplied signatures plus generic content hygiene checks."""

    name = "content"
    kind = DetectorKind.CONTENT
    default_severity = Severity.MEDIUM

    def __init__(
        self,
        *,
        enabled: bool = True,
        min_confidence: float = 0.35,
        packs: Optional[Sequence[str]] = None,
        check_binaries: bool = True,
        **options: Any,
    ) -> None:
        """Args:
        enabled: Registry enable flag.
        min_confidence: Drop findings below this confidence.
        packs: Explicit pack allowlist; defaults to every non-owned pack.
        check_binaries: Enable magic-byte / control-character checks.
        """
        super().__init__(enabled=enabled, **options)
        self.min_confidence = float(min_confidence)
        self.packs = list(packs) if packs is not None else None
        self.check_binaries = bool(check_binaries)

    def analyze(self, ctx: EvaluationContext) -> List[Finding]:
        from .text_sources import iter_spans

        findings: List[Finding] = []
        spans = iter_spans(ctx)
        packs = self._packs()
        if packs:
            sigset = default_signature_set()
            for span in spans:
                for hit in sigset.scan(span.text, packs=packs, location=span.location):
                    findings.append(
                        self.make_finding(
                            f"Content signature matched: {hit.signature.id}",
                            description=hit.signature.description
                            or f"Matched content signature {hit.signature.id}.",
                            severity=hit.severity,
                            confidence=hit.confidence,
                            evidence=[hit.evidence],
                            location=span.location,
                            references=hit.signature.references,
                            tags=["content"] + list(hit.signature.tags),
                        )
                    )
        if self.check_binaries:
            for span in spans:
                findings.extend(self._hygiene(span.text, span.location))
        return findings

    def _packs(self) -> List[str]:
        """Resolve which signature packs this detector owns."""
        if self.packs is not None:
            return list(self.packs)
        available = default_signature_set().stats().get("packs", {})
        return [pack for pack in available if pack not in _OWNED_PACKS]

    def _hygiene(self, text: str, location: str) -> List[Finding]:
        findings: List[Finding] = []
        for prefix, label in _MAGIC_PREFIXES.items():
            if text.startswith(prefix):
                findings.append(
                    self.make_finding(
                        f"Binary content in a text field ({label})",
                        description=(
                            f"Value begins with the {label} magic signature. Executable or "
                            "archive content smuggled through a text argument is a common "
                            "dropper technique."
                        ),
                        severity=Severity.HIGH,
                        confidence=0.75,
                        evidence=[f"magic={label}", f"bytes={len(text)}"],
                        location=location,
                        remediation="Reject binary payloads on text parameters.",
                        tags=["content", "binary", label],
                    )
                )
                break

        controls = len(_CONTROL_RE.findall(text))
        if controls >= 5:
            findings.append(
                self.make_finding(
                    "Control characters in text argument",
                    description=(
                        f"Value contains {controls} C0 control characters, which are used to "
                        "corrupt logs, spoof terminals and hide payloads from reviewers."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    evidence=[f"control_chars={controls}"],
                    location=location,
                    remediation="Strip control characters before logging or forwarding.",
                    tags=["content", "control_chars", "log_injection"],
                )
            )

        invisible = count_invisible(text)
        if invisible >= 10:
            findings.append(
                self.make_finding(
                    "Large volume of invisible characters",
                    description=(
                        f"Value carries {invisible} invisible characters - typical of a "
                        "Unicode smuggling channel."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=0.55,
                    evidence=[f"invisible={invisible}"],
                    location=location,
                    remediation="Normalise and strip invisible characters on ingest.",
                    tags=["content", "unicode"],
                )
            )

        if _DANGEROUS_EXT_RE.search(text):
            findings.append(
                self.make_finding(
                    "Executable file reference",
                    description="Argument references an executable or script file extension.",
                    severity=Severity.LOW,
                    confidence=0.4,
                    evidence=[_first(_DANGEROUS_EXT_RE, text)],
                    location=location,
                    remediation="Restrict which file types the agent may write or run.",
                    tags=["content", "executable"],
                )
            )

        if len(text) >= _LARGE_PAYLOAD:
            findings.append(
                self.make_finding(
                    "Oversized argument payload",
                    description=(
                        f"Single argument is {len(text)} characters. Oversized payloads are "
                        "used to bury instructions and to stage bulk data."
                    ),
                    severity=Severity.LOW,
                    confidence=0.4,
                    evidence=[f"chars={len(text)}"],
                    location=location,
                    remediation="Enforce per-parameter size limits.",
                    tags=["content", "oversize"],
                )
            )
        return findings

    def analyze_text(self, text: str, location: str = "text") -> List[Finding]:
        findings: List[Finding] = []
        packs = self._packs()
        if packs:
            for hit in default_signature_set().scan(text, packs=packs, location=location):
                findings.append(
                    self.make_finding(
                        f"Content signature matched: {hit.signature.id}",
                        description=hit.signature.description,
                        severity=hit.severity,
                        confidence=hit.confidence,
                        evidence=[hit.evidence],
                        location=location,
                        tags=["content"] + list(hit.signature.tags),
                    )
                )
        if self.check_binaries:
            findings.extend(self._hygiene(text, location))
        return findings


def _first(pattern: re.Pattern[str], text: str) -> str:
    """First match of ``pattern`` in ``text`` (empty string when absent)."""
    match = pattern.search(text)
    return match.group(0) if match else ""


#: Contract-facing alias used by the architecture documents.
ContentPolicyDetector = ContentDetector

__all__ = ["ContentDetector", "ContentPolicyDetector"]
