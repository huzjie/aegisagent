"""Egress / SSRF detector.

Focuses on *where the agent is trying to send traffic*, independent of payload
content.  The high-value targets are:

* cloud instance-metadata services (``169.254.169.254`` ...) - reading these
  yields role credentials, the classic SSRF-to-credential-theft path;
* private / internal addresses (SSRF pivot);
* sensitive ports (redis, postgres, docker API ...) reached over plain HTTP;
* URL shorteners that hide the real destination from an allowlist.

It complements the exfiltration detector (which keys off known drop sites) by
covering infrastructure targets.
"""

from __future__ import annotations

from typing import Any, List, Optional

from ..core.logging import get_logger
from ..core.types import DetectorKind, EvaluationContext, Finding, Severity
from ..core.utils import extract_urls, host_matches_allowlist
from .base import Detector
from .indicators import classify_host, is_metadata_host

LOGGER = get_logger("detect.egress")


class EgressDetector(Detector):
    """Flags outbound network targets that should be unreachable from an agent."""

    name = "egress"
    kind = DetectorKind.EGRESS
    default_severity = Severity.HIGH

    def __init__(
        self,
        *,
        enabled: bool = True,
        min_confidence: float = 0.4,
        allowlist: Optional[List[str]] = None,
        block_metadata: bool = True,
        block_private: bool = True,
        **options: Any,
    ) -> None:
        """Args:
        enabled: Registry enable flag.
        min_confidence: Drop findings below this confidence.
        allowlist: Hosts/URLs always permitted (production APIs the agent needs).
        block_metadata: Flag cloud metadata endpoints (SSRF -> credentials).
        block_private: Flag RFC1918 / loopback / internal TLD targets.
        """
        super().__init__(enabled=enabled, **options)
        self.min_confidence = float(min_confidence)
        self.allowlist = list(allowlist or [])
        self.block_metadata = bool(block_metadata)
        self.block_private = bool(block_private)

    def analyze(self, ctx: EvaluationContext) -> List[Finding]:
        from .text_sources import iter_argument_spans, iter_untrusted_spans

        findings: List[Finding] = []
        seen: set[str] = set()
        sources = list(iter_argument_spans(ctx)) + list(iter_untrusted_spans(ctx))
        for span in sources:
            for url in extract_urls(span.text):
                host = classify_host(url).get("host") or ""
                if not host or host in seen:
                    continue
                seen.add(host)
                if self.allowlist and host_matches_allowlist(url, self.allowlist):
                    continue
                finding = self._judge(url, span.location)
                if finding is not None:
                    findings.append(finding)
        return findings

    def _judge(self, url: str, location: str) -> Optional[Finding]:
        info = classify_host(url)
        host = info.get("host") or ""
        if self.block_metadata and (info.get("metadata") or is_metadata_host(host)):
            return self.make_finding(
                "SSRF to cloud metadata service",
                description=(
                    f"Argument targets the instance metadata endpoint '{host}'. Reading it "
                    "yields cloud role credentials - the canonical SSRF credential-theft path."
                ),
                severity=Severity.CRITICAL,
                confidence=0.95,
                evidence=[f"url={url}"],
                location=location,
                remediation="Block all metadata-range egress from the agent sandbox.",
                tags=["ssrf", "metadata", "egress", "credential_theft"],
            )
        private = info.get("private")
        if self.block_private and private:
            return self.make_finding(
                "Egress to private / internal address",
                description=(
                    f"Argument targets a non-routable internal host ({private}: '{host}'). "
                    "Typical SSRF pivot toward internal services."
                ),
                severity=Severity.HIGH,
                confidence=0.8,
                evidence=[f"url={url}", f"reason={private}"],
                location=location,
                remediation="Deny egress to internal ranges; allowlist only required externals.",
                tags=["ssrf", "private", "egress"],
            )
        port = info.get("dangerous_port")
        if port:
            return self.make_finding(
                "Egress to sensitive service port",
                description=(
                    f"Argument targets port {info.get('port')} ({port}) over agent HTTP. "
                    "This port usually fronts a privileged service (db, cache, docker API)."
                ),
                severity=Severity.HIGH,
                confidence=0.75,
                evidence=[f"url={url}", f"service={port}"],
                location=location,
                remediation="Restrict egress to web ports; gate privileged services behind approval.",
                tags=["egress", "dangerous_port", "ssrf"],
            )
        if info.get("is_ip_literal"):
            return self.make_finding(
                "Egress to raw IP literal",
                description=(
                    f"Argument targets an IP-literal host '{host}' rather than a domain. "
                    "IP literals dodge domain allowlists and are common in C2 traffic."
                ),
                severity=Severity.MEDIUM,
                confidence=0.5,
                evidence=[f"url={url}"],
                location=location,
                remediation="Prefer hostname allowlisting; review IP-literal destinations.",
                tags=["egress", "ip_literal"],
            )
        return None

    def analyze_text(self, text: str, location: str = "text") -> List[Finding]:
        findings: List[Finding] = []
        for url in extract_urls(text):
            if self.allowlist and host_matches_allowlist(url, self.allowlist):
                continue
            finding = self._judge(url, location)
            if finding is not None:
                findings.append(finding)
        return findings
