"""Secret-leak detector and standalone credential scanner.

Hunts for live credentials - API keys, tokens, private keys, passwords - that
appear in tool arguments or (more dangerously) inside retrieved content that an
agent is about to forward.  It combines:

* the bundled ``secrets`` signature pack (provider-specific key formats),
* structural high-entropy scanning (a 40-char random blob is a secret even when
  it does not match a known format), and
* PII recognition (the :mod:`aegis.detect.pii` recognisers) so that leaking a
  customer's ID card number or bank card is also caught.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ..core.logging import get_logger
from ..core.types import DetectorKind, EvaluationContext, Finding, Severity
from .base import Detector
from .entropy import looks_random
from .pii import DataSensitivity, scan_pii
from .signatures import default_signature_set

LOGGER = get_logger("detect.secrets")

#: Minimum length for an entropy-based secret candidate.
_MIN_SECRET_LEN = 16

#: Severity floor for PII leakage based on sensitivity tier.
_PII_SEVERITY = {
    DataSensitivity.CONFIDENTIAL: Severity.HIGH,
    DataSensitivity.RESTRICTED: Severity.CRITICAL,
    DataSensitivity.HIGHLY_RESTRICTED: Severity.CRITICAL,
}


@dataclass
class SecretHit:
    """A credential-shaped value discovered by :class:`SecretScanner`."""

    rule: str
    matched: str
    severity: Severity = Severity.HIGH
    confidence: float = 0.8
    description: str = ""
    start: int = 0
    end: int = 0

    @property
    def evidence(self) -> str:
        return f"[{self.rule}] {self.matched[:24]}{'…' if len(self.matched) > 24 else ''}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "description": self.description,
            "span": [self.start, self.end],
        }


#: Real credential regular expressions (compiled once at import).  These are the
#: formats an attacker would exfiltrate; format-only matches are down-ranked by
#: the entropy / placeholder checks inside :meth:`SecretScanner.scan`.
_SECRET_PATTERNS: List[Tuple[str, "re.Pattern[str]", Severity, float, str]] = []
for _name, _src, _sev, _conf, _desc in [
    ("openai", r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}", Severity.CRITICAL, 0.92, "OpenAI API key"),
    ("anthropic", r"sk-ant-[A-Za-z0-9_-]{20,}", Severity.CRITICAL, 0.92, "Anthropic API key"),
    ("github_ghp", r"ghp_[A-Za-z0-9]{36}", Severity.CRITICAL, 0.95, "GitHub personal access token"),
    ("github_gho", r"gho_[A-Za-z0-9]{36}", Severity.CRITICAL, 0.9, "GitHub OAuth token"),
    ("github_ghu", r"ghu_[A-Za-z0-9]{36}", Severity.CRITICAL, 0.9, "GitHub user-to-server token"),
    ("github_ghs", r"ghs_[A-Za-z0-9]{36}", Severity.CRITICAL, 0.9, "GitHub server-to-server token"),
    ("github_ghr", r"ghr_[A-Za-z0-9]{36}", Severity.CRITICAL, 0.9, "GitHub refresh token"),
    ("github_pat", r"github_pat_[A-Za-z0-9_]{22,}", Severity.CRITICAL, 0.92, "GitHub fine-grained PAT"),
    ("aws_key", r"AKIA[0-9A-Z]{16}", Severity.CRITICAL, 0.95, "AWS access key id"),
    ("aws_secret", r"(?i)(aws_secret_access_key|aws_secret)\s*[:=]\s*['\"]?[A-Za-z0-9/+]{40}", Severity.CRITICAL, 0.9, "AWS secret access key"),
    ("gcp_sa", r"\"type\"\s*:\s*\"service_account\"", Severity.CRITICAL, 0.8, "GCP service-account JSON"),
    ("gcp_key", r"(?i)(AIza[0-9A-Za-z_-]{35}|GOOG[0-9A-Z]{18,})", Severity.CRITICAL, 0.9, "GCP API key / service account"),
    ("azure_client", r"(?i)azure(client)?(_|\\s)?(id|secret)\s*[:=]\s*['\"]?[A-Za-z0-9]{16,}", Severity.CRITICAL, 0.88, "Azure client secret"),
    ("slack", r"xox[baprs]-[A-Za-z0-9-]{10,}", Severity.CRITICAL, 0.92, "Slack token"),
    ("stripe_live", r"sk_live_[0-9a-zA-Z]{16,}", Severity.CRITICAL, 0.95, "Stripe live secret key"),
    ("stripe_restricted", r"rk_live_[0-9a-zA-Z]{16,}", Severity.CRITICAL, 0.92, "Stripe restricted key"),
    ("jwt", r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", Severity.HIGH, 0.85, "JSON Web Token"),
    ("rsa_key", r"-----BEGIN RSA PRIVATE KEY-----", Severity.CRITICAL, 0.98, "RSA private key"),
    ("ec_key", r"-----BEGIN EC PRIVATE KEY-----", Severity.CRITICAL, 0.98, "EC private key"),
    ("openssh_key", r"-----BEGIN OPENSSH PRIVATE KEY-----", Severity.CRITICAL, 0.98, "OpenSSH private key"),
    ("pgp_key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", Severity.CRITICAL, 0.98, "PGP private key"),
    ("private_key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", Severity.CRITICAL, 0.96, "Generic private key"),
    ("pg_string", r"(?i)(postgres(ql)?|pgsql)://[^\s:'\"]+:[^\s:'\"]+@", Severity.HIGH, 0.85, "PostgreSQL connection string"),
    ("mysql_string", r"(?i)(mysql|mariadb)://[^\s:'\"]+:[^\s:'\"]+@", Severity.HIGH, 0.85, "MySQL/MariaDB connection string"),
    ("mongo_string", r"(?i)mongodb(\+srv)?://[^\s:'\"]+:[^\s:'\"]+@", Severity.HIGH, 0.85, "MongoDB connection string"),
    ("redis_string", r"(?i)redis://[^\s:'\"]+:[^\s:'\"]+@", Severity.HIGH, 0.85, "Redis connection string"),
    ("twilio", r"(?i)SK[0-9a-fA-F]{32}", Severity.HIGH, 0.85, "Twilio API key"),
    ("sendgrid", r"SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}", Severity.HIGH, 0.85, "SendGrid API key"),
    ("mailgun", r"(?i)key-[0-9a-zA-Z]{32}", Severity.HIGH, 0.85, "Mailgun private key"),
    ("datadog", r"(?i)ddapikey-[0-9a-f]{32}", Severity.HIGH, 0.85, "Datadog API key"),
    ("newrelic", r"(?i)[Nn]R[Aa][Pp][Ii][0-9a-f]{32}", Severity.HIGH, 0.85, "New Relic ingest key"),
    ("npm_token", r"(?i)(npm_)?(_authtoken|authToken)\s*[:=]\s*['\"]?[A-Za-z0-9_-]{20,}", Severity.HIGH, 0.85, "npm registry token"),
    ("pypi_token", r"(?i)pypi[_-]?token\s*[:=]\s*['\"]?[A-Za-z0-9_-]{20,}", Severity.HIGH, 0.85, "PyPI upload token"),
    ("dockerhub", r"(?i)dckr_pat_[0-9a-zA-Z]{24,}", Severity.HIGH, 0.85, "DockerHub PAT"),
    ("k8s_sa", r"(?i)eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", Severity.HIGH, 0.8, "Kubernetes service-account JWT"),
    ("grafana", r"(?i)(gfo|glsa)_[A-Za-z0-9]{24,}", Severity.HIGH, 0.85, "Grafana API token"),
    ("jenkins", r"(?i)jenkins[_-]?token\s*[:=]\s*['\"]?[0-9a-fA-F]{32,}", Severity.HIGH, 0.85, "Jenkins API token"),
    ("gitlab", r"glpat-[0-9a-zA-Z_-]{20,}", Severity.HIGH, 0.9, "GitLab personal access token"),
    ("telegram", r"(?i)\d{8,10}:[0-9A-Za-z_-]{32,}", Severity.HIGH, 0.9, "Telegram bot token"),
    ("discord", r"(?i)[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{27,}", Severity.HIGH, 0.85, "Discord bot token"),
    ("cloudflare", r"(?i)(cf|cloudflare)_(api|token|key)\s*[:=]\s*['\"]?[A-Za-z0-9_-]{32,}", Severity.HIGH, 0.85, "Cloudflare API token"),
    ("digitalocean", r"dop_v1_[0-9a-f]{64}", Severity.CRITICAL, 0.92, "DigitalOcean token"),
    ("heroku", r"(?i)(heroku[a-z0-9_]{0,12})?(_api_key|token)\s*[:=]\s*['\"]?[0-9A-Fa-f]{32,}", Severity.HIGH, 0.85, "Heroku API key"),
    ("notion", r"secret_[0-9a-zA-Z]{32,}", Severity.HIGH, 0.9, "Notion integration secret"),
    ("feishu", r"(?i)(feishu|lark)[_-]?webhook[_-]?key\s*[:=]\s*['\"]?[0-9a-f]{32,}", Severity.HIGH, 0.85, "Feishu/Lark webhook key"),
    ("wecom", r"(?i)(wecom|ww)[_-]?webhook[_-]?key\s*[:=]\s*['\"]?[0-9a-fA-Z]{32,}", Severity.HIGH, 0.85, "WeCom webhook key"),
    ("aliyun", r"(?i)LTAI[A-Za-z0-9]{12,20}", Severity.CRITICAL, 0.92, "Alibaba Cloud access key id"),
    ("tencent", r"(?i)AKID[A-Za-z0-9]{32,48}", Severity.CRITICAL, 0.92, "Tencent Cloud secret id"),
]:
    _SECRET_PATTERNS.append(
        (_name, re.compile(_src), _sev, _conf, _desc)
    )
del _name, _src, _sev, _conf, _desc

#: Placeholder fragments that mean a "match" is almost certainly a doc sample.
_PLACEHOLDER_RE = re.compile(
    r"(?i)\b(REDACTED|EXAMPLE|xxxxxxxx|your[_-]?(key|token|secret|password)|sample|dummy|fake|changeme)\b"
)


def entropy(s: str) -> float:
    """Shannon entropy (bits/char) of ``s`` - high values imply randomness."""
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER_RE.search(value))


class SecretScanner:
    """Standalone credential scanner (no detector/context dependency).

    Use this directly when you already have a blob of text and just want the
    secrets in it (CLI, redaction middleware, log scrubbers).  It combines the
    bundled ``secrets`` signature pack with a structural high-entropy scan and
    down-ranks obvious placeholders so docs don't generate false alerts.
    """

    def __init__(self, *, min_entropy: float = 3.5, min_token_len: int = 16) -> None:
        self.min_entropy = float(min_entropy)
        self.min_token_len = int(min_token_len)

    def scan(self, text: str, *, location: str = "text") -> List[SecretHit]:
        """Return every credential-shaped value found in ``text``."""
        if not text:
            return []
        hits: List[SecretHit] = []
        for name, pattern, severity, confidence, description in _SECRET_PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(0)
                if _is_placeholder(value):
                    continue
                hits.append(
                    SecretHit(
                        rule=name,
                        matched=value,
                        severity=severity,
                        confidence=confidence,
                        description=description,
                        start=match.start(),
                        end=match.end(),
                    )
                )
        # Structural high-entropy scan for format-less blobs.
        for token in _tokenize(text):
            if len(token) < self.min_token_len or _is_placeholder(token):
                continue
            if looks_random(token, min_length=self.min_token_len, threshold=self.min_entropy):
                hits.append(
                    SecretHit(
                        rule="high_entropy",
                        matched=token,
                        severity=Severity.HIGH,
                        confidence=0.5,
                        description="Random-looking high-entropy token",
                        start=text.find(token),
                        end=text.find(token) + len(token),
                    )
                )
        return hits

    def redact(self, text: str) -> str:
        """Return ``text`` with every detected secret masked."""
        if not text:
            return text
        spans = sorted(
            ((h.start, h.end) for h in self.scan(text) if h.start >= 0 and h.end > h.start),
            key=lambda s: (s[0], -s[1]),
        )
        # Collapse overlapping matches (e.g. the generic ``sk-`` rule inside an
        # ``sk-ant-`` key) so one credential is masked exactly once.
        merged: List[Tuple[int, int]] = []
        for start, end in spans:
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        out = text
        for start, end in reversed(merged):
            out = out[:start] + "***REDACTED***" + out[end:]
        return out

    def entropy(self, s: str) -> float:
        """Shannon entropy (bits per character) of ``s``."""
        return entropy(s)

    def rules(self) -> List[str]:
        """Names of every credential rule this scanner applies."""
        return [name for name, _, _, _, _ in _SECRET_PATTERNS]


class SecretLeakDetector(Detector):
    """Detects credentials and regulated PII flowing through tool calls."""

    name = "secret_leak"
    kind = DetectorKind.SECRET_LEAK
    default_severity = Severity.HIGH

    def __init__(
        self,
        *,
        enabled: bool = True,
        min_confidence: float = 0.4,
        scan_pii: bool = True,
        scan_entropy: bool = True,
        **options: Any,
    ) -> None:
        """Args:
        enabled: Registry enable flag.
        min_confidence: Drop findings below this confidence.
        scan_pii: Run the PII recognisers over untrusted spans.
        scan_entropy: Flag high-entropy blobs as candidate secrets.
        """
        super().__init__(enabled=enabled, **options)
        self.min_confidence = float(min_confidence)
        self.scan_pii = bool(scan_pii)
        self.scan_entropy = bool(scan_entropy)

    def analyze(self, ctx: EvaluationContext) -> List[Finding]:
        from .text_sources import iter_argument_spans, iter_untrusted_spans

        findings: List[Finding] = []
        findings.extend(self._scan_signatures(ctx))
        if self.scan_entropy:
            findings.extend(self._scan_entropy(ctx))
        if self.scan_pii:
            findings.extend(self._scan_pii(ctx))
        return findings

    def _scan_signatures(self, ctx: EvaluationContext) -> List[Finding]:
        from .text_sources import iter_spans

        findings: List[Finding] = []
        sigset = default_signature_set()
        for span in iter_spans(ctx, include_descriptor=False):
            for hit in sigset.scan(span.text, packs=["secrets"], location=span.location):
                findings.append(
                    self.make_finding(
                        f"Secret pattern matched: {hit.signature.id}",
                        description=hit.signature.description
                        or f"Matched secret signature {hit.signature.id}.",
                        severity=hit.severity,
                        confidence=hit.confidence,
                        evidence=[hit.evidence],
                        location=span.location,
                        remediation="Rotate the exposed credential and redact it from logs/arguments.",
                        references=hit.signature.references,
                        tags=["secret"] + list(hit.signature.tags),
                    )
                )
        return findings

    def _scan_entropy(self, ctx: EvaluationContext) -> List[Finding]:
        from .text_sources import iter_argument_spans, iter_untrusted_spans

        findings: List[Finding] = []
        seen: set[str] = set()
        for span in list(iter_argument_spans(ctx)) + list(iter_untrusted_spans(ctx)):
            for token in _tokenize(span.text):
                if len(token) < _MIN_SECRET_LEN or token in seen:
                    continue
                if looks_random(token, min_length=_MIN_SECRET_LEN):
                    seen.add(token)
                    findings.append(
                        self.make_finding(
                            "High-entropy secret-like value",
                            description=(
                                "Argument contains a random-looking high-entropy token that "
                                "resembles a credential and does not match a known format."
                            ),
                            severity=Severity.HIGH,
                            confidence=0.55,
                            evidence=[f"{token[:12]}… ({len(token)} chars)"],
                            location=span.location,
                            remediation="Confirm this is not a live secret before allowing the call.",
                            tags=["secret", "entropy"],
                        )
                    )
        return findings

    def _scan_pii(self, ctx: EvaluationContext) -> List[Finding]:
        from .text_sources import iter_argument_spans, iter_untrusted_spans

        findings: List[Finding] = []
        for span in list(iter_argument_spans(ctx)) + list(iter_untrusted_spans(ctx)):
            hits = scan_pii(span.text)
            if not hits:
                continue
            worst = max((h.sensitivity.rank for h in hits), default=0)
            sensitivity = next(
                (s for s in DataSensitivity if s.rank == worst), DataSensitivity.CONFIDENTIAL
            )
            kinds = sorted({h.kind for h in hits})
            findings.append(
                self.make_finding(
                    "PII present in tool input",
                    description=(
                        f"Argument/retrieved content contains personal data "
                        f"({', '.join(kinds)}). Forwarding it may breach data-protection rules."
                    ),
                    severity=_PII_SEVERITY.get(sensitivity, Severity.HIGH),
                    confidence=0.7,
                    evidence=[f"{len(hits)} PII matches: {', '.join(kinds)}"],
                    location=span.location,
                    remediation="Redact PII before the call; restrict to least-privilege data.",
                    tags=["pii", "secret", sensitivity.value],
                )
            )
        return findings


def _tokenize(text: str) -> List[str]:
    """Split text into bareword tokens suitable for entropy analysis."""
    import re

    return [t for t in re.findall(r"[A-Za-z0-9_\-+/=]{12,}", text)]
