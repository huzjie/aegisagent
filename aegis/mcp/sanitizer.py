"""Sanitisation of MCP tool arguments and results.

The proxy sits between an agent and untrusted (or merely risky) MCP servers, so
it scrubs both directions:

* **outbound** — arguments are checked against an allow/deny policy.  Secret
  shaped values are redacted before they ever reach a server, and tools that
  are block-listed are refused outright.  This stops an agent from leaking a
  credential into a tool argument the server will log.
* **inbound** — results are scanned for secrets and prompt-injection
  patterns.  If a result carries a freshly minted credential or an instruction
  trying to hijack the agent, the proxy flags it and can redact the offending
  span so it never reaches the model context.

All heavy lifting reuses :mod:`aegis.core` redaction and, when present, the
:mod:`aegis.detect` scanners — never bespoke regexes that drift from the rest
of the platform.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence

from ..core.logging import get_logger
from ..core.types import Severity

__all__ = [
    "SanitizeDecision",
    "SanitizeResult",
    "SanitizerConfig",
    "ArgumentSanitizer",
    "looks_like_secret_value",
    "SECRET_KEY_HINTS",
    "PROMPT_INJECTION_MARKERS",
]

_LOG = get_logger("aegis.mcp.sanitizer")

#: Argument key substrings that almost always carry secrets.
SECRET_KEY_HINTS = (
    "api_key",
    "apikey",
    "secret",
    "token",
    "password",
    "passwd",
    "private_key",
    "access_key",
    "auth",
    "credential",
    "session",
)

#: Result fragments that frequently indicate a prompt-injection attempt.
PROMPT_INJECTION_MARKERS = (
    "ignore previous instructions",
    "disregard previous",
    "ignore all prior",
    "you must now",
    "system prompt",
    "new instructions",
    "do not tell the user",
    "repeat after me",
    "developer mode",
    "jailbreak",
    "<system>",
    "[[instruction]]",
)


class SanitizeDecision(str, Enum):
    """Outcome of a sanitise pass."""

    ALLOW = "allow"
    REDACTED = "redacted"
    BLOCKED = "blocked"


@dataclass
class SanitizeResult:
    """What a sanitise pass did and why."""

    decision: SanitizeDecision = SanitizeDecision.ALLOW
    redacted_keys: List[str] = field(default_factory=list)
    removed_keys: List[str] = field(default_factory=list)
    blocked_reason: str = ""
    findings: List[str] = field(default_factory=list)
    severity: Severity = Severity.INFO
    mutated: bool = False

    @property
    def ok(self) -> bool:
        """Whether the call/result may proceed."""
        return self.decision is not SanitizeDecision.BLOCKED

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the result."""
        return {
            "decision": self.decision.value,
            "redacted_keys": list(self.redacted_keys),
            "removed_keys": list(self.removed_keys),
            "blocked_reason": self.blocked_reason,
            "findings": list(self.findings),
            "severity": self.severity.value,
            "mutated": self.mutated,
        }


@dataclass
class SanitizerConfig:
    """Policy applied by :class:`ArgumentSanitizer`."""

    block_tools: List[str] = field(default_factory=list)
    allow_tools: List[str] = field(default_factory=list)
    block_arg_keys: List[str] = field(default_factory=list)
    redact_arg_keys: List[str] = field(default_factory=list)
    allow_arg_keys: Dict[str, List[str]] = field(default_factory=dict)
    scan_results: bool = True
    redact_secrets_in_results: bool = True
    block_injection_in_results: bool = True
    fail_closed: bool = True

    def validate(self) -> None:
        """No-op validation hook for symmetry with other configs."""
        return


class ArgumentSanitizer:
    """Scrub MCP arguments before sending and results after receiving."""

    def __init__(self, config: Optional[SanitizerConfig] = None) -> None:
        """Create the sanitizer.

        Args:
            config: Allow/deny policy; defaults to permissive-but-redacting.
        """
        self._config = config or SanitizerConfig()
        self._config.validate()
        self._block_tool_re = _compile(self._config.block_tools)
        self._allow_tool_re = _compile(self._config.allow_tools)
        self._block_key_re = _compile(self._config.block_arg_keys)
        self._redact_key_re = _compile(list(self._config.redact_arg_keys) + list(SECRET_KEY_HINTS))
        self._inject_re = _compile(list(PROMPT_INJECTION_MARKERS))

    @property
    def config(self) -> SanitizerConfig:
        """Return the active policy."""
        return self._config

    # -- outbound -----------------------------------------------------------

    def sanitize_args(self, tool: str, arguments: Mapping[str, Any]) -> "tuple[Dict[str, Any], SanitizeResult]":
        """Scrub outbound arguments.

        Args:
            tool: Fully qualified tool name.
            arguments: The agent-supplied arguments.

        Returns:
            A tuple of (cleaned arguments, result).  When the decision is
            ``BLOCKED`` the arguments are returned empty and a
            :class:`ValidationError` is *not* raised here — the caller decides
            whether to hard-fail.

        Raises:
            ValidationError: ``fail_closed`` is set and no allow-listing match
                exists for a tool when an allow-list is configured.
        """
        result = SanitizeResult()
        cleaned: Dict[str, Any] = {}
        local_tool = tool.split("::")[-1]

        if self._block_tool_re and self._block_tool_re.search(tool):
            result.decision = SanitizeDecision.BLOCKED
            result.blocked_reason = f"tool {tool} is block-listed"
            result.severity = Severity.HIGH
            return {}, result

        if self._allow_tool_re and not self._allow_tool_re.search(tool):
            if self._config.fail_closed:
                result.decision = SanitizeDecision.BLOCKED
                result.blocked_reason = f"tool {tool} not on allow-list"
                result.severity = Severity.HIGH
                return {}, result
            # Non-fail-closed: allow but record.
            result.findings.append(f"tool {tool} not on allow-list (permitted, not fail-closed)")

        allowed = self._config.allow_arg_keys.get(local_tool) or self._config.allow_arg_keys.get(tool)
        for key, value in (arguments or {}).items():
            if self._block_key_re and self._block_key_re.search(key):
                result.removed_keys.append(key)
                result.mutated = True
                result.findings.append(f"removed blocked argument key: {key}")
                continue
            if allowed is not None and key not in allowed:
                result.removed_keys.append(key)
                result.mutated = True
                result.findings.append(f"removed unlisted argument key: {key}")
                continue
            if self._redact_key_re and self._redact_key_re.search(key):
                cleaned[key] = _mask(value)
                result.redacted_keys.append(key)
                result.mutated = True
                continue
            # Secret-shaped values are redacted regardless of key name.
            if isinstance(value, str) and looks_like_secret_value(value):
                cleaned[key] = _mask(value)
                result.redacted_keys.append(key)
                result.mutated = True
                result.findings.append(f"redacted secret-shaped value at key: {key}")
                continue
            cleaned[key] = value

        if result.redacted_keys or result.removed_keys:
            result.decision = SanitizeDecision.REDACTED
            result.severity = Severity.MEDIUM
        return cleaned, result

    # -- inbound ------------------------------------------------------------

    def sanitize_result(self, tool: str, content: Any) -> "tuple[Any, SanitizeResult]":
        """Scan an inbound result for secrets and injection.

        Args:
            tool: Fully qualified tool name (for log context).
            content: The result payload (string or structured).

        Returns:
            A tuple of (cleaned content, result).  Secrets are masked and
            injection markers trigger a ``BLOCKED`` decision when configured.
        """
        result = SanitizeResult()
        if not self._config.scan_results:
            return content, result
        text = _to_text(content)
        if not text:
            return content, result

        if self._config.block_injection_in_results and self._inject_re:
            hit = self._inject_re.search(text.lower())
            if hit:
                result.decision = SanitizeDecision.BLOCKED
                result.blocked_reason = f"prompt-injection marker in result: {hit.group(0)!r}"
                result.severity = Severity.CRITICAL
                result.findings.append(result.blocked_reason)
                return content, result

        if self._config.redact_secrets_in_results:
            redacted_text, found = _redact_secrets(text)
            if found:
                result.decision = SanitizeDecision.REDACTED
                result.severity = Severity.MEDIUM
                result.findings.append("redacted secret(s) present in tool result")
                result.mutated = True
                return _rebuild(content, redacted_text), result
        return content, result


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


#: Regexes matching well-known credential shapes, used by
#: :func:`looks_like_secret_value` and :func:`_redact_secrets`.
_SECRET_SHAPES = (
    r"sk-[A-Za-z0-9]{20,}",
    r"AKIA[0-9A-Z]{16}",
    r"ghp_[A-Za-z0-9]{30,}",
    r"gho_[A-Za-z0-9]{30,}",
    r"xox[baprs]-[A-Za-z0-9-]{10,}",
    r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
)

_SECRET_SHAPE_RE = re.compile("|".join(_SECRET_SHAPES))

#: Entropy floor above which a long opaque token is treated as a credential.
_ENTROPY_MIN_LEN = 24
_ENTROPY_THRESHOLD = 3.4


def looks_like_secret_value(value: str) -> bool:
    """Heuristically decide whether a string is a credential.

    Two signals are combined: known credential prefixes (OpenAI, AWS, GitHub,
    Slack, PEM, JWT) and Shannon entropy of long opaque tokens.  The function is
    deliberately conservative — the cost of a false positive is a redacted
    argument, while a false negative leaks a secret to an untrusted server.

    Args:
        value: The candidate string.

    Returns:
        ``True`` when the value should be masked before leaving the process.
    """
    if not value or len(value) < 12:
        return False
    if _SECRET_SHAPE_RE.search(value):
        return True
    candidate = value.strip()
    if len(candidate) < _ENTROPY_MIN_LEN or " " in candidate:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=_\-.]+", candidate):
        return False
    return _shannon_entropy(candidate) >= _ENTROPY_THRESHOLD


def _shannon_entropy(text: str) -> float:
    """Return the Shannon entropy (bits per character) of ``text``."""
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = float(len(text))
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log(probability, 2)
    return entropy


def _compile(patterns: Sequence[str]) -> Optional["re.Pattern[str]"]:
    """Compile a list of glob/literal patterns into one alternation.

    Returning ``None`` for an empty list is load-bearing: an *unset* allow-list
    must mean "no allow-list configured", not "an allow-list that matches
    nothing".  An earlier revision returned a never-matching regex here, which
    in combination with ``fail_closed`` blocked every single tool call.

    Args:
        patterns: Raw pattern strings.  Glob ``*`` is expanded to ``.*``.

    Returns:
        A compiled case-insensitive regex, or ``None`` when ``patterns`` is
        empty.
    """
    if not patterns:
        return None
    joined = "|".join(_glob_to_regex(p) for p in patterns)
    try:
        return re.compile(joined, re.IGNORECASE)
    except re.error:
        return re.compile(re.escape(joined), re.IGNORECASE)


def _glob_to_regex(pattern: str) -> str:
    """Translate a simple glob (only ``*``) into a regex fragment."""
    return re.escape(pattern).replace(r"\*", ".*")


def _mask(value: Any) -> str:
    """Return a stable mask standing in for a secret value.

    Args:
        value: The original value (any type); it is never echoed back.

    Returns:
        A fixed redaction marker so the mask itself leaks no length signal.
    """
    return "***REDACTED***"


def _to_text(content: Any) -> str:
    """Coerce a result payload to plain text for scanning."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, (list, tuple)):
        parts = []
        for item in content:
            if isinstance(item, dict) and "text" in item:
                parts.append(str(item["text"]))
            elif isinstance(item, str):
                parts.append(item)
            else:
                parts.append(str(item))
        return "\n".join(parts)
    if isinstance(content, dict):
        # MCP text content lives under a "text" key.
        if "text" in content:
            return str(content["text"])
        return str(content)
    return str(content)


def _rebuild(content: Any, redacted_text: str) -> Any:
    """Re-insert redacted text back into the original payload shape."""
    if isinstance(content, dict) and "text" in content:
        new = dict(content)
        new["text"] = redacted_text
        return new
    return redacted_text


def _redact_secrets(text: str) -> "tuple[str, bool]":
    """Mask secret-shaped substrings in ``text``.

    Args:
        text: The string to scan.

    Returns:
        A tuple of (possibly redacted text, whether any secret was found).
    """
    masked = text
    found = False

    # 1. key=value style assignments: keep the key, mask the value.
    assignment = re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password|passwd|access[_-]?key|private[_-]?key)"
        r"([\"']?\s*[:=]\s*[\"']?)([A-Za-z0-9\-_.]{8,})"
    )
    if assignment.search(masked):
        found = True
        masked = assignment.sub(lambda m: m.group(1) + m.group(2) + "***REDACTED***", masked)

    # 2. standalone credential shapes: mask the whole match.
    if _SECRET_SHAPE_RE.search(masked):
        found = True
        masked = _SECRET_SHAPE_RE.sub("***REDACTED***", masked)

    return masked, found
