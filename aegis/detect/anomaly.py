"""Behavioural anomaly detector.

Signature detection catches known-bad payloads; this module catches *unusual*
behaviour: an agent that suddenly calls a tool it has never used, bursts of
calls in a short window, arguments far larger than usual, or a session that
walks the classic reconnaissance -> credential-read -> egress chain.

State is per-process and bounded (sliding windows and small per-key profiles),
so it works without any external store while still surviving normal traffic.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from ..core.logging import get_logger
from ..core.types import DetectorKind, EvaluationContext, Finding, Severity
from ..core.utils import SlidingWindowCounter
from .base import Detector

LOGGER = get_logger("detect.anomaly")

#: Tool-name substrings marking each stage of the kill chain.
_CHAIN_STAGES: Dict[str, tuple[str, ...]] = {
    "recon": ("list", "search", "find", "scan", "enumerate", "describe", "glob"),
    "collect": ("read", "get", "fetch", "cat", "download", "query", "select", "dump"),
    "egress": ("post", "send", "upload", "write_url", "http", "request", "email", "webhook", "publish"),
}

#: Ordered stage progression that constitutes an exfiltration chain.
_CHAIN_ORDER = ("recon", "collect", "egress")

#: Hours (UTC, 24h) outside which high-risk operations are considered off-hours.
_WORKING_HOURS = (7, 21)


@dataclass
class SequenceRule:
    """A "tool A shortly followed by tool B" pattern worth alerting on.

    ``source`` and ``sink`` are lowercase substring markers matched against tool
    names, so ``("secret", "http")`` fires for ``vault.read_secret`` followed by
    ``http.post`` regardless of the concrete naming convention in use.

    Attributes:
        id: Stable rule identifier used in evidence and tuning.
        source: Substrings identifying the data-acquisition step (any match).
        sink: Substrings identifying the data-release step (any match).
        window: How many recent calls may separate source from sink.
        severity: Severity assigned when the pair is observed.
        confidence: Base confidence for the finding.
        description: Human-readable explanation of the risk.
    """

    id: str
    source: tuple[str, ...]
    sink: tuple[str, ...]
    window: int = 6
    severity: Severity = Severity.HIGH
    confidence: float = 0.7
    description: str = ""

    def source_matches(self, tool: str) -> bool:
        low = (tool or "").lower()
        return any(marker in low for marker in self.source)

    def sink_matches(self, tool: str) -> bool:
        low = (tool or "").lower()
        return any(marker in low for marker in self.sink)


#: Built-in dangerous call sequences.  Each encodes a real post-compromise
#: pattern: acquire sensitive data, then push it somewhere the operator cannot
#: see.  They fire on the *sink* call, which is the last moment to intervene.
SEQUENCE_RULES: List[SequenceRule] = [
    SequenceRule(
        id="seq-secret-to-network",
        source=("secret", "credential", "vault", "keyring", "token"),
        sink=("http", "post", "request", "curl", "fetch", "webhook", "upload"),
        severity=Severity.CRITICAL,
        confidence=0.85,
        description="Credential read immediately followed by an outbound network call.",
    ),
    SequenceRule(
        id="seq-users-to-email",
        source=("list_user", "list_users", "get_users", "directory", "roster", "contacts"),
        sink=("email", "mail", "smtp", "send_message", "notify"),
        severity=Severity.HIGH,
        confidence=0.75,
        description="User/contact enumeration followed by a mass-communication tool.",
    ),
    SequenceRule(
        id="seq-db-to-http",
        source=("db_", "sql", "query", "select", "database", "table"),
        sink=("http", "post", "request", "webhook", "upload"),
        severity=Severity.HIGH,
        confidence=0.75,
        description="Database read followed by an HTTP POST - classic DB exfiltration.",
    ),
    SequenceRule(
        id="seq-file-to-upload",
        source=("read_file", "file_read", "cat", "open_file", "fs.read"),
        sink=("upload", "put_object", "s3", "attach", "share", "drive"),
        severity=Severity.HIGH,
        confidence=0.75,
        description="Local file read followed by an upload to external storage.",
    ),
    SequenceRule(
        id="seq-env-to-network",
        source=("env", "environ", "printenv", "dotenv", "config_dump"),
        sink=("http", "post", "request", "send", "webhook", "dns", "upload"),
        severity=Severity.CRITICAL,
        confidence=0.85,
        description="Environment dump followed by any network egress.",
    ),
    SequenceRule(
        id="seq-ssh-to-egress",
        source=(".ssh", "id_rsa", "private_key", "keypair"),
        sink=("http", "post", "send", "upload", "paste", "gist"),
        severity=Severity.CRITICAL,
        confidence=0.9,
        description="SSH key material read then pushed off-host.",
    ),
    SequenceRule(
        id="seq-cloudcreds-to-egress",
        source=("sts", "assume_role", "get_caller_identity", "metadata", "iam"),
        sink=("http", "post", "request", "upload", "webhook"),
        severity=Severity.CRITICAL,
        confidence=0.85,
        description="Cloud credential/identity probe followed by egress (SSRF chain).",
    ),
    SequenceRule(
        id="seq-screenshot-to-network",
        source=("screenshot", "screen_capture", "clipboard", "paste_read"),
        sink=("http", "post", "upload", "send", "webhook"),
        severity=Severity.HIGH,
        confidence=0.8,
        description="Screen/clipboard capture followed by an outbound transfer.",
    ),
    SequenceRule(
        id="seq-export-to-share",
        source=("export", "dump", "backup", "snapshot"),
        sink=("share", "publish", "public", "presign", "link"),
        severity=Severity.HIGH,
        confidence=0.75,
        description="Bulk export followed by a public-sharing operation.",
    ),
    SequenceRule(
        id="seq-recon-to-delete",
        source=("list", "search", "find", "enumerate"),
        sink=("delete", "drop", "purge", "destroy", "truncate", "wipe"),
        window=4,
        severity=Severity.HIGH,
        confidence=0.7,
        description="Enumeration immediately followed by destruction - ransom/wiper shape.",
    ),
    SequenceRule(
        id="seq-iam-to-grant",
        source=("whoami", "get_caller", "list_role", "list_permission"),
        sink=("grant", "attach_policy", "add_member", "create_key", "add_role"),
        severity=Severity.CRITICAL,
        confidence=0.8,
        description="Permission enumeration followed by a privilege grant - escalation.",
    ),
    SequenceRule(
        id="seq-repo-to-publish",
        source=("clone", "checkout", "repo_read", "source"),
        sink=("push", "publish", "npm", "pypi", "release", "gist"),
        severity=Severity.HIGH,
        confidence=0.7,
        description="Source read followed by a package/repository publish.",
    ),
]


@dataclass
class ToolProfile:
    """Rolling statistics for one tool within one session."""

    calls: int = 0
    total_arg_bytes: int = 0
    max_arg_bytes: int = 0

    @property
    def mean_arg_bytes(self) -> float:
        return self.total_arg_bytes / self.calls if self.calls else 0.0

    def observe(self, size: int) -> None:
        self.calls += 1
        self.total_arg_bytes += size
        self.max_arg_bytes = max(self.max_arg_bytes, size)


class AnomalyDetector(Detector):
    """Flags statistically unusual or chain-like agent behaviour."""

    name = "anomaly"
    kind = DetectorKind.ANOMALY
    default_severity = Severity.MEDIUM

    def __init__(
        self,
        *,
        enabled: bool = True,
        min_confidence: float = 0.35,
        burst_window_s: float = 60.0,
        burst_threshold: int = 20,
        size_multiplier: float = 8.0,
        min_calls_for_baseline: int = 5,
        sequence_rules: Optional[Sequence[SequenceRule]] = None,
        **options: Any,
    ) -> None:
        """Args:
        enabled: Registry enable flag.
        min_confidence: Drop findings below this confidence.
        burst_window_s: Sliding window used for rate anomaly detection.
        burst_threshold: Calls within the window that constitute a burst.
        size_multiplier: Argument size vs baseline mean that is "unusual".
        min_calls_for_baseline: Calls needed before size baselines are trusted.
        sequence_rules: Override the built-in :data:`SEQUENCE_RULES`.
        """
        super().__init__(enabled=enabled, **options)
        self.sequence_rules: List[SequenceRule] = list(sequence_rules or SEQUENCE_RULES)
        self.min_confidence = float(min_confidence)
        self.burst_threshold = int(burst_threshold)
        self.size_multiplier = float(size_multiplier)
        self.min_calls_for_baseline = int(min_calls_for_baseline)
        self._window = SlidingWindowCounter(window_s=float(burst_window_s))
        self._profiles: Dict[str, ToolProfile] = {}
        self._seen_tools: Dict[str, set[str]] = {}
        self._lock = threading.Lock()

    def analyze(self, ctx: EvaluationContext) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._check_rate(ctx))
        findings.extend(self._check_first_use(ctx))
        findings.extend(self._check_argument_size(ctx))
        findings.extend(self._check_kill_chain(ctx))
        findings.extend(self._check_sequences(ctx))
        findings.extend(self._check_off_hours(ctx))
        return findings

    # ------------------------------------------------------------------ #
    # Probes
    # ------------------------------------------------------------------ #
    def _check_rate(self, ctx: EvaluationContext) -> List[Finding]:
        key = f"{ctx.session.id}:{ctx.call.tool}"
        count = self._window.hit(key)
        if count < self.burst_threshold:
            return []
        excess = count / max(1, self.burst_threshold)
        return [
            self.make_finding(
                "Tool-call burst",
                description=(
                    f"'{ctx.call.tool}' was called {count} times in the rate window - "
                    "consistent with an automated loop or a runaway agent."
                ),
                severity=Severity.HIGH if excess >= 2 else Severity.MEDIUM,
                confidence=min(0.9, 0.5 + 0.1 * excess),
                evidence=[f"calls={count}", f"threshold={self.burst_threshold}"],
                location="session",
                remediation="Throttle the agent and inspect the loop condition.",
                tags=["anomaly", "rate"],
            )
        ]

    def _check_first_use(self, ctx: EvaluationContext) -> List[Finding]:
        tool = ctx.call.qualified_name
        with self._lock:
            seen = self._seen_tools.setdefault(ctx.agent.id, set())
            first_time = tool not in seen
            seen.add(tool)
        if not first_time:
            return []
        # First use is only interesting when the session already has history:
        # a brand new session legitimately uses everything for the first time.
        if len(ctx.history) < 3:
            return []
        return [
            self.make_finding(
                "First-ever use of this tool by the agent",
                description=(
                    f"Agent '{ctx.agent.name}' has never invoked '{tool}' before in this "
                    "process. Novel capability use mid-session warrants a look."
                ),
                severity=Severity.LOW,
                confidence=0.45,
                evidence=[f"tool={tool}", f"history={','.join(ctx.history[-5:])}"],
                location="session.history",
                remediation="Verify the new capability is in the agent's permission profile.",
                tags=["anomaly", "novel_tool"],
            )
        ]

    def _check_argument_size(self, ctx: EvaluationContext) -> List[Finding]:
        from .text_sources import argument_string

        size = len(argument_string(ctx.call.arguments))
        key = f"{ctx.agent.id}:{ctx.call.qualified_name}"
        with self._lock:
            profile = self._profiles.setdefault(key, ToolProfile())
            baseline = profile.mean_arg_bytes
            calls = profile.calls
            profile.observe(size)
        if calls < self.min_calls_for_baseline or baseline <= 0:
            return []
        ratio = size / baseline
        if ratio < self.size_multiplier:
            return []
        return [
            self.make_finding(
                "Unusually large tool arguments",
                description=(
                    f"Argument payload is {ratio:.1f}x the historical mean for this tool "
                    "- typical of bulk data staging before exfiltration."
                ),
                severity=Severity.MEDIUM,
                confidence=min(0.85, 0.4 + ratio / 40.0),
                evidence=[f"bytes={size}", f"baseline={baseline:.0f}", f"ratio={ratio:.1f}x"],
                location="arguments",
                remediation="Inspect the payload; consider a size cap for this tool.",
                tags=["anomaly", "volume"],
            )
        ]

    def _check_kill_chain(self, ctx: EvaluationContext) -> List[Finding]:
        sequence = list(ctx.history) + [ctx.call.tool]
        stages: List[str] = []
        for tool in sequence:
            low = (tool or "").lower()
            for stage, markers in _CHAIN_STAGES.items():
                if any(marker in low for marker in markers):
                    if not stages or stages[-1] != stage:
                        stages.append(stage)
                    break
        progressed = _longest_ordered_run(stages, _CHAIN_ORDER)
        if progressed < 3:
            return []
        return [
            self.make_finding(
                "Reconnaissance to egress chain observed",
                description=(
                    "The session walked the full recon -> collect -> egress sequence, the "
                    "canonical shape of an automated data-theft chain."
                ),
                severity=Severity.HIGH,
                confidence=0.7,
                evidence=[f"stages={'>'.join(stages)}", f"tools={','.join(sequence[-6:])}"],
                location="session.history",
                remediation="Require approval for the egress step and review the session transcript.",
                tags=["anomaly", "kill_chain", "exfiltration"],
            )
        ]

    def _check_sequences(self, ctx: EvaluationContext) -> List[Finding]:
        """Match the current call against every built-in :class:`SequenceRule`.

        The current tool is treated as the *sink*; the rule fires when a matching
        *source* appears within ``rule.window`` preceding calls of this session.
        """
        current = ctx.call.qualified_name or ctx.call.tool
        history = list(ctx.history)
        if not history:
            return []
        findings: List[Finding] = []
        for rule in self.sequence_rules:
            if not rule.sink_matches(current):
                continue
            recent = history[-rule.window :]
            source = next((tool for tool in reversed(recent) if rule.source_matches(tool)), None)
            if source is None:
                continue
            findings.append(
                self.make_finding(
                    f"Dangerous tool sequence: {rule.id}",
                    description=(
                        f"{rule.description} Observed '{source}' followed by '{current}' "
                        f"within {rule.window} calls."
                    ),
                    severity=rule.severity,
                    confidence=rule.confidence,
                    evidence=[
                        f"rule={rule.id}",
                        f"source={source}",
                        f"sink={current}",
                        f"recent={','.join(recent)}",
                    ],
                    location="session.history",
                    remediation=(
                        "Require approval for the sink call and verify the data it carries "
                        "was not obtained from the sensitive source step."
                    ),
                    tags=["anomaly", "sequence", rule.id],
                )
            )
        return findings

    def _check_off_hours(self, ctx: EvaluationContext) -> List[Finding]:
        """Flag high-risk categories executed outside normal working hours."""
        risky = {"destructive", "secret", "payment", "identity", "deploy", "data_export"}
        categories = {c.value for c in (ctx.categories or [])}
        if not (categories & risky):
            return []
        hour = time.gmtime(ctx.now or time.time()).tm_hour
        start, end = _WORKING_HOURS
        if start <= hour < end:
            return []
        return [
            self.make_finding(
                "High-risk operation outside working hours",
                description=(
                    f"A {'/'.join(sorted(categories & risky))} operation ran at {hour:02d}:00 UTC, "
                    "outside the configured working window. Off-hours privileged activity is a "
                    "standard indicator of compromised automation."
                ),
                severity=Severity.MEDIUM,
                confidence=0.5,
                evidence=[f"hour_utc={hour}", f"window={start}-{end}", f"tool={ctx.call.tool}"],
                location="session",
                remediation="Confirm the schedule is expected; otherwise require human approval.",
                tags=["anomaly", "off_hours"],
            )
        ]

    def stats(self) -> Dict[str, Any]:
        """Counters for observability endpoints."""
        with self._lock:
            return {
                "profiles": len(self._profiles),
                "agents": len(self._seen_tools),
                "burst_threshold": self.burst_threshold,
                "sequence_rules": len(self.sequence_rules),
            }

    def reset(self) -> None:
        """Clear all learned baselines (used by tests and tenant teardown)."""
        with self._lock:
            self._profiles.clear()
            self._seen_tools.clear()


def _longest_ordered_run(observed: Sequence[str], order: Sequence[str]) -> int:
    """Length of the longest prefix of ``order`` appearing in sequence."""
    index = 0
    for stage in observed:
        if index < len(order) and stage == order[index]:
            index += 1
    return index


#: Contract-facing alias.  ``BehaviorAnomalyDetector`` is the name used in the
#: architecture documents and the cross-module call contract.
BehaviorAnomalyDetector = AnomalyDetector

__all__ = [
    "AnomalyDetector",
    "BehaviorAnomalyDetector",
    "SequenceRule",
    "SEQUENCE_RULES",
    "ToolProfile",
]
