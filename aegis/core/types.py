"""Shared domain contract for AegisAgent.

Every subsystem (policy, provenance, detection, sandbox, approval, audit) speaks
the vocabulary defined here.  The module is intentionally dependency-free
(standard library only) so it can be imported from CLI tools, workers and the
FastAPI control plane without pulling optional extras.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple

__all__ = [
    "RiskLevel",
    "Effect",
    "ActionCategory",
    "ProvenanceStatus",
    "Severity",
    "DetectorKind",
    "ApprovalState",
    "SandboxKind",
    "IncidentStatus",
    "TransportKind",
    "Principal",
    "AgentIdentity",
    "SessionRef",
    "ToolParameter",
    "ToolDescriptor",
    "ModelCompletion",
    "ToolCall",
    "ToolResult",
    "ProvenanceRecord",
    "Finding",
    "PolicyMatch",
    "Decision",
    "EvaluationContext",
    "ApprovalRequest",
    "AuditEvent",
    "Incident",
    "SandboxSpec",
    "SandboxResult",
    "RedTeamOutcome",
    "new_id",
    "utc_now",
    "to_dict",
]


# --------------------------------------------------------------------------- #
# Primitives
# --------------------------------------------------------------------------- #
def new_id(prefix: str = "obj") -> str:
    """Return a short, sortable, prefixed identifier."""
    return f"{prefix}_{uuid.uuid4().hex[:20]}"


def utc_now() -> float:
    """Epoch seconds with sub-millisecond precision (UTC)."""
    return time.time()


def to_dict(obj: Any) -> Any:
    """Recursively convert dataclasses / enums into JSON-safe primitives."""
    if isinstance(obj, Enum):
        return obj.value
    if hasattr(obj, "__dataclass_fields__"):
        return {k: to_dict(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {str(k): to_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [to_dict(v) for v in obj]
    return obj


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #
class RiskLevel(str, Enum):
    """Normalised risk banding used across classification and policy."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def score(self) -> int:
        return {"none": 0, "low": 25, "medium": 50, "high": 75, "critical": 100}[self.value]

    @classmethod
    def from_score(cls, score: float) -> "RiskLevel":
        if score >= 90:
            return cls.CRITICAL
        if score >= 70:
            return cls.HIGH
        if score >= 40:
            return cls.MEDIUM
        if score > 0:
            return cls.LOW
        return cls.NONE

    def at_least(self, other: "RiskLevel") -> bool:
        return self.score >= other.score


class Effect(str, Enum):
    """Terminal policy effects, ordered by restrictiveness."""

    ALLOW = "allow"
    OBSERVE = "observe"          # allow but flag + record enriched telemetry
    REDACT = "redact"            # allow with argument/result redaction
    THROTTLE = "throttle"        # allow but rate limited
    SANDBOX = "sandbox"          # force execution inside an isolation driver
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"
    QUARANTINE = "quarantine"    # deny + freeze the whole session

    @property
    def rank(self) -> int:
        order = [
            "allow",
            "observe",
            "redact",
            "throttle",
            "sandbox",
            "require_approval",
            "deny",
            "quarantine",
        ]
        return order.index(self.value)

    @property
    def blocks_execution(self) -> bool:
        return self in (Effect.DENY, Effect.QUARANTINE, Effect.REQUIRE_APPROVAL)

    @classmethod
    def most_restrictive(cls, effects: Sequence["Effect"]) -> "Effect":
        if not effects:
            return cls.ALLOW
        return max(effects, key=lambda e: e.rank)


class ActionCategory(str, Enum):
    """Taxonomy of what a tool call actually does to the world."""

    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    NETWORK = "network"
    SECRET = "secret"
    IDENTITY = "identity"
    DEPLOY = "deploy"
    DESTRUCTIVE = "destructive"
    COMMUNICATION = "communication"
    PAYMENT = "payment"
    DATA_EXPORT = "data_export"
    CONFIG = "config"
    UNKNOWN = "unknown"

    @property
    def default_risk(self) -> RiskLevel:
        return {
            "read": RiskLevel.LOW,
            "write": RiskLevel.MEDIUM,
            "execute": RiskLevel.HIGH,
            "network": RiskLevel.MEDIUM,
            "secret": RiskLevel.HIGH,
            "identity": RiskLevel.HIGH,
            "deploy": RiskLevel.HIGH,
            "destructive": RiskLevel.CRITICAL,
            "communication": RiskLevel.MEDIUM,
            "payment": RiskLevel.CRITICAL,
            "data_export": RiskLevel.HIGH,
            "config": RiskLevel.MEDIUM,
            "unknown": RiskLevel.MEDIUM,
        }[self.value]


class ProvenanceStatus(str, Enum):
    """Result of binding a tool call back to a real model completion.

    This is the core defence against the ``CoreBreak`` class of guardrail
    bypasses (CVE-2026-18830 / CVE-2026-18236 / CVE-2026-64650), where a tool is
    dispatched without the model ever authorising it.
    """

    VERIFIED = "verified"
    UNSIGNED = "unsigned"
    MISSING = "missing"
    FORGED = "forged"
    REPLAYED = "replayed"
    EXPIRED = "expired"
    MISMATCHED = "mismatched"      # name/args differ from the recorded completion
    ORPHANED = "orphaned"          # no completion recorded in the session ledger
    UNTRUSTED_ISSUER = "untrusted_issuer"

    @property
    def is_trustworthy(self) -> bool:
        return self is ProvenanceStatus.VERIFIED

    @property
    def risk(self) -> RiskLevel:
        return {
            "verified": RiskLevel.NONE,
            "unsigned": RiskLevel.MEDIUM,
            "missing": RiskLevel.HIGH,
            "forged": RiskLevel.CRITICAL,
            "replayed": RiskLevel.CRITICAL,
            "expired": RiskLevel.MEDIUM,
            "mismatched": RiskLevel.CRITICAL,
            "orphaned": RiskLevel.HIGH,
            "untrusted_issuer": RiskLevel.HIGH,
        }[self.value]


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def score(self) -> int:
        return {"info": 0, "low": 25, "medium": 50, "high": 75, "critical": 100}[self.value]


class DetectorKind(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    EXFILTRATION = "exfiltration"
    SECRET_LEAK = "secret_leak"
    TOOL_POISONING = "tool_poisoning"
    SCHEMA_DRIFT = "schema_drift"
    PROVENANCE = "provenance"
    ANOMALY = "anomaly"
    EGRESS = "egress"
    SANDBOX_ESCAPE = "sandbox_escape"
    SUPPLY_CHAIN = "supply_chain"
    POLICY = "policy"
    CONTENT = "content"


class ApprovalState(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    ESCALATED = "escalated"
    AUTO_APPROVED = "auto_approved"

    @property
    def is_terminal(self) -> bool:
        return self in (
            ApprovalState.APPROVED,
            ApprovalState.REJECTED,
            ApprovalState.EXPIRED,
            ApprovalState.CANCELLED,
            ApprovalState.AUTO_APPROVED,
        )


class SandboxKind(str, Enum):
    NONE = "none"
    SUBPROCESS = "subprocess"
    DOCKER = "docker"
    FIREJAIL = "firejail"
    GVISOR = "gvisor"
    REMOTE = "remote"


class IncidentStatus(str, Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class TransportKind(str, Enum):
    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"
    WEBSOCKET = "websocket"
    INPROC = "inproc"


# --------------------------------------------------------------------------- #
# Identity
# --------------------------------------------------------------------------- #
@dataclass
class Principal:
    """A human or service account acting on the platform."""

    id: str = field(default_factory=lambda: new_id("usr"))
    name: str = "anonymous"
    email: str = ""
    roles: List[str] = field(default_factory=lambda: ["viewer"])
    tenant_id: str = "default"
    mfa_verified: bool = False
    hardware_key_verified: bool = False
    attributes: Dict[str, Any] = field(default_factory=dict)

    def has_role(self, *roles: str) -> bool:
        return bool(set(roles) & set(self.roles)) or "admin" in self.roles


@dataclass
class AgentIdentity:
    """The autonomous agent whose actions are being governed."""

    id: str = field(default_factory=lambda: new_id("agt"))
    name: str = "unnamed-agent"
    tenant_id: str = "default"
    owner: str = ""
    model: str = "unknown"
    provider: str = "unknown"
    permission_profile: str = "default"
    labels: Dict[str, str] = field(default_factory=dict)
    trust_tier: str = "standard"        # untrusted | standard | trusted | privileged
    created_at: float = field(default_factory=utc_now)

    @property
    def is_untrusted(self) -> bool:
        return self.trust_tier == "untrusted"


@dataclass
class SessionRef:
    """A single agent run / conversation."""

    id: str = field(default_factory=lambda: new_id("ses"))
    agent_id: str = ""
    tenant_id: str = "default"
    principal_id: str = ""
    started_at: float = field(default_factory=utc_now)
    turn: int = 0
    labels: Dict[str, str] = field(default_factory=dict)
    quarantined: bool = False


# --------------------------------------------------------------------------- #
# Tools & model traffic
# --------------------------------------------------------------------------- #
@dataclass
class ToolParameter:
    name: str
    type: str = "string"
    description: str = ""
    required: bool = False
    enum: List[Any] = field(default_factory=list)
    max_length: Optional[int] = None
    pattern: Optional[str] = None


@dataclass
class ToolDescriptor:
    """Declared capability surface of a tool (MCP tool, function, plugin)."""

    name: str
    description: str = ""
    server: str = "local"
    transport: TransportKind = TransportKind.INPROC
    parameters: List[ToolParameter] = field(default_factory=list)
    categories: List[ActionCategory] = field(default_factory=list)
    reversible: bool = True
    idempotent: bool = False
    requires_approval: bool = False
    schema_hash: str = ""
    version: str = "1.0.0"
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def qualified_name(self) -> str:
        return f"{self.server}::{self.name}" if self.server else self.name


@dataclass
class ModelCompletion:
    """A recorded model turn. Tool calls must be traceable to one of these."""

    id: str = field(default_factory=lambda: new_id("cmp"))
    session_id: str = ""
    turn: int = 0
    model: str = ""
    provider: str = ""
    content: str = ""
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    finish_reason: str = "stop"
    created_at: float = field(default_factory=utc_now)
    prompt_hash: str = ""
    response_hash: str = ""
    usage: Dict[str, int] = field(default_factory=dict)


@dataclass
class ToolCall:
    """An intent to invoke a tool, before any enforcement decision."""

    id: str = field(default_factory=lambda: new_id("tc"))
    session_id: str = ""
    agent_id: str = ""
    tenant_id: str = "default"
    tool: str = ""
    server: str = "local"
    arguments: Dict[str, Any] = field(default_factory=dict)
    completion_id: Optional[str] = None
    turn: int = 0
    created_at: float = field(default_factory=utc_now)
    attestation: Optional[str] = None       # signed provenance token
    source: str = "model"                   # model | api | replay | orchestrator | unknown
    caller_ip: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def qualified_name(self) -> str:
        return f"{self.server}::{self.tool}" if self.server else self.tool


@dataclass
class ToolResult:
    call_id: str = ""
    ok: bool = True
    content: Any = None
    error: str = ""
    duration_ms: float = 0.0
    redacted: bool = False
    truncated: bool = False
    bytes_out: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Provenance
# --------------------------------------------------------------------------- #
@dataclass
class ProvenanceRecord:
    """Outcome of verifying that a tool call was truly authorised by the model."""

    call_id: str = ""
    status: ProvenanceStatus = ProvenanceStatus.MISSING
    completion_id: Optional[str] = None
    issuer: str = ""
    signature_algorithm: str = ""
    bound_hash: str = ""
    observed_hash: str = ""
    issued_at: float = 0.0
    verified_at: float = field(default_factory=utc_now)
    nonce: str = ""
    reasons: List[str] = field(default_factory=list)

    @property
    def trustworthy(self) -> bool:
        return self.status.is_trustworthy


# --------------------------------------------------------------------------- #
# Detection & policy
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    """A single security observation produced by a detector."""

    id: str = field(default_factory=lambda: new_id("fnd"))
    detector: str = ""
    kind: DetectorKind = DetectorKind.CONTENT
    severity: Severity = Severity.LOW
    title: str = ""
    description: str = ""
    confidence: float = 0.5
    evidence: List[str] = field(default_factory=list)
    location: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=utc_now)

    @property
    def weighted_score(self) -> float:
        return self.severity.score * max(0.0, min(1.0, self.confidence))


@dataclass
class PolicyMatch:
    rule_id: str = ""
    policy_id: str = ""
    effect: Effect = Effect.ALLOW
    priority: int = 0
    reason: str = ""
    matched_on: List[str] = field(default_factory=list)
    obligations: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Decision:
    """Final enforcement verdict for one tool call."""

    id: str = field(default_factory=lambda: new_id("dec"))
    call_id: str = ""
    session_id: str = ""
    agent_id: str = ""
    tenant_id: str = "default"
    effect: Effect = Effect.ALLOW
    risk: RiskLevel = RiskLevel.LOW
    risk_score: float = 0.0
    categories: List[ActionCategory] = field(default_factory=list)
    provenance: Optional[ProvenanceRecord] = None
    findings: List[Finding] = field(default_factory=list)
    matches: List[PolicyMatch] = field(default_factory=list)
    obligations: Dict[str, Any] = field(default_factory=dict)
    approval_id: Optional[str] = None
    reason: str = ""
    evaluated_at: float = field(default_factory=utc_now)
    duration_ms: float = 0.0
    policy_bundle_version: str = ""
    dry_run: bool = False

    @property
    def allowed(self) -> bool:
        return not self.effect.blocks_execution

    @property
    def top_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: f.weighted_score, reverse=True)[:5]

    def explain(self) -> str:
        bits = [f"effect={self.effect.value}", f"risk={self.risk.value}({self.risk_score:.0f})"]
        if self.provenance:
            bits.append(f"provenance={self.provenance.status.value}")
        if self.matches:
            bits.append("rules=" + ",".join(m.rule_id for m in self.matches[:3]))
        if self.findings:
            bits.append(f"findings={len(self.findings)}")
        return " ".join(bits) + (f" :: {self.reason}" if self.reason else "")


@dataclass
class EvaluationContext:
    """Everything the policy engine may inspect when judging a call."""

    call: ToolCall
    agent: AgentIdentity
    session: SessionRef
    descriptor: Optional[ToolDescriptor] = None
    provenance: Optional[ProvenanceRecord] = None
    findings: List[Finding] = field(default_factory=list)
    categories: List[ActionCategory] = field(default_factory=list)
    risk: RiskLevel = RiskLevel.LOW
    risk_score: float = 0.0
    principal: Optional[Principal] = None
    environment: str = "production"
    history: List[str] = field(default_factory=list)   # recent tool names this session
    counters: Dict[str, int] = field(default_factory=dict)
    now: float = field(default_factory=utc_now)
    extra: Dict[str, Any] = field(default_factory=dict)

    def attribute(self, path: str) -> Any:
        """Resolve a dotted attribute path used by the policy condition DSL."""
        cursor: Any = {
            "call": self.call,
            "agent": self.agent,
            "session": self.session,
            "tool": self.descriptor,
            "provenance": self.provenance,
            "principal": self.principal,
            "risk": self.risk,
            "risk_score": self.risk_score,
            "environment": self.environment,
            "categories": [c.value for c in self.categories],
            "counters": self.counters,
            "extra": self.extra,
        }
        for part in path.split("."):
            if cursor is None:
                return None
            if isinstance(cursor, dict):
                cursor = cursor.get(part)
            else:
                cursor = getattr(cursor, part, None)
        if isinstance(cursor, Enum):
            return cursor.value
        return cursor


# --------------------------------------------------------------------------- #
# Approval / audit / incidents
# --------------------------------------------------------------------------- #
@dataclass
class ApprovalRequest:
    id: str = field(default_factory=lambda: new_id("apr"))
    call_id: str = ""
    decision_id: str = ""
    session_id: str = ""
    agent_id: str = ""
    tenant_id: str = "default"
    tool: str = ""
    arguments_preview: Dict[str, Any] = field(default_factory=dict)
    risk: RiskLevel = RiskLevel.HIGH
    blast_radius: str = ""
    justification: str = ""
    state: ApprovalState = ApprovalState.PENDING
    requested_at: float = field(default_factory=utc_now)
    expires_at: float = 0.0
    decided_at: Optional[float] = None
    decided_by: str = ""
    decision_note: str = ""
    required_roles: List[str] = field(default_factory=lambda: ["approver"])
    require_step_up: bool = False
    escalation_level: int = 0
    channels: List[str] = field(default_factory=list)

    def is_expired(self, now: Optional[float] = None) -> bool:
        now = now if now is not None else utc_now()
        return self.expires_at > 0 and now > self.expires_at and not self.state.is_terminal


@dataclass
class AuditEvent:
    """One tamper-evident ledger entry."""

    id: str = field(default_factory=lambda: new_id("evt"))
    sequence: int = 0
    timestamp: float = field(default_factory=utc_now)
    tenant_id: str = "default"
    actor: str = "system"
    action: str = ""
    resource: str = ""
    outcome: str = "success"
    severity: Severity = Severity.INFO
    session_id: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""
    hash: str = ""
    signature: str = ""


@dataclass
class Incident:
    id: str = field(default_factory=lambda: new_id("inc"))
    tenant_id: str = "default"
    title: str = ""
    summary: str = ""
    severity: Severity = Severity.MEDIUM
    status: IncidentStatus = IncidentStatus.OPEN
    session_id: str = ""
    agent_id: str = ""
    findings: List[Finding] = field(default_factory=list)
    decision_ids: List[str] = field(default_factory=list)
    opened_at: float = field(default_factory=utc_now)
    updated_at: float = field(default_factory=utc_now)
    assignee: str = ""
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    containment: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Sandbox & red team
# --------------------------------------------------------------------------- #
@dataclass
class SandboxSpec:
    kind: SandboxKind = SandboxKind.SUBPROCESS
    image: str = "python:3.12-slim"
    workdir: str = "/workspace"
    timeout_s: float = 30.0
    memory_mb: int = 512
    cpu_quota: float = 1.0
    pids_limit: int = 128
    network: str = "deny"                  # deny | allowlist | allow
    egress_allowlist: List[str] = field(default_factory=list)
    read_only_root: bool = True
    writable_paths: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    drop_capabilities: List[str] = field(default_factory=lambda: ["ALL"])
    seccomp_profile: str = "default"
    no_new_privileges: bool = True
    canary_tokens: List[str] = field(default_factory=list)
    user: str = "10001:10001"


@dataclass
class SandboxResult:
    ok: bool = True
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    duration_ms: float = 0.0
    timed_out: bool = False
    killed: bool = False
    escape_detected: bool = False
    egress_blocked: List[str] = field(default_factory=list)
    canaries_triggered: List[str] = field(default_factory=list)
    resource_usage: Dict[str, Any] = field(default_factory=dict)
    driver: str = "subprocess"


@dataclass
class RedTeamOutcome:
    scenario_id: str = ""
    name: str = ""
    category: str = ""
    passed: bool = False           # True == the platform successfully defended
    expected_effect: str = ""
    observed_effect: str = ""
    severity: Severity = Severity.MEDIUM
    detail: str = ""
    duration_ms: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


def summarize_decisions(decisions: Sequence[Decision]) -> Dict[str, Any]:
    """Aggregate helper reused by CLI, API and reporting layers."""
    total = len(decisions)
    by_effect: Dict[str, int] = {}
    blocked = 0
    risk_sum = 0.0
    for d in decisions:
        by_effect[d.effect.value] = by_effect.get(d.effect.value, 0) + 1
        risk_sum += d.risk_score
        if d.effect.blocks_execution:
            blocked += 1
    return {
        "total": total,
        "blocked": blocked,
        "allowed": total - blocked,
        "block_rate": round(blocked / total, 4) if total else 0.0,
        "avg_risk": round(risk_sum / total, 2) if total else 0.0,
        "by_effect": by_effect,
    }


def diff_arguments(expected: Dict[str, Any], observed: Dict[str, Any]) -> List[Tuple[str, Any, Any]]:
    """Return (key, expected, observed) triples that differ - used by provenance."""
    keys = set(expected) | set(observed)
    out: List[Tuple[str, Any, Any]] = []
    for key in sorted(keys):
        a, b = expected.get(key), observed.get(key)
        if a != b:
            out.append((key, a, b))
    return out
