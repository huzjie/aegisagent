"""Data models for the human-in-the-loop approval layer.

The 2026-08 incidents at three major agent platforms shared one root cause:
the approval artefact was **not cryptographically bound to the action it
approved**.  An attacker could get a benign call approved and then redeem the
approval for a different, malicious call (a classic time-of-check /
time-of-use swap), or simply replay a previously granted approval.

Every model in this module therefore carries three defences:

``binding``
    A fingerprint over the *exact* tool name plus canonicalised arguments.
    Redemption re-computes the fingerprint and refuses on mismatch.
``nonce`` + ``single_use``
    Receipts are one-shot.  A redeemed receipt is burned and can never be
    presented again.
``signature``
    An HMAC over the canonical receipt body, so a forged approval object
    injected into the process (or reconstructed from a log) fails validation.

Nothing here performs I/O; persistence lives in :mod:`aegis.approval.store`
and orchestration in :mod:`aegis.approval.workflow`.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence

from ..core.crypto import (
    canonical_json,
    constant_time_equals,
    fingerprint,
    hmac_sign,
    hmac_verify,
    random_nonce,
    sha256_hex,
)
from ..core.errors import ValidationError
from ..core.types import (
    ApprovalRequest,
    ApprovalState,
    Principal,
    RiskLevel,
    ToolCall,
    new_id,
    utc_now,
)
from ..core.utils import deep_redact_preview, truncate

__all__ = [
    "VoteKind",
    "ApprovalChannel",
    "ApprovalVote",
    "QuorumRule",
    "ApprovalPolicy",
    "ApprovalReceipt",
    "ApprovalTicket",
    "ApprovalOutcome",
    "compute_binding",
    "preview_arguments",
    "DEFAULT_QUORUM",
    "DEFAULT_POLICY",
]


# ---------------------------------------------------------------------------
# enums
# ---------------------------------------------------------------------------


class VoteKind(str, Enum):
    """How a single approver responded to a ticket."""

    APPROVE = "approve"
    REJECT = "reject"
    ABSTAIN = "abstain"
    REQUEST_INFO = "request_info"

    @property
    def is_decisive(self) -> bool:
        """Whether this vote can move a ticket toward a terminal state."""
        return self in (VoteKind.APPROVE, VoteKind.REJECT)


class ApprovalChannel(str, Enum):
    """Delivery channels used to *notify* approvers.

    A channel never carries authority.  Notifications are one-way; the actual
    vote must arrive through an authenticated call into
    :class:`aegis.approval.workflow.ApprovalWorkflow`.  This split is what
    prevents "reply YES to this webhook" style forgery.
    """

    CONSOLE = "console"
    WEBHOOK = "webhook"
    SLACK = "slack"
    EMAIL = "email"
    WECOM = "wecom"

    @property
    def is_interactive(self) -> bool:
        """True when a human is expected to read the message directly."""
        return self in (ApprovalChannel.CONSOLE, ApprovalChannel.SLACK, ApprovalChannel.WECOM)


# ---------------------------------------------------------------------------
# binding helpers
# ---------------------------------------------------------------------------


def compute_binding(tool: str, arguments: Mapping[str, Any], *, extra: Optional[Mapping[str, Any]] = None) -> str:
    """Return the fingerprint that binds an approval to one concrete action.

    Args:
        tool: Fully qualified tool name (``server.tool`` for MCP calls).
        arguments: The argument mapping that will actually be executed.
        extra: Optional additional context folded into the binding, e.g.
            ``{"target_account": "prod-1"}``.  Use it when the same arguments
            mean different things in different environments.

    Returns:
        A stable hex fingerprint.  Two calls that differ in *any* argument
        value, key order aside, produce different fingerprints.
    """
    body: Dict[str, Any] = {"tool": tool, "arguments": dict(arguments or {})}
    if extra:
        body["extra"] = dict(extra)
    return fingerprint(body, length=32)


def preview_arguments(arguments: Mapping[str, Any], *, max_len: int = 160) -> Dict[str, Any]:
    """Build a redacted, human-readable argument preview for approvers.

    Approvers must see enough to judge blast radius but never raw secrets.
    Values are truncated and known-secret shapes are masked by
    :func:`aegis.core.utils.deep_redact_preview`.

    Args:
        arguments: Raw argument mapping.
        max_len: Per-value truncation limit.

    Returns:
        A new mapping safe to render in Slack/email/console.
    """
    preview = deep_redact_preview(dict(arguments or {}), max_len=max_len)
    return preview if isinstance(preview, dict) else {"value": preview}


# ---------------------------------------------------------------------------
# votes
# ---------------------------------------------------------------------------


@dataclass
class ApprovalVote:
    """One approver's response, signed against the ticket binding."""

    id: str = field(default_factory=lambda: new_id("vote"))
    ticket_id: str = ""
    approver_id: str = ""
    approver_name: str = ""
    approver_roles: List[str] = field(default_factory=list)
    kind: VoteKind = VoteKind.ABSTAIN
    note: str = ""
    channel: ApprovalChannel = ApprovalChannel.CONSOLE
    step_up_verified: bool = False
    step_up_method: str = ""
    binding: str = ""
    cast_at: float = field(default_factory=utc_now)
    source_ip: str = ""
    signature: str = ""

    def payload(self) -> Dict[str, Any]:
        """Return the canonical body that the signature covers."""
        return {
            "id": self.id,
            "ticket_id": self.ticket_id,
            "approver_id": self.approver_id,
            "kind": self.kind.value,
            "binding": self.binding,
            "step_up_verified": self.step_up_verified,
            "cast_at": round(self.cast_at, 3),
        }

    def sign(self, key: str) -> str:
        """Sign the vote with ``key`` and store the signature.

        Args:
            key: HMAC key material, normally derived per tenant.

        Returns:
            The hex signature that was stored on the vote.
        """
        self.signature = hmac_sign(key, canonical_json(self.payload()))
        return self.signature

    def verify(self, key: str) -> bool:
        """Check the stored signature against ``key``.

        Args:
            key: The same HMAC key used by :meth:`sign`.

        Returns:
            ``True`` when the signature is present and valid.
        """
        if not self.signature:
            return False
        return hmac_verify(key, canonical_json(self.payload()), self.signature)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable representation."""
        data = asdict(self)
        data["kind"] = self.kind.value
        data["channel"] = self.channel.value
        return data


# ---------------------------------------------------------------------------
# quorum + policy
# ---------------------------------------------------------------------------


@dataclass
class QuorumRule:
    """How many, and which, approvers are needed to release a ticket."""

    min_approvals: int = 1
    required_roles: List[str] = field(default_factory=lambda: ["approver"])
    require_distinct_principals: bool = True
    deny_self_approval: bool = True
    require_step_up: bool = False
    require_all_roles: bool = False
    veto_on_any_reject: bool = True

    def validate(self) -> None:
        """Raise :class:`ValidationError` when the rule is self-contradictory."""
        if self.min_approvals < 1:
            raise ValidationError("quorum.min_approvals must be >= 1", details={"field": "min_approvals"})
        if not self.required_roles:
            raise ValidationError("quorum.required_roles must not be empty", details={"field": "required_roles"})
        if self.require_all_roles and self.min_approvals < len(self.required_roles):
            raise ValidationError(
                "quorum.min_approvals must cover every required role when require_all_roles is set",
                details={"field": "min_approvals"},
            )

    def role_allows(self, principal: Principal) -> bool:
        """Whether ``principal`` holds a role that may vote on this ticket.

        Args:
            principal: The voting identity.

        Returns:
            ``True`` if at least one required role matches (``admin`` is a
            wildcard handled by :meth:`Principal.has_role`).
        """
        return principal.has_role(*self.required_roles)

    def describe(self) -> str:
        """Return a one-line human summary used in notifications."""
        bits = [f"{self.min_approvals} approval(s)", "roles=" + "|".join(self.required_roles)]
        if self.require_step_up:
            bits.append("step-up required")
        if self.deny_self_approval:
            bits.append("no self-approval")
        if self.require_distinct_principals and self.min_approvals > 1:
            bits.append("distinct humans")
        return ", ".join(bits)


DEFAULT_QUORUM: Dict[RiskLevel, QuorumRule] = {
    RiskLevel.NONE: QuorumRule(min_approvals=1, required_roles=["approver"]),
    RiskLevel.LOW: QuorumRule(min_approvals=1, required_roles=["approver"]),
    RiskLevel.MEDIUM: QuorumRule(min_approvals=1, required_roles=["approver"]),
    RiskLevel.HIGH: QuorumRule(
        min_approvals=1,
        required_roles=["approver", "security"],
        require_step_up=False,
    ),
    RiskLevel.CRITICAL: QuorumRule(
        min_approvals=2,
        required_roles=["approver", "security"],
        require_distinct_principals=True,
        deny_self_approval=True,
        require_step_up=True,
    ),
}


@dataclass
class ApprovalPolicy:
    """Tenant-level configuration of the approval layer."""

    enabled: bool = True
    default_ttl_s: int = 900
    auto_approve_below: RiskLevel = RiskLevel.MEDIUM
    escalate_after_s: int = 300
    max_escalation_level: int = 3
    require_step_up_for: List[RiskLevel] = field(default_factory=lambda: [RiskLevel.CRITICAL])
    channels: List[ApprovalChannel] = field(default_factory=lambda: [ApprovalChannel.CONSOLE])
    quorum: Dict[RiskLevel, QuorumRule] = field(default_factory=lambda: dict(DEFAULT_QUORUM))
    break_glass_enabled: bool = True
    break_glass_ttl_s: int = 1800
    fail_closed: bool = True
    receipt_ttl_s: int = 300
    bind_arguments: bool = True

    def quorum_for(self, risk: RiskLevel) -> QuorumRule:
        """Return the quorum rule that applies to ``risk``.

        Args:
            risk: Risk level attached to the pending decision.

        Returns:
            The configured rule, falling back to the strictest known rule when
            the level is missing from the mapping (fail-closed).
        """
        rule = self.quorum.get(risk)
        if rule is not None:
            return rule
        if self.fail_closed:
            return self.quorum.get(RiskLevel.CRITICAL, DEFAULT_QUORUM[RiskLevel.CRITICAL])
        return QuorumRule()

    def needs_step_up(self, risk: RiskLevel) -> bool:
        """Whether ``risk`` mandates a fresh second-factor challenge."""
        if risk in self.require_step_up_for:
            return True
        return self.quorum_for(risk).require_step_up

    def can_auto_approve(self, risk: RiskLevel) -> bool:
        """Whether ``risk`` is low enough to skip the human entirely.

        Auto-approval is *strictly below* the configured threshold, never at
        it, so ``auto_approve_below=medium`` still stops medium-risk actions.
        """
        try:
            return risk.score < self.auto_approve_below.score
        except AttributeError:  # pragma: no cover - defensive for enum drift
            return False

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ApprovalPolicy":
        """Build a policy from a raw configuration section.

        Args:
            data: The ``approval`` section of :class:`aegis.core.config.Settings`.

        Returns:
            A populated policy; unknown keys are ignored so that newer config
            files stay loadable by older builds.
        """
        policy = cls()
        policy.enabled = bool(data.get("enabled", policy.enabled))
        policy.default_ttl_s = int(data.get("default_ttl_s", policy.default_ttl_s))
        policy.escalate_after_s = int(data.get("escalate_after_s", policy.escalate_after_s))
        policy.break_glass_enabled = bool(data.get("break_glass_enabled", policy.break_glass_enabled))
        policy.break_glass_ttl_s = int(data.get("break_glass_ttl_s", policy.break_glass_ttl_s))
        raw_below = data.get("auto_approve_below")
        if isinstance(raw_below, str):
            policy.auto_approve_below = _coerce_risk(raw_below, policy.auto_approve_below)
        raw_step_up = data.get("require_step_up_for")
        if isinstance(raw_step_up, (list, tuple)):
            policy.require_step_up_for = [_coerce_risk(str(x), RiskLevel.CRITICAL) for x in raw_step_up]
        raw_channels = data.get("channels")
        if isinstance(raw_channels, (list, tuple)):
            channels: List[ApprovalChannel] = []
            for name in raw_channels:
                try:
                    channels.append(ApprovalChannel(str(name).strip().lower()))
                except ValueError:
                    continue
            if channels:
                policy.channels = channels
        return policy


def _coerce_risk(raw: str, default: RiskLevel) -> RiskLevel:
    """Parse a risk level name, returning ``default`` when unrecognised."""
    try:
        return RiskLevel(raw.strip().lower())
    except ValueError:
        return default


DEFAULT_POLICY = ApprovalPolicy()


# ---------------------------------------------------------------------------
# receipts
# ---------------------------------------------------------------------------


@dataclass
class ApprovalReceipt:
    """A single-use, signed proof that a specific action was approved.

    The receipt is the *only* artefact the enforcement path accepts.  A
    ``Decision`` carrying ``approval_id`` alone is never sufficient, because an
    identifier can be copied out of a log; the receipt additionally proves
    binding, freshness and non-replay.
    """

    id: str = field(default_factory=lambda: new_id("rcpt"))
    ticket_id: str = ""
    call_id: str = ""
    tenant_id: str = "default"
    binding: str = ""
    state: ApprovalState = ApprovalState.APPROVED
    approvers: List[str] = field(default_factory=list)
    step_up_verified: bool = False
    break_glass: bool = False
    nonce: str = field(default_factory=random_nonce)
    issued_at: float = field(default_factory=utc_now)
    expires_at: float = 0.0
    redeemed_at: Optional[float] = None
    signature: str = ""
    key_id: str = "default"

    def payload(self) -> Dict[str, Any]:
        """Return the canonical body covered by :attr:`signature`."""
        return {
            "id": self.id,
            "ticket_id": self.ticket_id,
            "call_id": self.call_id,
            "tenant_id": self.tenant_id,
            "binding": self.binding,
            "state": self.state.value,
            "approvers": sorted(self.approvers),
            "step_up_verified": self.step_up_verified,
            "break_glass": self.break_glass,
            "nonce": self.nonce,
            "issued_at": round(self.issued_at, 3),
            "expires_at": round(self.expires_at, 3),
        }

    def sign(self, key: str, *, key_id: str = "default") -> str:
        """Sign the receipt body.

        Args:
            key: HMAC key material.
            key_id: Identifier recorded so that keys can be rotated.

        Returns:
            The stored hex signature.
        """
        self.key_id = key_id
        self.signature = hmac_sign(key, canonical_json(self.payload()))
        return self.signature

    def verify_signature(self, key: str) -> bool:
        """Return whether the signature matches ``key``."""
        if not self.signature:
            return False
        return hmac_verify(key, canonical_json(self.payload()), self.signature)

    def is_expired(self, now: Optional[float] = None) -> bool:
        """Whether the receipt is past its short redemption window."""
        moment = now if now is not None else utc_now()
        return self.expires_at > 0 and moment > self.expires_at

    def matches(self, tool: str, arguments: Mapping[str, Any], *, extra: Optional[Mapping[str, Any]] = None) -> bool:
        """Check that the receipt was issued for exactly this call.

        Args:
            tool: Tool name about to execute.
            arguments: Arguments about to execute.
            extra: Additional binding context supplied at request time.

        Returns:
            ``True`` only when the recomputed fingerprint equals the bound one.
        """
        if not self.binding:
            return False
        return constant_time_equals(self.binding, compute_binding(tool, arguments, extra=extra))

    def token(self) -> str:
        """Return the compact string handed to the enforcement path."""
        return f"{self.id}.{self.nonce}.{self.signature[:32]}"

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable representation."""
        data = asdict(self)
        data["state"] = self.state.value
        return data


# ---------------------------------------------------------------------------
# tickets
# ---------------------------------------------------------------------------


@dataclass
class ApprovalTicket:
    """The mutable server-side record backing one :class:`ApprovalRequest`.

    ``request`` holds the shared wire-level shape defined in
    :mod:`aegis.core.types`; everything security-critical (binding, votes,
    quorum evaluation, receipt) lives on the ticket so that it never has to
    cross a trust boundary.
    """

    request: ApprovalRequest = field(default_factory=ApprovalRequest)
    binding: str = ""
    binding_extra: Dict[str, Any] = field(default_factory=dict)
    quorum: QuorumRule = field(default_factory=QuorumRule)
    votes: List[ApprovalVote] = field(default_factory=list)
    receipt: Optional[ApprovalReceipt] = None
    requester_id: str = ""
    notified_channels: List[str] = field(default_factory=list)
    escalated_at: List[float] = field(default_factory=list)
    break_glass: bool = False
    break_glass_grant_id: str = ""
    history: List[Dict[str, Any]] = field(default_factory=list)
    tool_arguments_hash: str = ""

    # -- identity -----------------------------------------------------------

    @property
    def id(self) -> str:
        """Ticket identifier (mirrors the wrapped request id)."""
        return self.request.id

    @property
    def state(self) -> ApprovalState:
        """Current lifecycle state."""
        return self.request.state

    @property
    def risk(self) -> RiskLevel:
        """Risk level carried by the originating decision."""
        return self.request.risk

    @property
    def is_terminal(self) -> bool:
        """Whether no further votes can change the outcome."""
        return self.request.state.is_terminal

    # -- construction -------------------------------------------------------

    @classmethod
    def from_call(
        cls,
        call: ToolCall,
        *,
        risk: RiskLevel = RiskLevel.HIGH,
        quorum: Optional[QuorumRule] = None,
        ttl_s: int = 900,
        decision_id: str = "",
        justification: str = "",
        blast_radius: str = "",
        requester_id: str = "",
        binding_extra: Optional[Mapping[str, Any]] = None,
        channels: Optional[Sequence[str]] = None,
    ) -> "ApprovalTicket":
        """Create a ticket bound to one concrete tool call.

        Args:
            call: The intercepted tool call awaiting a human verdict.
            risk: Risk level assigned by the policy engine.
            quorum: Quorum rule; defaults to the built-in rule for ``risk``.
            ttl_s: Seconds before the ticket auto-expires (fail-closed).
            decision_id: Identifier of the policy decision that raised this.
            justification: Why the agent claims it needs the action.
            blast_radius: Short description of what breaks if this is wrong.
            requester_id: Principal or agent that triggered the request; used
                to enforce the no-self-approval rule.
            binding_extra: Extra context folded into the binding fingerprint.
            channels: Notification channel names to record on the request.

        Returns:
            A ready-to-enqueue ticket in ``PENDING`` state.
        """
        now = utc_now()
        rule = quorum or DEFAULT_QUORUM.get(risk, QuorumRule())
        request = ApprovalRequest(
            call_id=call.id,
            decision_id=decision_id,
            session_id=call.session_id,
            agent_id=call.agent_id,
            tenant_id=call.tenant_id,
            tool=call.qualified_name if hasattr(call, "qualified_name") else call.tool,
            arguments_preview=preview_arguments(call.arguments),
            risk=risk,
            blast_radius=blast_radius,
            justification=justification,
            state=ApprovalState.PENDING,
            requested_at=now,
            expires_at=now + max(1, int(ttl_s)),
            required_roles=list(rule.required_roles),
            require_step_up=rule.require_step_up,
            channels=[str(c) for c in (channels or [])],
        )
        ticket = cls(
            request=request,
            binding=compute_binding(request.tool, call.arguments, extra=binding_extra),
            binding_extra=dict(binding_extra or {}),
            quorum=rule,
            requester_id=requester_id or call.agent_id,
            tool_arguments_hash=sha256_hex(canonical_json(dict(call.arguments or {}))),
        )
        ticket.record("created", detail={"risk": risk.value, "quorum": rule.describe()})
        return ticket

    # -- bookkeeping --------------------------------------------------------

    def record(self, event: str, *, actor: str = "system", detail: Optional[Mapping[str, Any]] = None) -> None:
        """Append an entry to the ticket's local history trail.

        Args:
            event: Short machine-readable event name.
            actor: Who caused it.
            detail: Optional structured context.
        """
        self.history.append(
            {
                "at": utc_now(),
                "event": event,
                "actor": actor,
                "state": self.request.state.value,
                "detail": dict(detail or {}),
            }
        )

    def approvals(self) -> List[ApprovalVote]:
        """Return only the approving votes."""
        return [v for v in self.votes if v.kind is VoteKind.APPROVE]

    def rejections(self) -> List[ApprovalVote]:
        """Return only the rejecting votes."""
        return [v for v in self.votes if v.kind is VoteKind.REJECT]

    def distinct_approver_ids(self) -> List[str]:
        """Return the unique principal ids that approved, order preserved."""
        seen: List[str] = []
        for vote in self.approvals():
            if vote.approver_id and vote.approver_id not in seen:
                seen.append(vote.approver_id)
        return seen

    def has_voted(self, approver_id: str) -> bool:
        """Whether ``approver_id`` already cast a decisive vote."""
        return any(v.approver_id == approver_id and v.kind.is_decisive for v in self.votes)

    def notify_on_escalation(self, extra_role: str) -> None:
        """Record that escalation added ``extra_role`` to the approver pool.

        Args:
            extra_role: The role newly granted voting rights, used when
                rendering escalation notifications so approvers know they have
                been roped in.
        """
        channel = f"escalate:{extra_role}"
        if channel not in self.notified_channels:
            self.notified_channels.append(channel)

    # -- quorum evaluation --------------------------------------------------

    def quorum_met(self) -> bool:
        """Whether the approving votes satisfy the configured quorum.

        Returns:
            ``True`` only when the count, distinctness, role coverage and
            step-up constraints all hold.  Any rejection with
            ``veto_on_any_reject`` immediately yields ``False``.
        """
        if self.quorum.veto_on_any_reject and self.rejections():
            return False
        approvals = self.approvals()
        if self.quorum.require_step_up and not all(v.step_up_verified for v in approvals):
            return False
        ids = self.distinct_approver_ids()
        count = len(ids) if self.quorum.require_distinct_principals else len(approvals)
        if count < self.quorum.min_approvals:
            return False
        if self.quorum.require_all_roles:
            covered = {role for vote in approvals for role in vote.approver_roles}
            if not set(self.quorum.required_roles).issubset(covered):
                return False
        return True

    def remaining_approvals(self) -> int:
        """How many more approving votes are still needed (never negative)."""
        have = len(self.distinct_approver_ids()) if self.quorum.require_distinct_principals else len(self.approvals())
        return max(0, self.quorum.min_approvals - have)

    def is_expired(self, now: Optional[float] = None) -> bool:
        """Whether the ticket has passed its TTL without a verdict."""
        return self.request.is_expired(now)

    # -- serialisation ------------------------------------------------------

    def summary(self) -> str:
        """Return a compact one-line description for logs and notifications."""
        return (
            f"[{self.id}] {self.request.tool} risk={self.risk.value} "
            f"state={self.state.value} {len(self.approvals())}/{self.quorum.min_approvals} "
            f"{truncate(self.request.justification, 60)}"
        ).strip()

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable representation of the whole ticket."""
        request = asdict(self.request)
        request["state"] = self.request.state.value
        request["risk"] = self.request.risk.value
        return {
            "request": request,
            "binding": self.binding,
            "binding_extra": dict(self.binding_extra),
            "quorum": asdict(self.quorum),
            "votes": [v.to_dict() for v in self.votes],
            "receipt": self.receipt.to_dict() if self.receipt else None,
            "requester_id": self.requester_id,
            "notified_channels": list(self.notified_channels),
            "escalated_at": list(self.escalated_at),
            "break_glass": self.break_glass,
            "break_glass_grant_id": self.break_glass_grant_id,
            "history": list(self.history),
            "tool_arguments_hash": self.tool_arguments_hash,
        }


@dataclass
class ApprovalOutcome:
    """The result handed back to the caller that is blocked on a ticket."""

    ticket_id: str = ""
    state: ApprovalState = ApprovalState.PENDING
    approved: bool = False
    receipt: Optional[ApprovalReceipt] = None
    reason: str = ""
    waited_ms: float = 0.0
    approvers: List[str] = field(default_factory=list)
    escalation_level: int = 0

    @property
    def token(self) -> str:
        """Redemption token, or an empty string when not approved."""
        return self.receipt.token() if self.receipt else ""

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable representation."""
        return {
            "ticket_id": self.ticket_id,
            "state": self.state.value,
            "approved": self.approved,
            "receipt": self.receipt.to_dict() if self.receipt else None,
            "reason": self.reason,
            "waited_ms": round(self.waited_ms, 2),
            "approvers": list(self.approvers),
            "escalation_level": self.escalation_level,
        }
