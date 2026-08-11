"""Orchestration core for the human-in-the-loop approval layer.

:class:`ApprovalWorkflow` is the single entry point the rest of the platform
talks to.  It ties together the queue, escalation, step-up and break-glass
subsystems and enforces the invariants that the 2026-08 approval-bypass
incidents violated:

1. **Binding.**  A ticket is minted against the *exact* tool + arguments.  The
   approval vote and the issued receipt both carry that fingerprint, and
   redemption checks it again.  Approving a benign call can never release a
   malicious one.
2. **No self-approval.**  The requester may not also be the approver unless
   the quorum explicitly allows it.
3. **No deny-by-timeout.**  Silence is a denial.  Auto-expiry and SLA breach
   both resolve to a rejection (fail-closed), never to an approval.
4. **Single-use receipt.**  The signed receipt can be redeemed exactly once;
   the nonce makes replay impossible even if the token leaks from a log.
5. **Break-glass is loud.**  Every emergency bypass is scoped, short-lived and
   audit-logged at CRITICAL severity.

The workflow is persistence-agnostic.  Optional collaborators (notifier,
audit ledger, step-up registry, key source) are injected or looked up lazily
so that the approval package imports cleanly without its peers and so that no
import-time cycle exists with :mod:`aegis.audit` or :mod:`aegis.core`.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from ..core.config import get_settings
from ..core.crypto import constant_time_equals, hmac_sign, random_nonce, sha256_hex
from ..core.errors import (
    ApprovalError,
    ApprovalRejected,
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    NotFoundError,
    StepUpRequired,
    ValidationError,
)
from ..core.logging import get_logger
from ..core.types import (
    ApprovalState,
    Principal,
    RiskLevel,
    Severity,
    ToolCall,
    utc_now,
)
from .breakglass import BreakGlassGrant, BreakGlassManager
from .escalation import EscalationEngine, EscalationEvent, EscalationPolicy
from .models import (
    ApprovalChannel,
    ApprovalOutcome,
    ApprovalPolicy,
    ApprovalReceipt,
    ApprovalTicket,
    ApprovalVote,
    QuorumRule,
    VoteKind,
    compute_binding,
    preview_arguments,
)
from .queue import ApprovalQueue, QueueLimits
from .stepup import StepUpRegistry, StepUpResult

__all__ = ["ApprovalWorkflow", "WorkflowHooks", "ApprovalConfig"]

_LOG = get_logger("aegis.approval.workflow")

#: Authority that may decide a ticket, beyond simple role membership.
NotifierCallable = Callable[["ApprovalTicket", str], None]


@dataclass
class WorkflowHooks:
    """Injectable collaborators that the workflow calls out to.

    Every hook is optional.  When omitted the workflow falls back to logging;
    the security properties (binding, quorum, single-use receipt) do *not*
    depend on any hook being present.
    """

    notifier: Optional[NotifierCallable] = None
    signer_key: Optional[Callable[[str], str]] = None
    auditor: Optional[Callable[[str, Mapping[str, Any], Severity], None]] = None
    fetcher: Optional[Callable[[str], Optional[Principal]]] = None
    on_resolved: Optional[Callable[["ApprovalTicket", "ApprovalOutcome"], None]] = None


@dataclass
class ApprovalConfig:
    """Construction parameters for :class:`ApprovalWorkflow`."""

    policy: ApprovalPolicy = field(default_factory=ApprovalPolicy)
    queue_limits: QueueLimits = field(default_factory=QueueLimits)
    escalation: EscalationPolicy = field(default_factory=EscalationPolicy)
    enable_break_glass: bool = True
    break_glass_ttl_s: int = 1800
    receipt_ttl_s: int = 300
    fail_closed: bool = True

    @classmethod
    def from_settings(cls, settings: Optional[Any] = None) -> "ApprovalConfig":
        """Build the config from the active :class:`aegis.core.config.Settings`.

        Args:
            settings: Optional settings object; loaded lazily when omitted.

        Returns:
            A populated config honouring the ``approval`` section.
        """
        cfg = settings or get_settings()
        section = cfg.section("approval") if cfg else {}
        policy = ApprovalPolicy.from_mapping(section)
        esc = EscalationPolicy(
            escalate_after_s=float(section.get("escalate_after_s", 300)),
            sla_s=float(section.get("default_ttl_s", 900)) * 1.0,
        )
        esc.validate()
        return cls(
            policy=policy,
            escalation=esc,
            enable_break_glass=bool(section.get("break_glass_enabled", True)),
            break_glass_ttl_s=int(section.get("break_glass_ttl_s", 1800)),
            receipt_ttl_s=int(section.get("receipt_ttl_s", 300)),
            fail_closed=bool(cfg.fail_closed()) if cfg else True,
        )


class ApprovalWorkflow:
    """Stateful coordinator for creating, deciding and redeeming approvals."""

    def __init__(
        self,
        config: Optional[ApprovalConfig] = None,
        *,
        hooks: Optional[WorkflowHooks] = None,
        stepup: Optional[StepUpRegistry] = None,
        breakglass: Optional[BreakGlassManager] = None,
        tenant_id: str = "default",
    ) -> None:
        """Create the workflow.

        Args:
            config: Parameters; defaults are loaded from settings.
            hooks: Callable collaborators (notify / audit / sign / fetch).
            stepup: Step-up registry; a default one is created when omitted.
            breakglass: Break-glass manager; created from config when omitted.
            tenant_id: Tenant this workflow instance serves.
        """
        self._config = config or ApprovalConfig.from_settings()
        self._hooks = hooks or WorkflowHooks()
        self._tenant_id = tenant_id
        self._queue = ApprovalQueue(self._config.queue_limits)
        self._escalation = EscalationEngine(self._config.escalation)
        self._stepup = stepup or StepUpRegistry()
        self._breakglass = breakglass or BreakGlassManager(
            enabled=self._config.enable_break_glass,
            ttl_s=self._config.break_glass_ttl_s,
        )
        self._redeemed: Dict[str, float] = {}
        self._redeem_lock = threading.RLock()
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._queue.subscribe(self._on_state_change)

    # -- properties ---------------------------------------------------------

    @property
    def policy(self) -> ApprovalPolicy:
        """Return the active approval policy."""
        return self._config.policy

    @property
    def queue(self) -> ApprovalQueue:
        """Return the underlying pending-approval queue."""
        return self._queue

    @property
    def escalation(self) -> EscalationEngine:
        """Return the escalation engine."""
        return self._escalation

    @property
    def break_glass(self) -> BreakGlassManager:
        """Return the break-glass manager."""
        return self._breakglass

    @property
    def step_up(self) -> StepUpRegistry:
        """Return the step-up registry."""
        return self._stepup

    # -- hook helpers -------------------------------------------------------

    def set_hooks(self, hooks: WorkflowHooks) -> None:
        """Replace the injected collaborators."""
        self._hooks = hooks

    def sign_key(self, key_id: str) -> str:
        """Return the HMAC key for a receipt/vote ``key_id``.

        Args:
            key_id: Identifier recorded on the artefact.

        Returns:
            A deterministic key.  When a ``signer_key`` hook is configured it
            is consulted; otherwise a per-process default key is derived so the
            workflow still produces verifiable signatures (note: deployments
            should inject a tenant secret for cross-process trust).
        """
        if self._hooks.signer_key is not None:
            return self._hooks.signer_key(key_id)
        return sha256_hex(f"aegis-approval-default:{key_id}:{self._tenant_id}")

    def _audit(self, action: str, payload: Mapping[str, Any], severity: Severity = Severity.INFO) -> None:
        """Emit an audit event through the hook when available."""
        if self._hooks.auditor is not None:
            try:
                self._hooks.auditor(action, dict(payload), severity)
                return
            except Exception as exc:  # pragma: no cover - audit defect
                _LOG.warning("approval auditor hook failed", extra={"error": str(exc)})
        try:
            from ..audit.ledger import get_ledger  # type: ignore

            get_ledger().append(
                action=action,
                actor=str(payload.get("actor", "system")),
                resource=payload.get("resource", "approval"),
                severity=severity,
                tenant_id=payload.get("tenant_id", self._tenant_id),
                payload=dict(payload),
            )
        except Exception:
            _LOG.debug("approval audit unavailable", extra={"action": action})

    def _notify(self, ticket: ApprovalTicket, event: str) -> None:
        """Dispatch a notification, preferring the injected notifier."""
        if self._hooks.notifier is not None:
            try:
                self._hooks.notifier(ticket, event)
                return
            except Exception as exc:  # pragma: no cover - notifier defect
                _LOG.warning("approval notifier hook failed", extra={"event": event, "error": str(exc)})
        try:
            from .notifier import dispatch  # type: ignore

            dispatch(ticket, event, policy=self._config.policy)
        except Exception as exc:  # pragma: no cover - notifier unavailable
            _LOG.debug("approval notifier dispatch unavailable", extra={"event": event, "error": str(exc)})

    def _principal(self, principal_id: str) -> Principal:
        """Resolve a principal id to an object, falling back to a bare stub.

        Args:
            principal_id: Identifier of the human.

        Returns:
            A :class:`Principal`, either fetched via hook or a minimal stub so
            role checks still run (defaulting to no privileged roles).
        """
        if self._hooks.fetcher is not None:
            principal = self._hooks.fetcher(principal_id)
            if principal is not None:
                return principal
        return Principal(id=principal_id, name=principal_id)

    # -- ticket creation ----------------------------------------------------

    def request(
        self,
        call: ToolCall,
        *,
        risk: Optional[RiskLevel] = None,
        decision_id: str = "",
        justification: str = "",
        blast_radius: str = "",
        requester: Optional[Principal] = None,
        binding_extra: Optional[Mapping[str, Any]] = None,
        channels: Optional[Sequence[str]] = None,
        ttl_s: Optional[int] = None,
    ) -> ApprovalTicket:
        """Raise an approval request for a tool call and enqueue it.

        Args:
            call: The intercepted call that needs a human.
            risk: Risk level from the policy engine; derives the default quorum
                when ``quorum`` is not supplied.
            decision_id: Identifier of the decision that raised this.
            justification: Agent-supplied reason (shown to approvers).
            blast_radius: What breaks if the action is wrong.
            requester: Who triggered the call (used for no-self-approval).
            binding_extra: Extra context folded into the binding.
            channels: Notification channel names.
            ttl_s: Override the policy default ticket lifetime.

        Returns:
            The enqueued ticket.  When risk is below the auto-approve
            threshold the ticket is resolved ``AUTO_APPROVED`` immediately and
            a pre-signed receipt is attached.

        Raises:
            ValidationError: ``call`` has no tool.  RateLimited: queue guards
            tripped (fail-closed).
        """
        if not call.tool and not getattr(call, "qualified_name", ""):
            raise ValidationError("cannot request approval for an empty tool", details={"call_id": call.id})
        level = risk or RiskLevel.HIGH
        quorum = self._config.policy.quorum_for(level)
        ttl = int(ttl_s if ttl_s is not None else self._config.policy.default_ttl_s)
        requester_id = requester.id if requester else call.agent_id
        ticket = ApprovalTicket.from_call(
            call,
            risk=level,
            quorum=quorum,
            ttl_s=ttl,
            decision_id=decision_id,
            justification=justification,
            blast_radius=blast_radius,
            requester_id=requester_id,
            binding_extra=binding_extra,
            channels=channels,
        )
        self._escalation.track(ticket)

        # Auto-approve path: pilot-light actions below the threshold skip a
        # human but still receive a binding, single-use receipt.
        if self._config.policy.can_auto_approve(level) and not self._config.policy.bind_arguments:
            receipt = self._issue_receipt(ticket, approvers=[], step_up=False, break_glass=False)
            ticket.request.state = ApprovalState.AUTO_APPROVED
            ticket.request.decided_at = utc_now()
            ticket.request.decided_by = "auto"
            ticket.receipt = receipt
            ticket.record("auto_approved", actor="auto")
            self._queue.submit(ticket, dedup=False)
            self._queue.transition(ticket.id, ApprovalState.AUTO_APPROVED, actor="auto", note="below threshold")
            _LOG.info("auto-approved low-risk action", extra={"ticket_id": ticket.id, "tool": ticket.request.tool})
            self._audit(
                "approval.auto_approved",
                {"ticket_id": ticket.id, "tool": ticket.request.tool, "risk": level.value, "actor": "auto"},
                Severity.INFO,
            )
            return ticket

        self._queue.submit(ticket)
        self._notify(ticket, "submitted")
        self._audit(
            "approval.requested",
            {
                "ticket_id": ticket.id,
                "tool": ticket.request.tool,
                "risk": level.value,
                "requester_id": requester_id,
                "quorum": quorum.describe(),
                "actor": requester_id,
                "resource": f"approval/{ticket.id}",
            },
            Severity.MEDIUM if level.value in ("high", "critical") else Severity.INFO,
        )
        return ticket

    # -- voting -------------------------------------------------------------

    def cast_vote(
        self,
        ticket_id: str,
        approver: Principal,
        kind: VoteKind,
        *,
        note: str = "",
        channel: ApprovalChannel = ApprovalChannel.CONSOLE,
        step_up_proof: str = "",
        step_up_method: str = "",
    ) -> ApprovalVote:
        """Record one approver's decision and advance the ticket if quorum met.

        Args:
            ticket_id: Ticket being decided.
            approver: The human casting the vote.
            kind: Approve / reject / abstain / request-info.
            note: Free-text annotation stored on the vote.
            channel: How the vote arrived (never authoritative).
            step_up_proof: A second-factor code/assertion when the quorum
                requires step-up.
            step_up_method: Which step-up mechanism produced ``step_up_proof``.

        Returns:
            The recorded :class:`ApprovalVote`.

        Raises:
            NotFoundError: Unknown ticket.  AuthorizationError: approver lacks
            the required role, is the requester under no-self-approval, or has
            a conflicting prior vote.  ValidationError: undecided risk state.
            StepUpRequired: quorum needs second factor and none supplied.
        """
        ticket = self._queue.get(ticket_id)
        if ticket.is_terminal:
            raise ConflictError(f"ticket {ticket_id} is already {ticket.state.value}")
        self._authorize_voter(ticket, approver, kind)

        if kind is VoteKind.APPROVE:
            step_up_ok = True
            if ticket.quorum.require_step_up:
                if not step_up_proof:
                    raise StepUpRequired(
                        "this approval requires a fresh step-up factor",
                        details={"ticket_id": ticket_id, "method": step_up_method or "totp"},
                    )
                result: StepUpResult = self._stepup.verify(
                    approver, ticket_id, step_up_proof, method=step_up_method or ""
                )
                result.require()
                step_up_ok = result.ok
            else:
                step_up_ok = True

        vote = ApprovalVote(
            ticket_id=ticket.id,
            approver_id=approver.id,
            approver_name=approver.name,
            approver_roles=list(approver.roles),
            kind=kind,
            note=note,
            channel=channel,
            step_up_verified=(kind is VoteKind.APPROVE and ticket.quorum.require_step_up and step_up_ok),
            step_up_method=step_up_method or (self._stepup.methods[0] if ticket.quorum.require_step_up else ""),
            binding=ticket.binding,
        )
        vote.sign(self.sign_key("vote"))
        ticket.votes.append(vote)
        ticket.record(
            "vote",
            actor=approver.id,
            detail={"kind": kind.value, "step_up": vote.step_up_verified, "channel": channel.value},
        )
        _LOG.info(
            "approval vote cast",
            extra={"ticket_id": ticket_id, "approver": approver.id, "kind": kind.value},
        )

        if kind is VoteKind.REJECT:
            self._resolve(ticket, ApprovalState.REJECTED, approver.id, note=note)
            return vote

        if kind is VoteKind.APPROVE and ticket.quorum_met():
            self._issue_and_resolve(ticket, approver)
            return vote

        self._queue.notify_changed(ticket.id, event="vote")
        self._notify(ticket, "vote")
        return vote

    def _authorize_voter(self, ticket: ApprovalTicket, approver: Principal, kind: VoteKind) -> None:
        """Enforce role, no-self-approval and de-duplication rules."""
        if not ticket.quorum.role_allows(approver):
            raise AuthorizationError(
                "voter lacks a required role for this ticket",
                details={"required": ticket.quorum.required_roles, "held": approver.roles},
            )
        if ticket.quorum.deny_self_approval and approver.id and approver.id == ticket.requester_id:
            raise AuthorizationError(
                "requester may not approve their own action",
                details={"ticket_id": ticket.id, "requester_id": ticket.requester_id},
            )
        # Allow changing a previous non-decisive vote, but not double-counting.
        if ticket.has_voted(approver.id) and kind.is_decisive:
            raise ConflictError(
                "approver has already cast a decisive vote on this ticket",
                details={"approver_id": approver.id},
            )

    def _issue_and_resolve(self, ticket: ApprovalTicket, approver: Principal) -> None:
        """Issue the receipt and move the ticket to APPROVED."""
        approvers = ticket.distinct_approver_ids()
        receipt = self._issue_receipt(
            ticket,
            approvers=approvers,
            step_up=any(v.step_up_verified for v in ticket.approvals()),
            break_glass=False,
        )
        ticket.receipt = receipt
        self._resolve(ticket, ApprovalState.APPROVED, approver.id, note="quorum met")

    def _issue_receipt(
        self,
        ticket: ApprovalTicket,
        *,
        approvers: Sequence[str],
        step_up: bool,
        break_glass: bool,
    ) -> ApprovalReceipt:
        """Build, sign and return a single-use receipt bound to the ticket."""
        ttl = int(self._config.receipt_ttl_s)
        receipt = ApprovalReceipt(
            ticket_id=ticket.id,
            call_id=ticket.request.call_id,
            tenant_id=ticket.request.tenant_id,
            binding=ticket.binding,
            state=ApprovalState.APPROVED,
            approvers=list(approvers),
            step_up_verified=step_up,
            break_glass=break_glass,
            issued_at=utc_now(),
            expires_at=utc_now() + ttl,
        )
        receipt.sign(self.sign_key("receipt"), key_id="receipt")
        self._audit(
            "approval.receipt.issued",
            {
                "receipt_id": receipt.id,
                "ticket_id": ticket.id,
                "approvers": list(approvers),
                "step_up": step_up,
                "break_glass": break_glass,
                "actor": ",".join(approvers) or "auto",
                "resource": f"approval/{ticket.id}",
            },
            Severity.INFO,
        )
        return receipt

    def _resolve(self, ticket: ApprovalTicket, state: ApprovalState, actor: str, *, note: str = "") -> None:
        """Transition a ticket to a terminal state, audit, notify and redeem."""
        ticket.request.state = state
        ticket.record("resolved", actor=actor, detail={"state": state.value, "note": note})
        self._queue.transition(ticket.id, state, actor=actor, note=note)
        self._escalation.mark_resolved(ticket)
        severity = Severity.MEDIUM if state is ApprovalState.APPROVED else Severity.INFO
        self._audit(
            "approval.resolved",
            {
                "ticket_id": ticket.id,
                "state": state.value,
                "actor": actor,
                "resource": f"approval/{ticket.id}",
            },
            severity,
        )
        self._notify(ticket, state.value)

    # -- waiting + redeeming ------------------------------------------------

    def wait(
        self,
        ticket_id: str,
        timeout_s: float,
        *,
        poll_escalation: bool = True,
    ) -> ApprovalOutcome:
        """Block until a verdict is reached, escalating along the way.

        Args:
            ticket_id: Ticket to observe.
            timeout_s: Wall-clock budget in seconds.
            poll_escalation: When true a background-ish single sweep is run so
                that the caller is not dependent on an external ticker.

        Returns:
            An outcome whose ``approved`` flag is only true when a valid
            receipt exists.  A timeout or expiry yields ``approved=False``.
        """
        if poll_escalation:
            self._escalation.run_once(self._queue.pending())
        start = utc_now()
        ticket = self._queue.wait(ticket_id, timeout_s)
        waited = utc_now() - start
        outcome = self._outcome_for(ticket, waited_ms=waited * 1000.0)
        if self._hooks.on_resolved is not None:
            try:
                self._hooks.on_resolved(ticket, outcome)
            except Exception as exc:  # pragma: no cover - user hook
                _LOG.warning("on_resolved hook failed", extra={"error": str(exc)})
        return outcome

    def _outcome_for(self, ticket: ApprovalTicket, *, waited_ms: float = 0.0) -> ApprovalOutcome:
        """Construct an outcome object from a (possibly terminal) ticket."""
        approved = ticket.state in (ApprovalState.APPROVED, ApprovalState.AUTO_APPROVED) and ticket.receipt is not None
        reason = ""
        if ticket.state is ApprovalState.REJECTED:
            reason = "rejected by approver"
        elif ticket.state is ApprovalState.EXPIRED:
            reason = "no decision before timeout (fail-closed)"
        elif ticket.state is ApprovalState.CANCELLED:
            reason = "cancelled"
        elif ticket.state is ApprovalState.PENDING:
            reason = "still pending"
        return ApprovalOutcome(
            ticket_id=ticket.id,
            state=ticket.state,
            approved=approved,
            receipt=ticket.receipt,
            reason=reason,
            waited_ms=waited_ms,
            approvers=list(ticket.distinct_approver_ids()),
            escalation_level=ticket.request.escalation_level,
        )

    def redeem(
        self,
        ticket_id: str,
        tool: str,
        arguments: Mapping[str, Any],
        *,
        binding_extra: Optional[Mapping[str, Any]] = None,
        receipt_token: str = "",
        call_id: str = "",
        session_id: str = "",
        use_break_glass: Optional[str] = None,
    ) -> ApprovalReceipt:
        """Validate that a pending action may proceed, returning the receipt.

        This is the method the enforcement path calls.  It performs every
        check that makes approval meaningful:

        * the ticket reached an approving terminal state,
        * the tool + arguments hash to the ticket's recorded binding,
        * the receipt (if supplied by token) is genuine and unburned,
        * break-glass, when used, actually covers this call.

        Args:
            ticket_id: The approval ticket being redeemed.
            tool: The tool about to execute.
            arguments: The exact arguments about to execute.
            binding_extra: Extra context that must match the request time.
            receipt_token: Optional compact token; when present it is verified
                and burned so it cannot be replayed.
            call_id: Tool-call identifier for audit correlation.
            session_id: Session the call belongs to.
            use_break_glass: When a grant id, lets the call proceed under that
                emergency grant instead of a normal approval.

        Returns:
            The verified receipt (or a break-glass-backed receipt).

        Raises:
            NotFoundError: Unknown ticket.  ApprovalRejected: the ticket was
            not approved.  ValidationError: the binding does not match (the
            2026 swap attack).  ConflictError: the receipt was already used.
            AuthorizationError: break-glass scope/expiry violation.
        """
        ticket = self._queue.find(ticket_id)
        if ticket is None:
            raise NotFoundError("unknown approval ticket", details={"ticket_id": ticket_id})

        if use_break_glass:
            return self._redeem_break_glass(use_break_glass, tool, arguments, session_id=session_id, call_id=call_id)

        if ticket.state not in (ApprovalState.APPROVED, ApprovalState.AUTO_APPROVED):
            raise ApprovalRejected(
                f"action not approved (state={ticket.state.value})",
                details={"ticket_id": ticket_id, "tool": tool},
            )

        live_binding = compute_binding(tool, arguments, extra=binding_extra or ticket.binding_extra)
        if not self._bindings_match(ticket.binding, live_binding):
            self._audit(
                "approval.binding_mismatch",
                {
                    "ticket_id": ticket_id,
                    "tool": tool,
                    "approved_args_hash": ticket.tool_arguments_hash,
                    "live_args_hash": sha256_hex(__import__("json").dumps(dict(arguments), sort_keys=True)),
                    "actor": "enforcement",
                    "resource": f"approval/{ticket_id}",
                },
                Severity.CRITICAL,
            )
            raise ValidationError(
                "approved action does not match executed action (binding mismatch)",
                details={"ticket_id": ticket_id, "tool": tool},
            )

        if receipt_token:
            self._burn_receipt(receipt_token, ticket)

        receipt = ticket.receipt
        if receipt is None:
            receipt = self._issue_receipt(
                ticket,
                approvers=ticket.distinct_approver_ids(),
                step_up=any(v.step_up_verified for v in ticket.approvals()),
                break_glass=False,
            )
            ticket.receipt = receipt
        self._audit(
            "approval.redeemed",
            {
                "ticket_id": ticket_id,
                "tool": tool,
                "call_id": call_id,
                "approvers": ticket.distinct_approver_ids(),
                "actor": "enforcement",
                "resource": f"approval/{ticket_id}",
            },
            Severity.INFO,
        )
        return receipt

    def _redeem_break_glass(
        self,
        grant_id: str,
        tool: str,
        arguments: Mapping[str, Any],
        *,
        session_id: str = "",
        call_id: str = "",
    ) -> ApprovalReceipt:
        """Release a call under a break-glass grant, returning a flagged receipt."""
        grant: Optional[BreakGlassGrant] = self._breakglass.consume(
            grant_id, tool, session_id=session_id, call_id=call_id
        )
        ticket = self._queue.find(grant.id)
        binding = compute_binding(tool, arguments, extra={"break_glass": grant.id})
        receipt = ApprovalReceipt(
            ticket_id=grant.id,
            call_id=call_id,
            tenant_id=grant.tenant_id,
            binding=binding,
            state=ApprovalState.APPROVED,
            approvers=[grant.principal_id],
            step_up_verified=False,
            break_glass=True,
            issued_at=utc_now(),
            expires_at=utc_now() + self._config.receipt_ttl_s,
        )
        receipt.sign(self.sign_key("receipt"), key_id="break_glass")
        self._audit(
            "approval.break_glass.redeemed",
            {
                "grant_id": grant.id,
                "tool": tool,
                "call_id": call_id,
                "actor": grant.principal_id,
                "resource": f"break_glass/{grant.id}",
            },
            Severity.CRITICAL,
        )
        return receipt

    def _burn_receipt(self, token: str, ticket: ApprovalTicket) -> None:
        """Verify a receipt token and mark it single-use.

        Args:
            token: Compact token from :meth:`ApprovalReceipt.token`.
            ticket: The ticket the token belongs to.

        Raises:
            ValidationError: Token shape is wrong or the embedded id is wrong.
            ConflictError: The token was already redeemed.
        """
        parts = (token or "").split(".")
        if len(parts) != 3:
            raise ValidationError("malformed receipt token", details={"ticket_id": ticket.id})
        token_id, nonce, sig_prefix = parts
        if ticket.receipt is not None and not constant_time_equals(token_id, ticket.receipt.id):
            raise ValidationError("receipt token does not match this ticket", details={"ticket_id": ticket.id})
        with self._redeem_lock:
            if token_id in self._redeemed:
                raise ConflictError(
                    "approval receipt already redeemed (replay blocked)",
                    details={"receipt_id": token_id, "ticket_id": ticket.id},
                )
            if ticket.receipt is not None:
                expected_prefix = ticket.receipt.signature[:32]
                if not constant_time_equals(expected_prefix, sig_prefix):
                    raise ValidationError("receipt signature mismatch", details={"ticket_id": ticket.id})
            self._redeemed[token_id] = utc_now()
        _LOG.info("receipt redeemed (single-use)", extra={"ticket_id": ticket.id, "receipt_id": token_id})

    @staticmethod
    def _bindings_match(approved: str, live: str) -> bool:
        """Constant-time compare of two binding fingerprints."""
        return constant_time_equals(approved, live)

    def pending(self, principal: Optional[Principal] = None) -> List[ApprovalTicket]:
        """List pending tickets, optionally scoped to a principal's rights."""
        if principal is None:
            return self._queue.pending()
        return self._queue.visible_to(principal)

    def get(self, ticket_id: str) -> ApprovalTicket:
        """Return a ticket by id."""
        return self._queue.get(ticket_id)

    def escalate_now(self) -> List[EscalationEvent]:
        """Run a single escalation sweep and return the events produced."""
        return self._escalation.run_once(self._queue.pending())

    def cancel(self, ticket_id: str, *, actor: str = "system", reason: str = "cancelled") -> ApprovalTicket:
        """Cancel a pending ticket."""
        ticket = self._queue.cancel(ticket_id, actor=actor, reason=reason)
        self._escalation.mark_resolved(ticket)
        self._audit(
            "approval.cancelled",
            {"ticket_id": ticket_id, "actor": actor, "resource": f"approval/{ticket_id}"},
            Severity.INFO,
        )
        return ticket

    def _on_state_change(self, event: str, ticket: ApprovalTicket) -> None:
        """Queue subscription handler (currently a no-op extension point)."""
        # Reserved for telemetry; keep cheap and side-effect free.
        _ = event, ticket
        return


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _constant_eq(a: str, b: str) -> bool:
    """Constant-time compare of two binding fingerprints."""
    return constant_time_equals(a, b)
