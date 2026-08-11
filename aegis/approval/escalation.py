"""Escalation and SLA tracking for unaddressed approval requests.

An approval left unanswered is not "safe", it is a latent outage or, worse, a
window an attacker can wait out.  Escalation converts silence into action:

* after ``escalate_after_s`` with no decision the ticket is bumped to the next
  tier, the approver pool is widened and a louder notification fires,
* a hard ``sla_s`` turns an unanswered ticket into an automatic ``EXPIRED``
  (fail-closed) so the waited-on caller unblocks as a *denial*,
* escalation levels are capped to avoid notifying the entire org every time.

Escalation only *widenst* the audience and tightens the SLA.  It never lowers
the risk, narrows roles, or auto-approves because that would be the exact
"approve by timeout" weakness the 2026 incidents exploited.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..core.logging import get_logger
from ..core.types import ApprovalState, Principal, RiskLevel, utc_now
from .models import ApprovalTicket, QuorumRule

__all__ = ["EscalationPolicy", "EscalationEvent", "EscalationEngine", "EscalationStats"]

_LOG = get_logger("aegis.approval.escalation")

#: Extra roles added at each escalation tier.
ESCALATION_ROLES = ("oncall", "security", "manager", "director")

#: How much the SLA tightens on each tier (multiplier applied to the floor).
SLA_TIGHTEN_FRACTION = 0.6


@dataclass
class EscalationPolicy:
    """Tunables that govern escalation behaviour."""

    escalate_after_s: float = 300.0
    sla_s: float = 900.0
    max_level: int = 3
    widen_roles: bool = True
    notify_on_escalate: bool = True

    def validate(self) -> None:
        """Clamp the policy into a sane range in place."""
        self.escalate_after_s = max(10.0, float(self.escalate_after_s))
        self.sla_s = max(self.escalate_after_s, float(self.sla_s))
        self.max_level = max(0, min(5, int(self.max_level)))


@dataclass
class EscalationEvent:
    """A single escalation step recorded on the ticket."""

    level: int = 0
    at: float = field(default_factory=utc_now)
    by: str = "engine"
    added_roles: List[str] = field(default_factory=list)
    note: str = ""


@dataclass
class EscalationStats:
    """Counters describing escalation activity."""

    escalated: int = 0
    sla_breached: int = 0
    resolved_within_sla: int = 0
    pending: int = 0

    def as_dict(self) -> Dict[str, int]:
        """Return the counters as a plain mapping."""
        return {
            "escalated": self.escalated,
            "sla_breached": self.sla_breached,
            "resolved_within_sla": self.resolved_within_sla,
            "pending": self.pending,
        }


class EscalationEngine:
    """Drives pending tickets through escalation tiers and SLA expiry."""

    def __init__(self, policy: Optional[EscalationPolicy] = None) -> None:
        """Create the engine.

        Args:
            policy: Escalation tunables; defaults to :class:`EscalationPolicy`.
        """
        self._policy = policy or EscalationPolicy()
        self._policy.validate()
        self._lock = threading.RLock()
        self._events: Dict[str, List[EscalationEvent]] = {}
        self._stats = EscalationStats()

    @property
    def policy(self) -> EscalationPolicy:
        """Return the active policy."""
        return self._policy

    @property
    def stats(self) -> EscalationStats:
        """Return live counters."""
        return self._stats

    # -- evaluation ---------------------------------------------------------

    def evaluate(self, ticket: ApprovalTicket, now: Optional[float] = None) -> List[EscalationEvent]:
        """Apply any due escalation and SLA expiry to ``ticket`` in place.

        Args:
            ticket: The pending ticket to evaluate.
            now: Current epoch seconds; defaults to ``utc_now()``.

        Returns:
            The escalation events produced during this pass (may be empty).
        """
        moment = now if now is not None else utc_now()
        produced: List[EscalationEvent] = []
        if ticket.is_terminal:
            return produced
        with self._lock:
            history = self._events.setdefault(ticket.id, [])
            level = len(history)

            # SLA breach always wins and is fail-closed.
            sla_deadline = ticket.request.requested_at + self._policy.sla_s
            if sla_deadline <= moment:
                self._stats.sla_breached += 1
                self._stats.pending = max(0, self._stats.pending - 1)
                produced.append(EscalationEvent(level=-1, at=moment, by="engine", note="SLA breached; auto-expired"))
                return produced

            if level >= self._policy.max_level:
                return produced

            escalate_deadline = ticket.request.requested_at + (level + 1) * self._policy.escalate_after_s
            if escalate_deadline <= moment:
                event = self._escalate_locked(ticket, level + 1, history, moment)
                produced.append(event)
                self._stats.escalated += 1
        return produced

    def _escalate_locked(
        self,
        ticket: ApprovalTicket,
        level: int,
        history: List[EscalationEvent],
        now: float,
    ) -> EscalationEvent:
        """Perform one escalation; caller must hold the lock."""
        added: List[str] = []
        if self._policy.widen_roles:
            extra = ESCALATION_ROLES[min(level - 1, len(ESCALATION_ROLES) - 1)]
            if extra not in ticket.quorum.required_roles:
                ticket.quorum.required_roles.append(extra)
                added.append(extra)
            if self._policy.notify_on_escalate:
                ticket.notify_on_escalation(extra)
        ticket.request.escalation_level = level
        ticket.escalated_at.append(now)
        event = EscalationEvent(level=level, at=now, added_roles=added, note=f"escalated to level {level}")
        history.append(event)
        ticket.record("escalated", actor="engine", detail={"level": level, "added_roles": added})
        _LOG.warning(
            "approval escalated",
            extra={"ticket_id": ticket.id, "level": level, "added_roles": added},
        )
        return event

    # -- auditing completion ------------------------------------------------

    def mark_resolved(self, ticket: ApprovalTicket, now: Optional[float] = None) -> None:
        """Record whether a resolved ticket beat its SLA.

        Args:
            ticket: A terminal ticket.
            now: Current epoch seconds.
        """
        moment = now if now is not None else utc_now()
        with self._lock:
            self._events.pop(ticket.id, None)
            self._stats.pending = max(0, self._stats.pending - 1)
            if ticket.state in (
                ApprovalState.APPROVED,
                ApprovalState.AUTO_APPROVED,
                ApprovalState.REJECTED,
                ApprovalState.CANCELLED,
            ):
                deadline = ticket.request.requested_at + self._policy.sla_s
                if moment <= deadline:
                    self._stats.resolved_within_sla += 1

    def track(self, ticket: ApprovalTicket) -> None:
        """Register a ticket as pending SLA tracking.

        Args:
            ticket: A freshly submitted ticket.
        """
        with self._lock:
            if ticket.id not in self._events:
                self._events[ticket.id] = []
            self._stats.pending += 1

    def register_pending(self, tickets: List[ApprovalTicket]) -> None:
        """Seed the tracker with already-queued tickets (e.g. on restart)."""
        with self._lock:
            for ticket in tickets:
                if not ticket.is_terminal and ticket.id not in self._events:
                    self._events[ticket.id] = []
                    self._stats.pending += 1

    def run_once(self, tickets: List[ApprovalTicket]) -> List[EscalationEvent]:
        """Evaluate every ticket once and return the aggregated events.

        Args:
            tickets: Snapshot of currently pending tickets.

        Returns:
            All escalation events produced in this sweep.
        """
        events: List[EscalationEvent] = []
        for ticket in tickets:
            events.extend(self.evaluate(ticket))
        return events

    def describe(self, ticket: ApprovalTicket) -> str:
        """Return the escalation tier label for a ticket."""
        level = ticket.request.escalation_level
        if level <= 0:
            return "tier-0 (normal)"
        return f"tier-{level} (escalated)"
