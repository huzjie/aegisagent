"""Thread-safe pending-approval queue with dedup, TTL reaping and waiters.

Beyond simple bookkeeping this queue implements two anti-abuse controls that
matter in agent deployments:

*Consent fatigue defence*
    An agent stuck in a retry loop can emit hundreds of identical approval
    requests until an approver clicks "yes" out of exhaustion.  Requests with
    an identical binding fingerprint collapse onto the *same* ticket inside a
    dedup window, and a per-session flood limit rejects the rest.

*Fail-closed expiry*
    Tickets that reach their TTL move to ``EXPIRED`` and any thread blocked on
    them is released with a negative outcome.  A queue that silently keeps
    waiting is a queue that eventually gets bypassed by a timeout handler.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from ..core.errors import ConflictError, NotFoundError, RateLimited
from ..core.logging import get_logger
from ..core.types import ApprovalState, Principal, RiskLevel, utc_now
from .models import ApprovalTicket

__all__ = ["ApprovalQueue", "QueueStats", "QueueLimits"]

_LOG = get_logger("aegis.approval.queue")


@dataclass
class QueueLimits:
    """Guard rails that keep the queue bounded under adversarial load."""

    max_pending: int = 500
    max_pending_per_session: int = 20
    dedup_window_s: float = 60.0
    max_history: int = 2000

    def validate(self) -> None:
        """Clamp nonsensical values into a safe range in place."""
        self.max_pending = max(1, int(self.max_pending))
        self.max_pending_per_session = max(1, int(self.max_pending_per_session))
        self.dedup_window_s = max(0.0, float(self.dedup_window_s))
        self.max_history = max(0, int(self.max_history))


@dataclass
class QueueStats:
    """Counters describing queue activity since process start."""

    submitted: int = 0
    deduplicated: int = 0
    rejected_flood: int = 0
    expired: int = 0
    resolved: int = 0
    cancelled: int = 0
    peak_pending: int = 0

    def as_dict(self) -> Dict[str, int]:
        """Return the counters as a plain mapping."""
        return {
            "submitted": self.submitted,
            "deduplicated": self.deduplicated,
            "rejected_flood": self.rejected_flood,
            "expired": self.expired,
            "resolved": self.resolved,
            "cancelled": self.cancelled,
            "peak_pending": self.peak_pending,
        }


class ApprovalQueue:
    """In-memory registry of live approval tickets.

    All public methods are safe to call from multiple threads.  Waiters use a
    single :class:`threading.Condition` so that a state change wakes exactly
    the threads that care, without busy polling.
    """

    def __init__(self, limits: Optional[QueueLimits] = None) -> None:
        """Create an empty queue.

        Args:
            limits: Optional bounds; defaults to :class:`QueueLimits`.
        """
        self._limits = limits or QueueLimits()
        self._limits.validate()
        self._cond = threading.Condition(threading.RLock())
        self._tickets: Dict[str, ApprovalTicket] = {}
        self._by_binding: Dict[str, Tuple[str, float]] = {}
        self._history: List[str] = []
        self._listeners: List[Callable[[str, ApprovalTicket], None]] = []
        self._stats = QueueStats()

    # -- introspection ------------------------------------------------------

    @property
    def stats(self) -> QueueStats:
        """Return the live statistics object."""
        return self._stats

    def __len__(self) -> int:
        """Return the number of tickets currently tracked."""
        with self._cond:
            return len(self._tickets)

    def subscribe(self, callback: Callable[[str, ApprovalTicket], None]) -> None:
        """Register a listener invoked on every state transition.

        Args:
            callback: Receives ``(event_name, ticket)``.  Exceptions raised by
                listeners are logged and swallowed so that one bad notifier
                cannot stall the approval path.
        """
        with self._cond:
            self._listeners.append(callback)

    def _emit(self, event: str, ticket: ApprovalTicket) -> None:
        """Fan out ``event`` to listeners, isolating failures."""
        for callback in list(self._listeners):
            try:
                callback(event, ticket)
            except Exception as exc:  # pragma: no cover - listener defect
                _LOG.warning("approval queue listener failed", extra={"event": event, "error": str(exc)})

    # -- submission ---------------------------------------------------------

    def submit(self, ticket: ApprovalTicket, *, dedup: bool = True) -> ApprovalTicket:
        """Add ``ticket`` to the queue, or return an equivalent live ticket.

        Args:
            ticket: A freshly created ticket in ``PENDING`` state.
            dedup: When true, an identical binding submitted inside the dedup
                window returns the existing ticket instead of creating a new
                one.

        Returns:
            The ticket that callers should wait on.  May be a pre-existing
            ticket when deduplication kicked in.

        Raises:
            ConflictError: The ticket id is already present.
            RateLimited: Global or per-session pending capacity is exhausted.
        """
        now = utc_now()
        with self._cond:
            self._reap_locked(now)
            if ticket.id in self._tickets:
                raise ConflictError(f"approval ticket already queued: {ticket.id}")
            if dedup and self._limits.dedup_window_s > 0 and ticket.binding:
                existing = self._dedup_lookup_locked(ticket.binding, now)
                if existing is not None:
                    self._stats.deduplicated += 1
                    existing.record("deduplicated", detail={"collapsed_id": ticket.id})
                    _LOG.info(
                        "collapsed duplicate approval request",
                        extra={"ticket_id": existing.id, "duplicate_of": ticket.id},
                    )
                    return existing
            pending = self._pending_locked()
            if len(pending) >= self._limits.max_pending:
                self._stats.rejected_flood += 1
                raise RateLimited(
                    "approval queue is full; refusing new requests (fail-closed)",
                    retry_after=30,
                )
            session = ticket.request.session_id
            if session:
                same_session = sum(1 for t in pending if t.request.session_id == session)
                if same_session >= self._limits.max_pending_per_session:
                    self._stats.rejected_flood += 1
                    raise RateLimited(
                        f"session {session} exceeded pending approval limit "
                        f"({self._limits.max_pending_per_session}); possible consent-fatigue attack",
                        retry_after=60,
                    )
            self._tickets[ticket.id] = ticket
            if ticket.binding:
                self._by_binding[ticket.binding] = (ticket.id, now)
            self._stats.submitted += 1
            self._stats.peak_pending = max(self._stats.peak_pending, len(self._pending_locked()))
            self._cond.notify_all()
        _LOG.info("approval requested", extra={"ticket_id": ticket.id, "tool": ticket.request.tool})
        self._emit("submitted", ticket)
        return ticket

    def _dedup_lookup_locked(self, binding: str, now: float) -> Optional[ApprovalTicket]:
        """Return a live ticket sharing ``binding`` inside the dedup window."""
        entry = self._by_binding.get(binding)
        if entry is None:
            return None
        ticket_id, created = entry
        if now - created > self._limits.dedup_window_s:
            self._by_binding.pop(binding, None)
            return None
        existing = self._tickets.get(ticket_id)
        if existing is None or existing.is_terminal or existing.is_expired(now):
            self._by_binding.pop(binding, None)
            return None
        return existing

    # -- lookup -------------------------------------------------------------

    def get(self, ticket_id: str) -> ApprovalTicket:
        """Return the ticket with ``ticket_id``.

        Args:
            ticket_id: Identifier issued at submission time.

        Returns:
            The live ticket object.

        Raises:
            NotFoundError: No such ticket is tracked.
        """
        with self._cond:
            ticket = self._tickets.get(ticket_id)
        if ticket is None:
            raise NotFoundError(f"unknown approval ticket: {ticket_id}", details={"resource": "approval"})
        return ticket

    def find(self, ticket_id: str) -> Optional[ApprovalTicket]:
        """Return the ticket or ``None`` when it is unknown."""
        with self._cond:
            return self._tickets.get(ticket_id)

    def _pending_locked(self) -> List[ApprovalTicket]:
        """Return non-terminal tickets; caller must hold the lock."""
        return [t for t in self._tickets.values() if not t.is_terminal]

    def pending(
        self,
        *,
        tenant_id: Optional[str] = None,
        session_id: Optional[str] = None,
        min_risk: Optional[RiskLevel] = None,
    ) -> List[ApprovalTicket]:
        """List live tickets, newest first, filtered by the given criteria.

        Args:
            tenant_id: Restrict to one tenant.
            session_id: Restrict to one agent session.
            min_risk: Only include tickets at or above this risk level.

        Returns:
            A snapshot list; mutating it does not affect the queue.
        """
        now = utc_now()
        with self._cond:
            self._reap_locked(now)
            items = self._pending_locked()
        if tenant_id:
            items = [t for t in items if t.request.tenant_id == tenant_id]
        if session_id:
            items = [t for t in items if t.request.session_id == session_id]
        if min_risk is not None:
            items = [t for t in items if t.risk.at_least(min_risk)]
        items.sort(key=lambda t: (-t.risk.score, t.request.requested_at))
        return items

    def visible_to(self, principal: Principal) -> List[ApprovalTicket]:
        """Return pending tickets that ``principal`` is entitled to act on.

        Args:
            principal: The human requesting their work queue.

        Returns:
            Tickets in the principal's tenant whose required roles intersect
            the principal's roles.
        """
        return [
            ticket
            for ticket in self.pending(tenant_id=principal.tenant_id)
            if ticket.quorum.role_allows(principal)
        ]

    # -- transitions --------------------------------------------------------

    def transition(self, ticket_id: str, state: ApprovalState, *, actor: str = "system", note: str = "") -> ApprovalTicket:
        """Move a ticket to ``state`` and wake every waiter.

        Args:
            ticket_id: Ticket to transition.
            state: The new lifecycle state.
            actor: Who performed the transition.
            note: Free-form annotation stored on the request.

        Returns:
            The updated ticket.

        Raises:
            NotFoundError: The ticket is unknown.
            ConflictError: The ticket already reached a terminal state.
        """
        with self._cond:
            ticket = self._tickets.get(ticket_id)
            if ticket is None:
                raise NotFoundError(f"unknown approval ticket: {ticket_id}", details={"resource": "approval"})
            if ticket.is_terminal and state is not ticket.state:
                raise ConflictError(
                    f"ticket {ticket_id} is already {ticket.state.value}; refusing transition to {state.value}"
                )
            ticket.request.state = state
            if state.is_terminal:
                ticket.request.decided_at = utc_now()
                ticket.request.decided_by = actor or ticket.request.decided_by
                if note:
                    ticket.request.decision_note = note
                self._retire_locked(ticket)
                if state in (ApprovalState.APPROVED, ApprovalState.AUTO_APPROVED, ApprovalState.REJECTED):
                    self._stats.resolved += 1
                elif state is ApprovalState.CANCELLED:
                    self._stats.cancelled += 1
            ticket.record("transition", actor=actor, detail={"to": state.value, "note": note})
            self._cond.notify_all()
        self._emit(state.value, ticket)
        return ticket

    def cancel(self, ticket_id: str, *, actor: str = "system", reason: str = "cancelled") -> ApprovalTicket:
        """Cancel a pending ticket, releasing any waiter with a denial."""
        return self.transition(ticket_id, ApprovalState.CANCELLED, actor=actor, note=reason)

    def cancel_session(self, session_id: str, *, actor: str = "system", reason: str = "session terminated") -> int:
        """Cancel every pending ticket belonging to ``session_id``.

        Used when a session is quarantined: leaving approvals alive would let
        a later approver unblock an agent that has already been contained.

        Args:
            session_id: The session being torn down.
            actor: Who requested the teardown.
            reason: Stored as the decision note.

        Returns:
            The number of tickets cancelled.
        """
        count = 0
        for ticket in self.pending(session_id=session_id):
            try:
                self.cancel(ticket.id, actor=actor, reason=reason)
                count += 1
            except (NotFoundError, ConflictError):
                continue
        return count

    def notify_changed(self, ticket_id: str, event: str = "updated") -> None:
        """Wake waiters after an in-place mutation such as a new vote.

        Args:
            ticket_id: Ticket that changed.
            event: Event label forwarded to listeners.
        """
        with self._cond:
            ticket = self._tickets.get(ticket_id)
            self._cond.notify_all()
        if ticket is not None:
            self._emit(event, ticket)

    # -- waiting ------------------------------------------------------------

    def wait(self, ticket_id: str, timeout_s: float) -> ApprovalTicket:
        """Block until the ticket reaches a terminal state or times out.

        Args:
            ticket_id: Ticket to observe.
            timeout_s: Maximum wall-clock seconds to block.  Non-positive
                values perform a single non-blocking check.

        Returns:
            The ticket.  If the deadline passes the ticket is transitioned to
            ``EXPIRED`` first, so the caller never sees a stale ``PENDING``
            and can safely treat "not approved" as "deny".

        Raises:
            NotFoundError: The ticket is unknown.
        """
        deadline = utc_now() + max(0.0, float(timeout_s))
        with self._cond:
            ticket = self._tickets.get(ticket_id)
            if ticket is None:
                raise NotFoundError(f"unknown approval ticket: {ticket_id}", details={"resource": "approval"})
            while not ticket.is_terminal:
                now = utc_now()
                if ticket.is_expired(now):
                    break
                remaining = deadline - now
                if remaining <= 0:
                    break
                ticket_expiry = ticket.request.expires_at
                if ticket_expiry > 0:
                    remaining = min(remaining, max(0.001, ticket_expiry - now))
                self._cond.wait(timeout=min(remaining, 1.0))
            if not ticket.is_terminal and ticket.is_expired():
                ticket.request.state = ApprovalState.EXPIRED
                ticket.request.decided_at = utc_now()
                ticket.record("expired", detail={"reason": "ttl elapsed"})
                self._stats.expired += 1
                self._retire_locked(ticket)
                self._cond.notify_all()
                expired = ticket
            else:
                expired = None
        if expired is not None:
            self._emit("expired", expired)
        return ticket

    # -- reaping ------------------------------------------------------------

    def reap_expired(self) -> List[ApprovalTicket]:
        """Expire every overdue ticket and return the affected tickets."""
        with self._cond:
            reaped = self._reap_locked(utc_now())
        for ticket in reaped:
            self._emit("expired", ticket)
        return reaped

    def _reap_locked(self, now: float) -> List[ApprovalTicket]:
        """Expire overdue tickets; caller must hold the lock."""
        reaped: List[ApprovalTicket] = []
        for ticket in list(self._tickets.values()):
            if ticket.is_terminal:
                continue
            if ticket.is_expired(now):
                ticket.request.state = ApprovalState.EXPIRED
                ticket.request.decided_at = now
                ticket.record("expired", detail={"reason": "ttl elapsed"})
                self._stats.expired += 1
                self._retire_locked(ticket)
                reaped.append(ticket)
        if reaped:
            self._cond.notify_all()
        return reaped

    def _retire_locked(self, ticket: ApprovalTicket) -> None:
        """Drop dedup and history bookkeeping for a finished ticket."""
        entry = self._by_binding.get(ticket.binding)
        if entry and entry[0] == ticket.id:
            self._by_binding.pop(ticket.binding, None)
        self._history.append(ticket.id)
        overflow = len(self._history) - self._limits.max_history
        if overflow > 0:
            for stale_id in self._history[:overflow]:
                stale = self._tickets.get(stale_id)
                if stale is not None and stale.is_terminal:
                    self._tickets.pop(stale_id, None)
            del self._history[:overflow]

    def purge(self, *, keep_terminal: bool = False) -> int:
        """Remove tickets from memory.

        Args:
            keep_terminal: When true only pending tickets are cancelled and
                retained; otherwise everything is dropped.

        Returns:
            The number of tickets removed.
        """
        with self._cond:
            if keep_terminal:
                victims: Iterable[str] = [tid for tid, t in self._tickets.items() if not t.is_terminal]
            else:
                victims = list(self._tickets.keys())
            removed = 0
            for tid in list(victims):
                self._tickets.pop(tid, None)
                removed += 1
            self._by_binding.clear()
            self._history.clear()
            self._cond.notify_all()
        return removed
