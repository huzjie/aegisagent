"""Drop-in interceptor that enforces provenance in front of any executor.

The CoreBreak advisories all describe the same architectural gap: the component
that *dispatches* a tool was not the component that *authorised* it, and nothing
sat between them.  ``ProvenanceMiddleware`` is that missing component.

It is deliberately callable, so it composes with whatever the host runtime
already has::

    guard = ProvenanceMiddleware(verifier, mode="enforce")

    def dispatch(call: ToolCall) -> ToolResult:
        guard(call)              # raises before anything is executed
        return real_executor(call)

Modes
-----
``off``
    No verification at all.  Returns a neutral record so callers do not have to
    branch on ``None``.
``monitor``
    Verify and record, never block.  This is the rollout mode - it tells you how
    much of your existing traffic would fail provenance *before* you turn on
    enforcement.
``enforce``
    Verify and raise on anything that is not ``VERIFIED``.
"""

from __future__ import annotations

import threading
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set

from ..core.config import Settings, get_settings
from ..core.errors import (
    ForgedToolCallError,
    ProvenanceError,
    ReplayAttackError,
)
from ..core.logging import get_logger
from ..core.types import ProvenanceRecord, ProvenanceStatus, ToolCall, utc_now
from .session_ledger import SessionLedger
from .store import ProvenanceStore
from .verifier import ProvenanceVerifier

__all__ = ["ProvenanceMiddleware", "MODES"]

_LOG = get_logger("provenance.middleware")

MODES = ("off", "monitor", "enforce")

#: Statuses severe enough that the whole session should be frozen, not just the
#: single call rejected.  Each one implies an attacker with request-forging
#: ability, so subsequent calls in that session cannot be trusted either.
DEFAULT_QUARANTINE_ON: Set[ProvenanceStatus] = {
    ProvenanceStatus.FORGED,
    ProvenanceStatus.REPLAYED,
    ProvenanceStatus.MISMATCHED,
}

_ERROR_FOR_STATUS = {
    ProvenanceStatus.FORGED: ForgedToolCallError,
    ProvenanceStatus.ORPHANED: ForgedToolCallError,
    ProvenanceStatus.MISMATCHED: ForgedToolCallError,
    ProvenanceStatus.REPLAYED: ReplayAttackError,
}


class ProvenanceMiddleware:
    """Verify-before-dispatch interceptor with off / monitor / enforce modes.

    Parameters
    ----------
    verifier:
        The :class:`~aegis.provenance.verifier.ProvenanceVerifier` doing the work.
    mode:
        ``"off"``, ``"monitor"`` or ``"enforce"``.
    store:
        Optional :class:`~aegis.provenance.store.ProvenanceStore`; every verdict
        (pass or fail) is persisted when supplied.
    ledger:
        Optional ledger used to record the attempted call and to quarantine the
        session on a severe breach.  Defaults to the verifier's own ledger.
    quarantine_on:
        Statuses that trigger session quarantine.  Pass an empty set to disable.
    on_violation:
        Optional callback invoked with ``(call, record)`` for every failure -
        the hook the incident pipeline subscribes to.
    """

    def __init__(
        self,
        verifier: ProvenanceVerifier,
        *,
        mode: str = "enforce",
        store: Optional[ProvenanceStore] = None,
        ledger: Optional[SessionLedger] = None,
        quarantine_on: Optional[Iterable[ProvenanceStatus]] = None,
        on_violation: Optional[Callable[[ToolCall, ProvenanceRecord], None]] = None,
        record_calls: bool = True,
        block_quarantined_sessions: bool = True,
    ) -> None:
        self.verifier = verifier
        self.mode = self._normalise_mode(mode)
        self.store = store
        self.ledger = ledger if ledger is not None else verifier.ledger
        self.quarantine_on: Set[ProvenanceStatus] = (
            set(quarantine_on) if quarantine_on is not None else set(DEFAULT_QUARANTINE_ON)
        )
        self.on_violation = on_violation
        self.record_calls = bool(record_calls)
        self.block_quarantined_sessions = bool(block_quarantined_sessions)
        self._lock = threading.Lock()
        self._seen = 0
        self._blocked = 0
        self._would_block = 0

    @staticmethod
    def _normalise_mode(mode: str) -> str:
        value = str(mode or "enforce").strip().lower()
        if value in ("disabled", "none", "false"):
            value = "off"
        if value in ("observe", "dry_run", "dry-run", "audit"):
            value = "monitor"
        if value not in MODES:
            raise ValueError(f"unknown provenance mode {mode!r}; expected one of {MODES}")
        return value

    @classmethod
    def from_settings(
        cls,
        settings: Optional[Settings] = None,
        *,
        verifier: Optional[ProvenanceVerifier] = None,
        store: Optional[ProvenanceStore] = None,
    ) -> "ProvenanceMiddleware":
        """Build middleware from the ``provenance`` configuration section."""
        settings = settings or get_settings()
        verifier = verifier or ProvenanceVerifier.from_settings(settings)
        enabled = bool(settings.get("provenance.enabled", True))
        mode = str(settings.get("provenance.mode", "enforce")) if enabled else "off"
        return cls(verifier, mode=mode, store=store)

    # ------------------------------------------------------------------ #
    # Hot path
    # ------------------------------------------------------------------ #
    def __call__(self, call: ToolCall) -> ProvenanceRecord:
        """Verify one tool call.

        Returns the :class:`ProvenanceRecord` in every mode.  In ``enforce``
        mode a non-verified result raises instead of returning, so a caller that
        forgets to inspect the record still cannot execute an unauthorised tool.
        """
        with self._lock:
            self._seen += 1

        if self.mode == "off":
            record = ProvenanceRecord(
                call_id=call.id,
                status=ProvenanceStatus.MISSING,
                completion_id=call.completion_id,
            )
            record.reasons.append("provenance mode=off - no verification was performed")
            return record

        if self.record_calls:
            self.ledger.record_call(call)

        if self.block_quarantined_sessions and self.ledger.is_quarantined(call.session_id):
            record = ProvenanceRecord(
                call_id=call.id,
                status=ProvenanceStatus.FORGED,
                completion_id=call.completion_id,
                verified_at=utc_now(),
            )
            record.reasons.append(
                f"session {call.session_id!r} is quarantined after an earlier provenance "
                f"breach - no further tool calls are accepted"
            )
            self._persist(call, record)
            return self._react(call, record)

        record = self.verifier.verify(call)
        self._persist(call, record)
        return self._react(call, record)

    def check(self, call: ToolCall) -> ProvenanceRecord:
        """Alias for :meth:`__call__` for callers that prefer a named method."""
        return self(call)

    def check_batch(self, calls: Sequence[ToolCall]) -> List[ProvenanceRecord]:
        """Verify several calls, collecting records.

        In ``enforce`` mode the first failure raises, matching the semantics of
        dispatching them sequentially.
        """
        return [self(call) for call in calls]

    def allows(self, call: ToolCall) -> bool:
        """Non-raising convenience check - True when the call may be dispatched."""
        if self.mode == "off":
            return True
        record = self.verifier.verify(call)
        self._persist(call, record)
        return record.trustworthy

    # ------------------------------------------------------------------ #
    # Reactions
    # ------------------------------------------------------------------ #
    def _react(self, call: ToolCall, record: ProvenanceRecord) -> ProvenanceRecord:
        """Apply mode-specific handling to a finished verdict."""
        if record.trustworthy:
            return record

        if self.on_violation is not None:
            try:
                self.on_violation(call, record)
            except Exception as exc:  # noqa: BLE001 - a bad hook must not unblock a call
                _LOG.error("provenance violation hook raised: %s", exc)

        if record.status in self.quarantine_on and call.session_id:
            self.ledger.quarantine(
                call.session_id, reason=f"provenance {record.status.value} on call {call.id}"
            )

        if self.mode == "monitor":
            with self._lock:
                self._would_block += 1
            _LOG.warning(
                "provenance violation (monitor mode - call NOT blocked)",
                fields={
                    "status": record.status.value,
                    "tool": call.qualified_name,
                    "call_id": call.id,
                    "session_id": call.session_id,
                    "reason": record.reasons[0] if record.reasons else "",
                },
            )
            return record

        with self._lock:
            self._blocked += 1
        error_cls = _ERROR_FOR_STATUS.get(record.status, ProvenanceError)
        raise error_cls(
            f"tool call {call.qualified_name!r} rejected: provenance status "
            f"{record.status.value}",
            details={
                "call_id": call.id,
                "session_id": call.session_id,
                "tool": call.qualified_name,
                "status": record.status.value,
                "risk": record.status.risk.value,
                "reasons": list(record.reasons),
            },
        )

    def _persist(self, call: ToolCall, record: ProvenanceRecord) -> None:
        if self.store is None:
            return
        try:
            self.store.put(
                record,
                session_id=call.session_id,
                tenant_id=call.tenant_id,
                tool=call.qualified_name,
            )
        except Exception as exc:  # noqa: BLE001 - evidence loss must not block traffic
            _LOG.error("could not persist provenance record: %s", exc)

    # ------------------------------------------------------------------ #
    # Control
    # ------------------------------------------------------------------ #
    def set_mode(self, mode: str) -> str:
        """Switch modes at runtime (monitor -> enforce rollouts)."""
        self.mode = self._normalise_mode(mode)
        _LOG.info("provenance mode changed", fields={"mode": self.mode})
        return self.mode

    def wrap(self, executor: Callable[[ToolCall], Any]) -> Callable[[ToolCall], Any]:
        """Return ``executor`` with a provenance check bolted on in front."""

        def guarded(call: ToolCall) -> Any:
            self(call)
            return executor(call)

        guarded.__name__ = getattr(executor, "__name__", "guarded_executor")
        guarded.__doc__ = (
            f"Provenance-guarded wrapper around {getattr(executor, '__name__', 'executor')}."
        )
        return guarded

    def stats(self) -> Dict[str, Any]:
        """Middleware counters merged with the verifier's own statistics."""
        with self._lock:
            seen, blocked, would_block = self._seen, self._blocked, self._would_block
        return {
            "mode": self.mode,
            "seen": seen,
            "blocked": blocked,
            "would_block": would_block,
            "block_rate": round(blocked / seen, 4) if seen else 0.0,
            "verifier": self.verifier.stats(),
        }
