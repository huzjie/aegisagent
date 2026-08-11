"""Append-only, hash-chained audit ledger.

The :class:`AuditLedger` is the system of record for every security-relevant
action performed by the platform.  Each event is hashed into a chain using
SHA-256 and signed with HMAC-SHA256, so any tampering is detectable by
:meth:`AuditLedger.verify_chain`.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from aegis.core.types import AuditEvent, Severity, new_id, utc_now
from aegis.core.crypto import (
    Signer,
    NullSigner,
    chain_hash,
    canonical_json,
)
from aegis.core.logging import get_logger
from .event import AuditEventRecord, record_to_dict, event_from_record
from .filters import AuditFilter
from .aggregator import AuditAggregator, AuditSummary
from .exporters import AuditExporter
from .alerting import AuditAlertEngine, AlertRule, AlertFired

__all__ = ["AuditLedger"]

_log = get_logger(__name__)


class AuditLedger:
    """Thread-safe append-only audit ledger with hash chaining.

    Args:
        path: optional filesystem path for JSONL persistence.  If empty, the
            ledger lives purely in memory.
        signer: cryptographic signer used to attach a detached signature to
            every event.  Defaults to :class:`NullSigner`.
        settings: optional :class:`aegis.core.config.Settings` instance used to
            configure alerting and export behaviour.
        sqlite_path: optional path to a SQLite database that mirrors the
            ledger for indexed querying.
    """

    def __init__(
        self,
        path: str = "",
        signer: Optional[Signer] = None,
        settings: Any = None,
        sqlite_path: str = "",
    ) -> None:
        self._path = path
        self._signer = signer or NullSigner()
        self._settings = settings
        self._events: List[AuditEventRecord] = []
        self._lock = threading.RLock()
        self._sequence: int = 0
        self._prev_hash: str = ""
        self._aggregator = AuditAggregator()
        self._exporter = AuditExporter()
        self._alert_engine = AuditAlertEngine()
        self._sqlite: Optional[sqlite3.Connection] = None

        if path and os.path.isfile(path):
            self._load_from_file(path)
        if sqlite_path:
            self._init_sqlite(sqlite_path)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def record(self, action: str, severity: Severity = Severity.INFO, **fields: Any) -> AuditEvent:
        """Create and append a new audit event.

        This is the primary entry point.  All keyword arguments are placed
        into the event's ``payload`` dictionary.

        Returns:
            The newly appended :class:`aegis.core.types.AuditEvent`.
        """
        record = AuditEventRecord(
            id=new_id("evt"),
            action=action,
            severity=severity,
            payload=dict(fields),
            actor=str(fields.get("actor", fields.get("tenant_id", "system"))),
            tenant_id=str(fields.get("tenant_id", "default")),
            session_id=str(fields.get("session_id", "")),
            agent_id=str(fields.get("agent_id", "")),
            principal_id=str(fields.get("principal_id", "")),
            resource=str(fields.get("resource", "")),
            outcome=str(fields.get("outcome", "success")),
        )
        self.append(record)
        return record.to_core()

    def append(self, event: AuditEventRecord) -> AuditEventRecord:
        """Append a pre-built event to the ledger, computing chain hash and signature."""
        with self._lock:
            self._sequence += 1
            event.sequence = self._sequence
            event.prev_hash = self._prev_hash

            hash_input = {
                "prev_hash": self._prev_hash,
                "payload": event.hashable_payload(),
            }
            event.hash = chain_hash(self._prev_hash, hash_input)
            event.signature = self._signer.sign(event.hashable_payload())

            self._events.append(event)
            self._prev_hash = event.hash

            if self._path:
                self._append_to_file(event)
            if self._sqlite is not None:
                self._insert_sqlite(event)

        self._alert_engine.evaluate(event)
        return event

    def verify_chain(self) -> Tuple[bool, List[str]]:
        """Verify the integrity of the hash chain.

        Returns:
            A tuple ``(valid, errors)`` where *errors* is a list of human
            readable descriptions for every broken link.
        """
        errors: List[str] = []
        with self._lock:
            prev_hash = ""
            for event in self._events:
                if event.prev_hash != prev_hash:
                    errors.append(
                        f"seq={event.sequence} id={event.id}: prev_hash mismatch "
                        f"(expected={prev_hash!r}, got={event.prev_hash!r})"
                    )
                hash_input = {
                    "prev_hash": event.prev_hash,
                    "payload": event.hashable_payload(),
                }
                expected = chain_hash(event.prev_hash, hash_input)
                if event.hash != expected:
                    errors.append(
                        f"seq={event.sequence} id={event.id}: hash mismatch "
                        f"(expected={expected!r}, got={event.hash!r})"
                    )
                if self._signer.algorithm != "none" and event.signature:
                    if not self._signer.verify(event.hashable_payload(), event.signature):
                        errors.append(
                            f"seq={event.sequence} id={event.id}: signature verification failed"
                        )
                prev_hash = event.hash
        valid = len(errors) == 0
        if not valid:
            self._alert_engine.report_chain_break({"errors": errors[:10]})
        return valid, errors

    def tail(self, n: int = 100) -> List[AuditEventRecord]:
        """Return the most recent *n* events."""
        with self._lock:
            return list(self._events[-n:])

    def recent(self, n: int = 100) -> List[AuditEventRecord]:
        """Alias for :meth:`tail`."""
        return self.tail(n)

    def query(self, filter: Optional[AuditFilter] = None, **kwargs: Any) -> List[AuditEventRecord]:
        """Return events matching *filter*."""
        if filter is None:
            filter = AuditFilter(**kwargs)
        with self._lock:
            snapshot = list(self._events)
        results = [e for e in snapshot if filter.matches(e)]
        if filter.limit and filter.limit > 0:
            results = results[:filter.limit]
        return results

    def export_jsonl(self, path: str) -> str:
        """Write the full ledger to a JSONL file."""
        with self._lock:
            events = list(self._events)
        return self._exporter.export(events, fmt="jsonl", path=path)

    def import_jsonl(self, path: str) -> int:
        """Import events from a JSONL file, skipping duplicates.

        Returns:
            Number of events imported.
        """
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        imported = 0
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                record = AuditEventRecord.from_json(line)
                with self._lock:
                    existing_ids = {e.id for e in self._events}
                if record.id in existing_ids:
                    continue
                self.append(record)
                imported += 1
        return imported

    def stats(self) -> Dict[str, Any]:
        """Return summary statistics about the ledger."""
        with self._lock:
            events = list(self._events)
        summary = self._aggregator.summary(events)
        return {
            "total_events": len(events),
            "sequence": self._sequence,
            "last_hash": self._prev_hash,
            "summary": summary.to_dict(),
        }

    def summary(self, events: Optional[Sequence[AuditEventRecord]] = None) -> AuditSummary:
        """Compute aggregated statistics.

        If *events* is ``None``, the full ledger is summarised.
        """
        if events is None:
            with self._lock:
                events = list(self._events)
        return self._aggregator.summary(events)

    @property
    def alert_engine(self) -> AuditAlertEngine:
        """The alert engine attached to this ledger."""
        return self._alert_engine

    @property
    def aggregator(self) -> AuditAggregator:
        """The aggregator attached to this ledger."""
        return self._aggregator

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)

    # ------------------------------------------------------------------ #
    # Persistence helpers
    # ------------------------------------------------------------------ #

    def _load_from_file(self, path: str) -> None:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = AuditEventRecord.from_json(line)
                    self._events.append(record)
                    if record.sequence > self._sequence:
                        self._sequence = record.sequence
                    if record.hash:
                        self._prev_hash = record.hash
                except Exception:
                    _log.exception("failed to parse audit line")

    def _append_to_file(self, event: AuditEventRecord) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self._path)) or ".", exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(event.to_json() + "\n")

    def _init_sqlite(self, path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        self._sqlite = sqlite3.connect(path, check_same_thread=False)
        self._sqlite.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                sequence INTEGER,
                timestamp REAL,
                tenant_id TEXT,
                actor TEXT,
                action TEXT,
                resource TEXT,
                outcome TEXT,
                severity TEXT,
                session_id TEXT,
                agent_id TEXT,
                principal_id TEXT,
                payload_json TEXT,
                prev_hash TEXT,
                hash TEXT,
                signature TEXT
            )
            """
        )
        self._sqlite.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action)"
        )
        self._sqlite.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(timestamp)"
        )
        self._sqlite.commit()
        # Re-seed in-memory state from SQLite if the file already existed
        cursor = self._sqlite.execute(
            "SELECT sequence, hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
        )
        row = cursor.fetchone()
        if row:
            if row[0] and row[0] > self._sequence:
                self._sequence = row[0]
            if row[1]:
                self._prev_hash = row[1]

    def _insert_sqlite(self, event: AuditEventRecord) -> None:
        if self._sqlite is None:
            return
        try:
            self._sqlite.execute(
                """
                INSERT OR IGNORE INTO audit_events
                (id, sequence, timestamp, tenant_id, actor, action, resource,
                 outcome, severity, session_id, agent_id, principal_id,
                 payload_json, prev_hash, hash, signature)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.id, event.sequence, event.timestamp, event.tenant_id,
                    event.actor, event.action, event.resource, event.outcome,
                    event.severity.value, event.session_id, event.agent_id,
                    event.principal_id, json.dumps(event.payload, default=str),
                    event.prev_hash, event.hash, event.signature,
                ),
            )
            self._sqlite.commit()
        except Exception:
            _log.exception("sqlite insert failed")
