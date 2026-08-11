"""Persistence for provenance verdicts.

Verification results are evidence.  When an injected tool call is blocked at
03:00, the on-call engineer needs to be able to ask "show me every ORPHANED call
on this tenant in the last hour" without grepping logs.

Two implementations ship:

* :class:`InMemoryProvenanceStore` - bounded ring buffer, zero setup, used by
  tests and by the embedded SDK mode.
* :class:`SQLiteProvenanceStore` - stdlib ``sqlite3`` with a proper schema,
  indices on the columns incident response actually filters by, and idempotent
  upserts so a retried write cannot duplicate evidence.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from ..core.errors import StorageError
from ..core.logging import get_logger
from ..core.types import ProvenanceRecord, ProvenanceStatus, utc_now

__all__ = [
    "record_to_row",
    "row_to_record",
    "ProvenanceStore",
    "InMemoryProvenanceStore",
    "SQLiteProvenanceStore",
    "build_store",
]

_LOG = get_logger("provenance.store")


# --------------------------------------------------------------------------- #
# Serialisation
# --------------------------------------------------------------------------- #
def record_to_row(
    record: ProvenanceRecord,
    *,
    session_id: str = "",
    tenant_id: str = "default",
    tool: str = "",
) -> Dict[str, Any]:
    """Flatten a :class:`ProvenanceRecord` into a storable row."""
    return {
        "call_id": record.call_id,
        "session_id": session_id,
        "tenant_id": tenant_id or "default",
        "tool": tool,
        "status": record.status.value,
        "completion_id": record.completion_id or "",
        "issuer": record.issuer,
        "signature_algorithm": record.signature_algorithm,
        "bound_hash": record.bound_hash,
        "observed_hash": record.observed_hash,
        "issued_at": float(record.issued_at or 0.0),
        "verified_at": float(record.verified_at or utc_now()),
        "nonce": record.nonce,
        "risk": record.status.risk.value,
        "reasons": list(record.reasons),
    }


def row_to_record(row: Dict[str, Any]) -> ProvenanceRecord:
    """Rebuild a :class:`ProvenanceRecord` from a stored row."""
    reasons = row.get("reasons")
    if isinstance(reasons, str):
        try:
            reasons = json.loads(reasons)
        except ValueError:
            reasons = [reasons]
    try:
        status = ProvenanceStatus(str(row.get("status", "missing")))
    except ValueError:
        status = ProvenanceStatus.MISSING
    return ProvenanceRecord(
        call_id=str(row.get("call_id", "")),
        status=status,
        completion_id=str(row.get("completion_id") or "") or None,
        issuer=str(row.get("issuer", "")),
        signature_algorithm=str(row.get("signature_algorithm", "")),
        bound_hash=str(row.get("bound_hash", "")),
        observed_hash=str(row.get("observed_hash", "")),
        issued_at=float(row.get("issued_at", 0.0) or 0.0),
        verified_at=float(row.get("verified_at", 0.0) or 0.0),
        nonce=str(row.get("nonce", "")),
        reasons=list(reasons or []),
    )


# --------------------------------------------------------------------------- #
# Interface
# --------------------------------------------------------------------------- #
class ProvenanceStore:
    """Abstract persistence interface for provenance verdicts."""

    backend = "abstract"

    def put(
        self,
        record: ProvenanceRecord,
        *,
        session_id: str = "",
        tenant_id: str = "default",
        tool: str = "",
    ) -> None:
        """Insert or replace the verdict for ``record.call_id``."""
        raise NotImplementedError  # pragma: no cover - interface

    def put_many(self, records: Iterable[ProvenanceRecord], **kw: Any) -> int:
        """Bulk write helper.  Returns the number of rows written."""
        count = 0
        for record in records:
            self.put(record, **kw)
            count += 1
        return count

    def get(self, call_id: str) -> Optional[ProvenanceRecord]:
        """Fetch a single verdict by call id."""
        raise NotImplementedError  # pragma: no cover - interface

    def list_by_status(
        self, status: ProvenanceStatus, *, limit: int = 100, tenant_id: str = ""
    ) -> List[ProvenanceRecord]:
        """Most recent verdicts with a given status, newest first."""
        raise NotImplementedError  # pragma: no cover - interface

    def list_by_session(self, session_id: str, *, limit: int = 200) -> List[ProvenanceRecord]:
        """Every verdict recorded for one session, newest first."""
        raise NotImplementedError  # pragma: no cover - interface

    def failures(self, *, limit: int = 100, tenant_id: str = "") -> List[ProvenanceRecord]:
        """All non-``VERIFIED`` verdicts - the incident-response entry point."""
        raise NotImplementedError  # pragma: no cover - interface

    def count(self) -> int:
        """Total rows retained."""
        raise NotImplementedError  # pragma: no cover - interface

    def counts_by_status(self) -> Dict[str, int]:
        """Histogram used by dashboards and the metrics endpoint."""
        raise NotImplementedError  # pragma: no cover - interface

    def prune(self, older_than_s: float) -> int:
        """Delete verdicts older than ``older_than_s`` seconds.  Returns count."""
        raise NotImplementedError  # pragma: no cover - interface

    def close(self) -> None:
        """Release resources."""
        return None


# --------------------------------------------------------------------------- #
# In-memory
# --------------------------------------------------------------------------- #
class InMemoryProvenanceStore(ProvenanceStore):
    """Bounded, thread-safe, process-local store.

    Oldest rows are evicted once ``maxsize`` is exceeded so a long-running
    gateway cannot leak memory through provenance evidence.
    """

    backend = "memory"

    def __init__(self, maxsize: int = 10_000) -> None:
        self.maxsize = max(16, int(maxsize))
        self._lock = threading.RLock()
        self._rows: Dict[str, Dict[str, Any]] = {}
        self._order: List[str] = []

    def put(
        self,
        record: ProvenanceRecord,
        *,
        session_id: str = "",
        tenant_id: str = "default",
        tool: str = "",
    ) -> None:
        row = record_to_row(record, session_id=session_id, tenant_id=tenant_id, tool=tool)
        key = row["call_id"] or f"anon:{len(self._order)}"
        row["call_id"] = key
        with self._lock:
            if key not in self._rows:
                self._order.append(key)
            self._rows[key] = row
            while len(self._order) > self.maxsize:
                self._rows.pop(self._order.pop(0), None)

    def get(self, call_id: str) -> Optional[ProvenanceRecord]:
        with self._lock:
            row = self._rows.get(call_id)
        return row_to_record(row) if row else None

    def _filtered(self, predicate: Any, limit: int) -> List[ProvenanceRecord]:
        with self._lock:
            rows = [self._rows[k] for k in reversed(self._order) if k in self._rows]
        out = [row_to_record(r) for r in rows if predicate(r)]
        return out[: max(0, int(limit))]

    def list_by_status(
        self, status: ProvenanceStatus, *, limit: int = 100, tenant_id: str = ""
    ) -> List[ProvenanceRecord]:
        return self._filtered(
            lambda r: r["status"] == status.value
            and (not tenant_id or r["tenant_id"] == tenant_id),
            limit,
        )

    def list_by_session(self, session_id: str, *, limit: int = 200) -> List[ProvenanceRecord]:
        return self._filtered(lambda r: r["session_id"] == session_id, limit)

    def failures(self, *, limit: int = 100, tenant_id: str = "") -> List[ProvenanceRecord]:
        return self._filtered(
            lambda r: r["status"] != ProvenanceStatus.VERIFIED.value
            and (not tenant_id or r["tenant_id"] == tenant_id),
            limit,
        )

    def count(self) -> int:
        with self._lock:
            return len(self._rows)

    def counts_by_status(self) -> Dict[str, int]:
        with self._lock:
            rows = list(self._rows.values())
        out: Dict[str, int] = {}
        for row in rows:
            out[row["status"]] = out.get(row["status"], 0) + 1
        return out

    def prune(self, older_than_s: float) -> int:
        cutoff = utc_now() - max(0.0, float(older_than_s))
        with self._lock:
            stale = [k for k, r in self._rows.items() if r.get("verified_at", 0.0) < cutoff]
            for key in stale:
                self._rows.pop(key, None)
            self._order = [k for k in self._order if k in self._rows]
        return len(stale)

    def clear(self) -> None:
        """Drop everything - test helper."""
        with self._lock:
            self._rows.clear()
            self._order.clear()


# --------------------------------------------------------------------------- #
# SQLite
# --------------------------------------------------------------------------- #
class SQLiteProvenanceStore(ProvenanceStore):
    """Durable store backed by stdlib ``sqlite3``.

    The schema is deliberately denormalised: provenance evidence is written once
    and read by humans under time pressure, so a single wide table with the
    right indices beats a normalised model here.
    """

    backend = "sqlite"

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS provenance_records (
        call_id             TEXT PRIMARY KEY,
        session_id          TEXT NOT NULL DEFAULT '',
        tenant_id           TEXT NOT NULL DEFAULT 'default',
        tool                TEXT NOT NULL DEFAULT '',
        status              TEXT NOT NULL,
        risk                TEXT NOT NULL DEFAULT 'none',
        completion_id       TEXT NOT NULL DEFAULT '',
        issuer              TEXT NOT NULL DEFAULT '',
        signature_algorithm TEXT NOT NULL DEFAULT '',
        bound_hash          TEXT NOT NULL DEFAULT '',
        observed_hash       TEXT NOT NULL DEFAULT '',
        nonce               TEXT NOT NULL DEFAULT '',
        issued_at           REAL NOT NULL DEFAULT 0,
        verified_at         REAL NOT NULL DEFAULT 0,
        reasons             TEXT NOT NULL DEFAULT '[]'
    );
    CREATE INDEX IF NOT EXISTS idx_prov_status  ON provenance_records (status, verified_at DESC);
    CREATE INDEX IF NOT EXISTS idx_prov_session ON provenance_records (session_id, verified_at DESC);
    CREATE INDEX IF NOT EXISTS idx_prov_tenant  ON provenance_records (tenant_id, verified_at DESC);
    CREATE INDEX IF NOT EXISTS idx_prov_compl   ON provenance_records (completion_id);
    CREATE INDEX IF NOT EXISTS idx_prov_time    ON provenance_records (verified_at DESC);
    """

    _COLUMNS = (
        "call_id, session_id, tenant_id, tool, status, risk, completion_id, issuer, "
        "signature_algorithm, bound_hash, observed_hash, nonce, issued_at, verified_at, reasons"
    )

    def __init__(self, path: str = "data/provenance.db") -> None:
        target = Path(path)
        if str(target.parent) not in ("", "."):
            target.parent.mkdir(parents=True, exist_ok=True)
        self.path = str(target)
        self._lock = threading.RLock()
        try:
            self._conn = sqlite3.connect(self.path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(self._SCHEMA)
            self._conn.commit()
        except sqlite3.Error as exc:
            raise StorageError(f"cannot open provenance store at {self.path}: {exc}", cause=exc)

    # -- writes ---------------------------------------------------------- #
    def put(
        self,
        record: ProvenanceRecord,
        *,
        session_id: str = "",
        tenant_id: str = "default",
        tool: str = "",
    ) -> None:
        row = record_to_row(record, session_id=session_id, tenant_id=tenant_id, tool=tool)
        if not row["call_id"]:
            raise StorageError("provenance record requires a call_id before persisting")
        statement = f"""
            INSERT INTO provenance_records ({self._COLUMNS})
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(call_id) DO UPDATE SET
                session_id=excluded.session_id,
                tenant_id=excluded.tenant_id,
                tool=excluded.tool,
                status=excluded.status,
                risk=excluded.risk,
                completion_id=excluded.completion_id,
                issuer=excluded.issuer,
                signature_algorithm=excluded.signature_algorithm,
                bound_hash=excluded.bound_hash,
                observed_hash=excluded.observed_hash,
                nonce=excluded.nonce,
                issued_at=excluded.issued_at,
                verified_at=excluded.verified_at,
                reasons=excluded.reasons
        """
        params = (
            row["call_id"],
            row["session_id"],
            row["tenant_id"],
            row["tool"],
            row["status"],
            row["risk"],
            row["completion_id"],
            row["issuer"],
            row["signature_algorithm"],
            row["bound_hash"],
            row["observed_hash"],
            row["nonce"],
            row["issued_at"],
            row["verified_at"],
            json.dumps(row["reasons"], ensure_ascii=False),
        )
        with self._lock:
            try:
                self._conn.execute(statement, params)
                self._conn.commit()
            except sqlite3.Error as exc:
                self._conn.rollback()
                raise StorageError(f"failed to persist provenance record: {exc}", cause=exc)

    # -- reads ----------------------------------------------------------- #
    def _query(self, where: str, params: tuple, limit: int) -> List[ProvenanceRecord]:
        sql = (
            f"SELECT {self._COLUMNS} FROM provenance_records "
            f"{where} ORDER BY verified_at DESC LIMIT ?"
        )
        with self._lock:
            try:
                rows = self._conn.execute(sql, params + (max(1, int(limit)),)).fetchall()
            except sqlite3.Error as exc:
                raise StorageError(f"provenance query failed: {exc}", cause=exc)
        return [row_to_record(dict(row)) for row in rows]

    def get(self, call_id: str) -> Optional[ProvenanceRecord]:
        with self._lock:
            row = self._conn.execute(
                f"SELECT {self._COLUMNS} FROM provenance_records WHERE call_id = ?", (call_id,)
            ).fetchone()
        return row_to_record(dict(row)) if row else None

    def list_by_status(
        self, status: ProvenanceStatus, *, limit: int = 100, tenant_id: str = ""
    ) -> List[ProvenanceRecord]:
        if tenant_id:
            return self._query(
                "WHERE status = ? AND tenant_id = ?", (status.value, tenant_id), limit
            )
        return self._query("WHERE status = ?", (status.value,), limit)

    def list_by_session(self, session_id: str, *, limit: int = 200) -> List[ProvenanceRecord]:
        return self._query("WHERE session_id = ?", (session_id,), limit)

    def failures(self, *, limit: int = 100, tenant_id: str = "") -> List[ProvenanceRecord]:
        verified = ProvenanceStatus.VERIFIED.value
        if tenant_id:
            return self._query(
                "WHERE status != ? AND tenant_id = ?", (verified, tenant_id), limit
            )
        return self._query("WHERE status != ?", (verified,), limit)

    def count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) FROM provenance_records").fetchone()
        return int(row[0]) if row else 0

    def counts_by_status(self) -> Dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT status, COUNT(*) AS n FROM provenance_records GROUP BY status"
            ).fetchall()
        return {str(r["status"]): int(r["n"]) for r in rows}

    def prune(self, older_than_s: float) -> int:
        cutoff = utc_now() - max(0.0, float(older_than_s))
        with self._lock:
            try:
                cursor = self._conn.execute(
                    "DELETE FROM provenance_records WHERE verified_at < ?", (cutoff,)
                )
                self._conn.commit()
            except sqlite3.Error as exc:
                self._conn.rollback()
                raise StorageError(f"prune failed: {exc}", cause=exc)
        return int(cursor.rowcount or 0)

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:  # pragma: no cover
                pass


def build_store(backend: str = "memory", dsn: str = "data/provenance.db") -> ProvenanceStore:
    """Factory mirroring the ``storage.backend`` configuration key."""
    kind = (backend or "memory").lower()
    if kind in ("sqlite", "sqlite3", "file"):
        try:
            return SQLiteProvenanceStore(dsn)
        except StorageError as exc:  # pragma: no cover - disk problems
            _LOG.warning("falling back to in-memory provenance store: %s", exc.message)
    return InMemoryProvenanceStore()
