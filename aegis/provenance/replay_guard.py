"""One-time-use enforcement for attestation nonces.

A signed attestation is a *capability*.  If it can be presented twice it stops
being proof that the model authorised an action and becomes a reusable token an
attacker can fire repeatedly - "transfer $10" replayed forty times.

``ReplayGuard`` makes every nonce strictly single-use inside its TTL window.
Two backends ship:

* ``memory`` - a dict guarded by a lock; correct for a single process.
* ``sqlite`` - a small table with a unique constraint; correct across the worker
  processes of one host, and durable across restarts.

The TTL matters for both correctness and memory: nonces only need to be
remembered for as long as an attestation could still be considered fresh
(``provenance.max_age_s`` plus clock skew).  Anything older is rejected by the
expiry check anyway, so forgetting it is safe.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from ..core.logging import get_logger
from ..core.types import utc_now

__all__ = ["ReplayGuardBackend", "MemoryReplayBackend", "SqliteReplayBackend", "ReplayGuard"]

_LOG = get_logger("provenance.replay")


class ReplayGuardBackend:
    """Storage interface for consumed nonces."""

    name = "abstract"

    def consume(self, nonce: str, expires_at: float) -> bool:
        """Atomically claim ``nonce``.  Return True on first use, False on replay."""
        raise NotImplementedError  # pragma: no cover - interface

    def seen(self, nonce: str) -> bool:
        """True when the nonce has already been consumed and is not yet expired."""
        raise NotImplementedError  # pragma: no cover - interface

    def purge(self, now: Optional[float] = None) -> int:
        """Drop expired entries.  Return how many were removed."""
        raise NotImplementedError  # pragma: no cover - interface

    def count(self) -> int:
        """Number of live (unexpired) nonces currently retained."""
        raise NotImplementedError  # pragma: no cover - interface

    def clear(self) -> None:
        """Forget everything - test helper / break-glass reset."""
        raise NotImplementedError  # pragma: no cover - interface

    def close(self) -> None:
        """Release any underlying resources."""
        return None


class MemoryReplayBackend(ReplayGuardBackend):
    """In-process nonce set.  Fast, non-durable, single-process only."""

    name = "memory"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._nonces: Dict[str, float] = {}

    def consume(self, nonce: str, expires_at: float) -> bool:
        now = utc_now()
        with self._lock:
            existing = self._nonces.get(nonce)
            if existing is not None and existing > now:
                return False
            self._nonces[nonce] = expires_at
            return True

    def seen(self, nonce: str) -> bool:
        now = utc_now()
        with self._lock:
            expiry = self._nonces.get(nonce)
            return expiry is not None and expiry > now

    def purge(self, now: Optional[float] = None) -> int:
        cutoff = now if now is not None else utc_now()
        with self._lock:
            stale = [n for n, exp in self._nonces.items() if exp <= cutoff]
            for nonce in stale:
                self._nonces.pop(nonce, None)
            return len(stale)

    def count(self) -> int:
        now = utc_now()
        with self._lock:
            return sum(1 for exp in self._nonces.values() if exp > now)

    def clear(self) -> None:
        with self._lock:
            self._nonces.clear()


class SqliteReplayBackend(ReplayGuardBackend):
    """Durable nonce store backed by stdlib ``sqlite3``.

    Uniqueness is enforced by the primary key, so ``consume`` is atomic even
    when several threads race on the same nonce: exactly one INSERT succeeds and
    every other caller sees :class:`sqlite3.IntegrityError`.
    """

    name = "sqlite"

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS provenance_nonces (
        nonce       TEXT PRIMARY KEY,
        consumed_at REAL NOT NULL,
        expires_at  REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_nonce_expiry ON provenance_nonces (expires_at);
    """

    def __init__(self, path: str = "data/provenance-nonces.db") -> None:
        target = Path(path)
        if target.parent and str(target.parent) not in ("", "."):
            target.parent.mkdir(parents=True, exist_ok=True)
        self.path = str(target)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(self._SCHEMA)
        self._conn.commit()

    def consume(self, nonce: str, expires_at: float) -> bool:
        now = utc_now()
        with self._lock:
            cursor = self._conn.execute(
                "SELECT expires_at FROM provenance_nonces WHERE nonce = ?", (nonce,)
            )
            row = cursor.fetchone()
            if row is not None:
                if float(row[0]) > now:
                    return False
                self._conn.execute("DELETE FROM provenance_nonces WHERE nonce = ?", (nonce,))
            try:
                self._conn.execute(
                    "INSERT INTO provenance_nonces (nonce, consumed_at, expires_at) VALUES (?,?,?)",
                    (nonce, now, float(expires_at)),
                )
                self._conn.commit()
                return True
            except sqlite3.IntegrityError:
                # Lost the race against a concurrent writer - that *is* a replay.
                self._conn.rollback()
                return False

    def seen(self, nonce: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT expires_at FROM provenance_nonces WHERE nonce = ?", (nonce,)
            ).fetchone()
        return row is not None and float(row[0]) > utc_now()

    def purge(self, now: Optional[float] = None) -> int:
        cutoff = now if now is not None else utc_now()
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM provenance_nonces WHERE expires_at <= ?", (cutoff,)
            )
            self._conn.commit()
            return int(cursor.rowcount or 0)

    def count(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM provenance_nonces WHERE expires_at > ?", (utc_now(),)
            ).fetchone()
        return int(row[0]) if row else 0

    def clear(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM provenance_nonces")
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:  # pragma: no cover - already closed
                pass


class ReplayGuard:
    """Rejects any attestation nonce that has been presented before.

    Parameters
    ----------
    ttl_s:
        How long a consumed nonce is remembered.  Should be at least
        ``provenance.max_age_s + provenance.clock_skew_s``.
    backend:
        ``"memory"`` (default), ``"sqlite"``, or a ready-made
        :class:`ReplayGuardBackend` instance.
    sqlite_path:
        Database file when ``backend="sqlite"``.
    purge_interval_s:
        Minimum wall-clock gap between opportunistic garbage collections.
    """

    def __init__(
        self,
        *,
        ttl_s: float = 900.0,
        backend: Any = "memory",
        sqlite_path: str = "data/provenance-nonces.db",
        purge_interval_s: float = 60.0,
    ) -> None:
        self.ttl_s = max(1.0, float(ttl_s))
        self.purge_interval_s = max(1.0, float(purge_interval_s))
        self._backend = self._build_backend(backend, sqlite_path)
        self._lock = threading.Lock()
        self._last_purge = time.monotonic()
        self._consumed = 0
        self._rejected = 0

    @staticmethod
    def _build_backend(backend: Any, sqlite_path: str) -> ReplayGuardBackend:
        if isinstance(backend, ReplayGuardBackend):
            return backend
        kind = str(backend or "memory").lower()
        if kind in ("sqlite", "sqlite3", "file"):
            try:
                return SqliteReplayBackend(sqlite_path)
            except sqlite3.Error as exc:  # pragma: no cover - disk problems
                _LOG.warning("sqlite replay backend unavailable, falling back to memory: %s", exc)
                return MemoryReplayBackend()
        return MemoryReplayBackend()

    # ------------------------------------------------------------------ #
    # Hot path
    # ------------------------------------------------------------------ #
    def check_and_consume(self, nonce: str, issued_at: float = 0.0) -> bool:
        """Claim a nonce.

        Returns ``True`` when this is the first presentation (the caller may
        proceed) and ``False`` when the nonce has already been spent, which the
        verifier translates into ``ProvenanceStatus.REPLAYED``.

        An empty nonce is always rejected: an attestation without one carries no
        replay protection at all.
        """
        if not nonce:
            self._rejected += 1
            return False
        self._maybe_purge()
        base = issued_at if issued_at and issued_at > 0 else utc_now()
        expires_at = base + self.ttl_s
        if expires_at <= utc_now():
            # Already outside the retention window; nothing to remember, but the
            # expiry check downstream will reject it anyway.
            expires_at = utc_now() + 1.0
        ok = self._backend.consume(nonce, expires_at)
        with self._lock:
            if ok:
                self._consumed += 1
            else:
                self._rejected += 1
        return ok

    def seen(self, nonce: str) -> bool:
        """Non-destructive check - does not consume the nonce."""
        return bool(nonce) and self._backend.seen(nonce)

    @property
    def seen_count(self) -> int:
        """Number of live nonces currently retained by the backend."""
        return self._backend.count()

    # ------------------------------------------------------------------ #
    # Maintenance
    # ------------------------------------------------------------------ #
    def _maybe_purge(self) -> None:
        now = time.monotonic()
        with self._lock:
            if now - self._last_purge < self.purge_interval_s:
                return
            self._last_purge = now
        removed = self._backend.purge()
        if removed:
            _LOG.debug("purged expired nonces", fields={"removed": removed})

    def purge(self) -> int:
        """Force a garbage collection pass.  Returns entries removed."""
        return self._backend.purge()

    def reset(self) -> None:
        """Forget every nonce.  Intended for tests and break-glass recovery."""
        self._backend.clear()
        with self._lock:
            self._consumed = 0
            self._rejected = 0

    def close(self) -> None:
        """Release backend resources."""
        self._backend.close()

    def stats(self) -> Dict[str, Any]:
        """Counters for the metrics endpoint."""
        with self._lock:
            consumed, rejected = self._consumed, self._rejected
        total = consumed + rejected
        return {
            "backend": self._backend.name,
            "ttl_s": self.ttl_s,
            "live_nonces": self.seen_count,
            "consumed": consumed,
            "rejected": rejected,
            "replay_rate": round(rejected / total, 4) if total else 0.0,
        }
