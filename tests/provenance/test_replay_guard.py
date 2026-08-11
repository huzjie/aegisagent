"""Tests for the attestation nonce replay guard."""

from __future__ import annotations

import pytest

from aegis.provenance import ReplayGuard
from aegis.provenance.replay_guard import (
    MemoryReplayBackend,
    SqliteReplayBackend,
)


def test_nonce_is_single_use() -> None:
    guard = ReplayGuard(ttl_s=60)
    assert guard.check_and_consume("n1", issued_at=1000.0) is True
    assert guard.check_and_consume("n1", issued_at=1000.0) is False


def test_empty_nonce_rejected() -> None:
    guard = ReplayGuard()
    assert guard.check_and_consume("", issued_at=1000.0) is False
    assert guard.seen_count == 0


def test_seen_count_tracks_live_nonces() -> None:
    guard = ReplayGuard(ttl_s=60)
    guard.check_and_consume("a", issued_at=1000.0)
    guard.check_and_consume("b", issued_at=1000.0)
    assert guard.seen_count == 2
    # Re-consuming 'a' does not increase the live count.
    guard.check_and_consume("a", issued_at=1001.0)
    assert guard.seen_count == 2


def test_sqlite_backend_single_use(tmp_path) -> None:
    backend = SqliteReplayBackend(str(tmp_path / "nonces.db"))
    assert backend.consume("x", expires_at=9999.0) is True
    assert backend.consume("x", expires_at=9999.0) is False
    assert backend.count() == 1


def test_purge_removes_expired(tmp_path) -> None:
    backend = SqliteReplayBackend(str(tmp_path / "nonces.db"))
    backend.consume("old", expires_at=10.0)
    assert backend.purge(now=100.0) >= 1
    assert backend.count() == 0
