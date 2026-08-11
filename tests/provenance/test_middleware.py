"""Tests for the provenance enforcement middleware."""

from __future__ import annotations

import pytest

from aegis.core.errors import ForgedToolCallError
from aegis.core.types import ProvenanceStatus
from aegis.provenance import ProvenanceMiddleware, ProvenanceVerifier, SessionLedger
from tests.conftest import TEST_SIGNING_KEY, make_call


def _middleware(mode: str) -> ProvenanceMiddleware:
    verifier = ProvenanceVerifier(signing_key=TEST_SIGNING_KEY, ledger=SessionLedger())
    return ProvenanceMiddleware(verifier, mode=mode)


def test_enforce_blocks_unsigned_call() -> None:
    guard = _middleware("enforce")
    call = make_call(tool="shell.exec", args={"cmd": "ls"})
    with pytest.raises(ForgedToolCallError):
        guard(call)


def test_monitor_does_not_block() -> None:
    guard = _middleware("monitor")
    call = make_call(tool="shell.exec", args={"cmd": "ls"})
    record = guard(call)
    assert record.status == ProvenanceStatus.UNSIGNED


def test_off_mode_returns_record() -> None:
    guard = _middleware("off")
    record = guard(make_call(tool="shell.exec", args={"cmd": "ls"}))
    assert record.status == ProvenanceStatus.MISSING


def test_allows_returns_bool() -> None:
    guard = _middleware("monitor")
    assert guard.allows(make_call(tool="shell.exec", args={"cmd": "ls"})) is False


def test_invalid_mode_rejected() -> None:
    verifier = ProvenanceVerifier(signing_key=TEST_SIGNING_KEY, ledger=SessionLedger())
    with pytest.raises(ValueError):
        ProvenanceMiddleware(verifier, mode="bogus")
