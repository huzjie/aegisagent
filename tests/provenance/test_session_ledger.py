"""Tests for the append-only, hash-chained session ledger."""

from __future__ import annotations

import pytest

from aegis.provenance import LedgerEntry, SessionLedger
from aegis.core.crypto import chain_hash
from tests.conftest import make_call, make_completion


def test_record_and_lookup_completion() -> None:
    ledger = SessionLedger()
    comp = make_completion(cid="cmp1", sid="ses1")
    ledger.record_completion(comp)
    assert ledger.get_completion("cmp1") is comp
    assert ledger.get_completion("nope") is None


def test_hash_chain_is_integrable_and_verifies() -> None:
    ledger = SessionLedger()
    comp = make_completion(cid="cmp1", sid="ses1")
    ledger.record_completion(comp)
    call = make_call(sid="ses1")
    ledger.record_call(call)
    ok, problems = ledger.verify_chain("ses1")
    assert ok
    assert problems == []


def test_tampering_breaks_the_chain() -> None:
    ledger = SessionLedger()
    comp = make_completion(cid="cmp1", sid="ses1")
    ledger.record_completion(comp)
    entries = ledger.entries("ses1")
    # Mutate the payload of the recorded completion in place.
    entries[0]["payload"]["completion_id"] = "tampered"
    ok, problems = ledger.verify_chain("ses1")
    assert not ok
    assert any("tampered" not in p and ("broken link" in p or "payload tampered" in p) for p in problems)


def test_quarantine_round_trip() -> None:
    ledger = SessionLedger()
    ledger.record_completion(make_completion(cid="c1", sid="ses1"))
    assert not ledger.is_quarantined("ses1")
    ledger.quarantine("ses1", reason="breach")
    assert ledger.is_quarantined("ses1")
    assert ledger.release("ses1")
    assert not ledger.is_quarantined("ses1")


def test_counters_reflect_recorded_activity() -> None:
    ledger = SessionLedger()
    ledger.record_completion(make_completion(cid="c1", sid="ses1"))
    ledger.record_call(make_call(sid="ses1"))
    counters = ledger.counters("ses1")
    assert counters["completions"] == 1
    assert counters["calls"] == 1


def test_verify_chain_empty_session_is_ok() -> None:
    ledger = SessionLedger()
    ok, problems = ledger.verify_chain("unknown")
    assert ok
    assert problems == []


def test_persisted_ledger_reloads(tmp_path) -> None:
    path = tmp_path / "sessions.jsonl"
    ledger = SessionLedger(persist_path=str(path))
    ledger.record_completion(make_completion(cid="c1", sid="s1"))
    assert path.exists()
    # A fresh ledger with the same path replays persisted entries.
    reloaded = SessionLedger(persist_path=str(path))
    assert reloaded.get_completion("c1") is not None
