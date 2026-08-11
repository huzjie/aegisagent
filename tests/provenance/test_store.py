"""Tests for provenance verdict persistence (in-memory and sqlite)."""

from __future__ import annotations

import pytest

from aegis.core.types import ProvenanceRecord, ProvenanceStatus
from aegis.provenance import (
    InMemoryProvenanceStore,
    SQLiteProvenanceStore,
    record_to_row,
    row_to_record,
)
from tests.conftest import make_call


def _record(status: ProvenanceStatus, call_id: str = "tc1") -> ProvenanceRecord:
    return ProvenanceRecord(
        call_id=call_id,
        status=status,
        completion_id="cmp1",
        reasons=[f"{status.value} reason"],
    )


@pytest.mark.parametrize("store_factory", [InMemoryProvenanceStore, lambda: SQLiteProvenanceStore(":memory:")])
def test_put_get_and_status_queries(store_factory) -> None:
    store = store_factory()
    store.put(_record(ProvenanceStatus.ORPHANED, "a"))
    store.put(_record(ProvenanceStatus.VERIFIED, "b"))
    assert store.get("a").status == ProvenanceStatus.ORPHANED
    assert len(store.list_by_status(ProvenanceStatus.ORPHANED)) == 1
    assert len(store.failures()) == 1
    assert store.counts_by_status().get("orphaned") == 1
    assert store.count() == 2


@pytest.mark.parametrize("store_factory", [InMemoryProvenanceStore, lambda: SQLiteProvenanceStore(":memory:")])
def test_row_round_trip(store_factory) -> None:
    record = _record(ProvenanceStatus.FORGED, "x")
    row = record_to_row(record, session_id="s1", tenant_id="t1", tool="shell.exec")
    back = row_to_record(row)
    assert back.status == ProvenanceStatus.FORGED
    assert back.call_id == "x"
    assert back.reasons == record.reasons


def test_in_memory_prunes_old_records() -> None:
    store = InMemoryProvenanceStore()
    store.put(_record(ProvenanceStatus.ORPHANED, "old"))
    removed = store.prune(older_than_s=0.0)
    assert removed == 1
    assert store.count() == 0
