"""Tests for the attestation binder (issue / bind flow)."""

from __future__ import annotations

import pytest

from aegis.core.errors import ValidationError
from aegis.provenance import ProvenanceBinder, SessionLedger
from aegis.provenance.attestation import decode_attestation
from tests.conftest import TEST_SIGNING_KEY, make_call, make_completion


@pytest.fixture
def bound():
    ledger = SessionLedger()
    binder = ProvenanceBinder(signing_key=TEST_SIGNING_KEY, ledger=ledger)
    comp = make_completion(tool="shell.exec", args={"cmd": "ls"})
    binder.bind_completion(comp)
    return binder, ledger, comp


def test_bind_records_completion_in_ledger(bound) -> None:
    binder, ledger, comp = bound
    assert ledger.get_completion(comp.id) is not None
    assert binder.is_bound(comp.id)
    assert "shell.exec" in binder.bound_tools(comp.id)


def test_issue_for_completion_returns_one_token_per_call(bound) -> None:
    binder, ledger, comp = bound
    tokens = binder.issue_for_completion(comp)
    assert len(tokens) == 1
    claims, _ = decode_attestation(tokens[0])
    assert claims["payload"]["tool"] == "shell.exec"


def test_issue_refuses_unknown_tool(bound) -> None:
    binder, ledger, comp = bound
    with pytest.raises(ValidationError):
        binder.issue(comp.id, "shell.unknown", {"cmd": "x"})


def test_issue_refuses_args_mismatch(bound) -> None:
    binder, ledger, comp = bound
    with pytest.raises(ValidationError):
        binder.issue(comp.id, "shell.exec", {"cmd": "rm -rf /"})


def test_issue_unknown_completion_raises(bound) -> None:
    binder, ledger, comp = bound
    with pytest.raises(ValidationError):
        binder.issue("does-not-exist", "shell.exec", {"cmd": "ls"})


def test_attach_stamps_call_with_token(bound) -> None:
    binder, ledger, comp = bound
    call = make_call(tool="shell.exec", args={"cmd": "ls"}, completion_id=comp.id)
    binder.attach(call)
    assert call.attestation
    claims, _ = decode_attestation(call.attestation)
    assert claims["payload"]["cid"] == comp.id
