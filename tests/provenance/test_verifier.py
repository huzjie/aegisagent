"""Tests for the provenance verifier - every step of the CoreBreak ladder."""

from __future__ import annotations

import pytest

from aegis.core.crypto import build_signer
from aegis.core.types import ProvenanceRecord, ProvenanceStatus
from aegis.provenance import ProvenanceBinder, ProvenanceVerifier, SessionLedger
from aegis.provenance.attestation import (
    Attestation,
    encode_attestation,
    hash_arguments,
)
from tests.conftest import TEST_SIGNING_KEY, make_call, make_completion


@pytest.fixture
def ledger_binder():
    ledger = SessionLedger()
    binder = ProvenanceBinder(signing_key=TEST_SIGNING_KEY, ledger=ledger)
    return ledger, binder


def test_unsigned_when_no_attestation_required() -> None:
    verifier = ProvenanceVerifier(signing_key=TEST_SIGNING_KEY, require_attestation=True)
    call = make_call(tool="shell.exec", args={"cmd": "ls"})
    assert verifier.verify(call).status == ProvenanceStatus.UNSIGNED


def test_orphaned_for_fabricated_completion_id() -> None:
    # A forged call naming a completion that never ran, with attestation off.
    verifier = ProvenanceVerifier(
        signing_key=TEST_SIGNING_KEY, require_attestation=False, ledger=SessionLedger()
    )
    call = make_call(
        tool="shell.exec", args={"cmd": "ls"}, completion_id="completion-that-never-ran"
    )
    record = verifier.verify(call)
    assert record.status == ProvenanceStatus.ORPHANED


def test_verified_round_trip(ledger_binder) -> None:
    ledger, binder = ledger_binder
    comp = make_completion(tool="shell.exec", args={"cmd": "ls"})
    binder.bind_completion(comp)
    token = binder.issue_for_completion(comp)[0]
    call = make_call(
        tool="shell.exec", args={"cmd": "ls"}, completion_id=comp.id, attestation=token
    )
    verifier = ProvenanceVerifier(signing_key=TEST_SIGNING_KEY, ledger=ledger)
    assert verifier.verify(call).status == ProvenanceStatus.VERIFIED


def test_forged_garbage_token() -> None:
    ledger, _ = ledger_binder
    verifier = ProvenanceVerifier(signing_key=TEST_SIGNING_KEY, ledger=ledger)
    call = make_call(tool="shell.exec", args={"cmd": "ls"}, attestation="garbage.token.here")
    assert verifier.verify(call).status == ProvenanceStatus.FORGED


def test_mismatched_arguments(ledger_binder) -> None:
    ledger, binder = ledger_binder
    comp = make_completion(tool="shell.exec", args={"cmd": "ls"})
    binder.bind_completion(comp)
    token = binder.issue_for_completion(comp)[0]
    # Dispatch with different arguments than the model authorised.
    call = make_call(
        tool="shell.exec", args={"cmd": "rm -rf /"}, completion_id=comp.id, attestation=token
    )
    assert verifier(ledger).verify(call).status == ProvenanceStatus.MISMATCHED


def verifier(ledger) -> ProvenanceVerifier:  # local helper
    return ProvenanceVerifier(signing_key=TEST_SIGNING_KEY, ledger=ledger)


def test_replayed_nonce(ledger_binder) -> None:
    ledger, binder = ledger_binder
    comp = make_completion(tool="shell.exec", args={"cmd": "ls"})
    binder.bind_completion(comp)
    token = binder.issue_for_completion(comp)[0]
    v = verifier(ledger)
    call = make_call(
        tool="shell.exec", args={"cmd": "ls"}, completion_id=comp.id, attestation=token
    )
    assert v.verify(call).status == ProvenanceStatus.VERIFIED
    assert v.verify(call).status == ProvenanceStatus.REPLAYED


def test_expired_token(ledger_binder) -> None:
    ledger, binder = ledger_binder
    comp = make_completion(tool="shell.exec", args={"cmd": "ls"})
    binder.bind_completion(comp)
    signer = build_signer("hmac-sha256", TEST_SIGNING_KEY, "default")
    att = Attestation(
        issuer="aegis-gateway",
        session_id="ses1",
        completion_id=comp.id,
        tool="shell.exec",
        args_hash=hash_arguments({"cmd": "ls"}),
        issued_at=1.0,
        expires_at=2.0,
    )
    token = encode_attestation(att, signer)
    call = make_call(
        tool="shell.exec", args={"cmd": "ls"}, completion_id=comp.id, attestation=token
    )
    v = ProvenanceVerifier(signing_key=TEST_SIGNING_KEY, ledger=ledger, max_age_s=300)
    assert v.verify(call).status == ProvenanceStatus.EXPIRED


def test_untrusted_issuer(ledger_binder) -> None:
    ledger, binder = ledger_binder
    comp = make_completion(tool="shell.exec", args={"cmd": "ls"})
    binder.bind_completion(comp)
    signer = build_signer("hmac-sha256", TEST_SIGNING_KEY, "default")
    att = Attestation(
        issuer="evil-ca",
        session_id="ses1",
        completion_id=comp.id,
        tool="shell.exec",
        args_hash=hash_arguments({"cmd": "ls"}),
    )
    token = encode_attestation(att, signer)
    call = make_call(
        tool="shell.exec", args={"cmd": "ls"}, completion_id=comp.id, attestation=token
    )
    v = ProvenanceVerifier(
        signing_key=TEST_SIGNING_KEY, ledger=ledger, trusted_issuers=["aegis-gateway"]
    )
    assert v.verify(call).status == ProvenanceStatus.UNTRUSTED_ISSUER


def test_mode_off_bypasses_to_verified() -> None:
    v = ProvenanceVerifier(signing_key=TEST_SIGNING_KEY, mode="off")
    call = make_call(tool="shell.exec", args={"cmd": "ls"})
    record = v.verify(call)
    assert record.status == ProvenanceStatus.VERIFIED


def test_quarantined_session_is_annotated(ledger_binder) -> None:
    ledger, binder = ledger_binder
    ledger.record_completion(make_completion(cid="c1", sid="ses1"))
    ledger.quarantine("ses1")
    v = ProvenanceVerifier(signing_key=TEST_SIGNING_KEY, ledger=ledger)
    call = make_call(tool="shell.exec", args={"cmd": "ls"}, sid="ses1")
    record = v.verify(call)
    assert any("quarantined" in reason.lower() for reason in record.reasons)


def test_verify_batch_preserves_order(ledger_binder) -> None:
    ledger, _ = ledger_binder
    calls = [
        make_call(tool="shell.exec", args={"cmd": "a"}),
        make_call(tool="shell.exec", args={"cmd": "b"}),
    ]
    v = ProvenanceVerifier(signing_key=TEST_SIGNING_KEY, ledger=ledger)
    records = v.verify_batch(calls)
    assert [r.status for r in records] == [ProvenanceStatus.UNSIGNED, ProvenanceStatus.UNSIGNED]
