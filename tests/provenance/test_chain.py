"""Tests for sub-agent delegation chains (ProvenanceChain)."""

from __future__ import annotations

import pytest

from aegis.core.crypto import build_signer
from aegis.core.errors import ProvenanceError
from aegis.core.types import ProvenanceStatus
from aegis.provenance import ProvenanceChain, SessionLedger
from aegis.provenance.attestation import Attestation, encode_attestation, hash_arguments
from tests.conftest import TEST_SIGNING_KEY, make_completion


def _root_token(tool: str, *, ledger: SessionLedger):
    comp = make_completion(cid="cmp-root", sid="ses1", tool=tool, args={"target": "svc"})
    ledger.record_completion(comp)
    signer = build_signer("hmac-sha256", TEST_SIGNING_KEY, "default")
    att = Attestation(
        issuer="aegis-gateway",
        session_id="ses1",
        completion_id=comp.id,
        agent_id="agent-a",
        tool=tool,
        args_hash=hash_arguments({"target": "svc"}),
    )
    return encode_attestation(att, signer), ledger


def test_delegate_narrows_scope_and_verifies() -> None:
    ledger = SessionLedger()
    root, ledger = _root_token("deploy::rollout", ledger=ledger)
    chain = ProvenanceChain(signing_key=TEST_SIGNING_KEY, ledger=ledger)
    child = chain.delegate(root, "agent-b", ["deploy::rollout"])
    assert chain.chain_ok(child)
    records = chain.verify_chain(child)
    assert records[0].status == ProvenanceStatus.VERIFIED


def test_scope_escalation_is_rejected() -> None:
    ledger = SessionLedger()
    root, ledger = _root_token("deploy::rollout", ledger=ledger)
    chain = ProvenanceChain(signing_key=TEST_SIGNING_KEY, ledger=ledger)
    with pytest.raises(ProvenanceError):
        chain.delegate(root, "agent-b", ["delete::everything"])


def test_authorizes_respects_effective_scope() -> None:
    ledger = SessionLedger()
    root, ledger = _root_token("deploy::rollout", ledger=ledger)
    chain = ProvenanceChain(signing_key=TEST_SIGNING_KEY, ledger=ledger)
    child = chain.delegate(root, "agent-b", ["deploy::rollout"])
    assert chain.authorizes(child, "deploy::rollout")
    assert not chain.authorizes(child, "deploy::other")


def test_orphaned_root_is_reported() -> None:
    ledger = SessionLedger()  # completion never recorded
    signer = build_signer("hmac-sha256", TEST_SIGNING_KEY, "default")
    att = Attestation(
        issuer="aegis-gateway", completion_id="missing", tool="deploy::rollout"
    )
    root = encode_attestation(att, signer)
    chain = ProvenanceChain(signing_key=TEST_SIGNING_KEY, ledger=ledger)
    records = chain.verify_chain(root)
    assert records[0].status == ProvenanceStatus.ORPHANED
