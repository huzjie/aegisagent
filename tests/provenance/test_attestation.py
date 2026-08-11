"""Tests for attestation token codec and argument hashing."""

from __future__ import annotations

import pytest

from aegis.core.crypto import build_signer
from aegis.provenance.attestation import (
    ATTESTATION_TYPE,
    Attestation,
    args_hash_of,
    attestation_subject,
    decode_attestation,
    encode_attestation,
    hash_arguments,
)


def test_args_hash_is_stable_and_order_independent() -> None:
    a = hash_arguments({"b": 2, "a": 1})
    b = hash_arguments({"a": 1, "b": 2})
    assert a == b
    assert hash_arguments(None) == hash_arguments({})
    assert args_hash_of is hash_arguments


def test_json_string_arguments_normalised() -> None:
    # OpenAI style serialises arguments to a string.
    as_dict = hash_arguments({"cmd": "ls"})
    as_str = hash_arguments('{"cmd": "ls"}')
    assert as_dict == as_str


def test_encode_decode_round_trip() -> None:
    signer = build_signer("hmac-sha256", "k", "default")
    att = Attestation(
        issuer="aegis-gateway",
        session_id="ses1",
        completion_id="cmp1",
        tool="shell.exec",
        args_hash=hash_arguments({"cmd": "ls"}),
    )
    token = encode_attestation(att, signer)
    claims, signature = decode_attestation(token)
    assert claims["header"]["typ"] == ATTESTATION_TYPE
    assert claims["payload"]["cid"] == "cmp1"
    assert claims["payload"]["tool"] == "shell.exec"
    assert signer.verify(claims["signing_input"], signature)


def test_subject_round_trip_preserves_fields() -> None:
    att = Attestation(tool="shell.exec", completion_id="cmp1", agent_id="agt1")
    subject = attestation_subject(att)
    rebuilt = Attestation.from_subject(subject)
    assert rebuilt.tool == "shell.exec"
    assert rebuilt.completion_id == "cmp1"
    assert rebuilt.agent_id == "agt1"


def test_decode_rejects_garbage() -> None:
    with pytest.raises(Exception):
        decode_attestation("not-a-token")
