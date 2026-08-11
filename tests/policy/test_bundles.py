"""Tests for bundle loading, merging and signing."""

from __future__ import annotations

import pytest

from aegis.core.crypto import build_signer
from aegis.policy import (
    BUILTIN_PACKS,
    builtin_bundles,
    builtin_pack_dir,
    load_builtin_bundles,
    load_bundle_file,
    merge_bundles,
    sign_bundle,
    verify_bundle,
    verify_bundle_detailed,
)
from tests.conftest import TEST_SIGNING_KEY


def _signer():
    return build_signer("hmac-sha256", TEST_SIGNING_KEY, "policy-bundle")


def test_builtin_pack_count() -> None:
    bundles = load_builtin_bundles()
    assert len(bundles) == len(BUILTIN_PACKS) == 8
    assert {b.id for b in bundles} == set(BUILTIN_PACKS)


def test_builtin_bundles_alias() -> None:
    assert builtin_bundles() == load_builtin_bundles()


def test_load_bundle_file_from_dir() -> None:
    bundle = load_bundle_file(builtin_pack_dir() / "baseline.yaml")
    assert bundle.id == "baseline"
    assert bundle.rule_count > 0


def test_unsigned_bundle_fails_required_verify() -> None:
    bundle = load_builtin_bundles(names=["baseline"])[0]
    ok, reason = verify_bundle_detailed(bundle, _signer(), required=True)
    assert ok is False
    assert "unsigned" in reason


def test_sign_and_verify_round_trip() -> None:
    bundle = load_builtin_bundles(names=["baseline"])[0]
    sign_bundle(bundle, _signer())
    assert bundle.is_signed
    assert verify_bundle(bundle, _signer()) is True


def test_merge_bundles_combines_rules() -> None:
    a = load_builtin_bundles(names=["baseline"])[0]
    b = load_builtin_bundles(names=["secrets"])[0]
    merged = merge_bundles([a, b])
    assert merged.rule_count == a.rule_count + b.rule_count
    assert "baseline" in merged.metadata["merged_from"]
