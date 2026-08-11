"""Tests for the policy pack catalogue (CLI / API metadata)."""

from __future__ import annotations

from aegis.policy import PolicyPackInfo, list_packs


def test_list_packs_returns_all_builtins() -> None:
    packs = list_packs()
    ids = {p.id for p in packs}
    assert {"baseline", "corebreak", "secrets", "destructive"} <= ids
    assert len(packs) == 8


def test_each_pack_has_rules_and_version() -> None:
    for pack in list_packs():
        assert pack.rules > 0
        assert pack.version
        assert pack.health in ("ok", "unsigned", "empty")


def test_pack_info_to_dict() -> None:
    pack = list_packs(names=["baseline"])[0]
    data = pack.to_dict()
    assert data["id"] == "baseline"
    assert data["rules"] == pack.rules
    assert "restrictive_rules" in data


def test_policy_pack_info_dataclass() -> None:
    info = PolicyPackInfo(
        id="x", name="X", version="1.0.0", description="d", rules=3, path="p"
    )
    assert info.short_id == "x"
    assert info.is_restrictive is False
    info.restrictive_rules = 1
    assert info.is_restrictive is True
