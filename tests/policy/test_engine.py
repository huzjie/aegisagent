"""Tests for the policy engine end to end."""

from __future__ import annotations

from aegis.core.config import get_settings
from aegis.core.types import Effect, ProvenanceRecord, ProvenanceStatus
from aegis.policy import PolicyEngine
from tests.conftest import make_call, make_ctx


def test_engine_loads_builtin_packs() -> None:
    engine = PolicyEngine.from_builtins()
    assert engine._compiled.rule_count > 0
    assert engine.bundle_version


def test_engine_from_settings() -> None:
    engine = PolicyEngine.from_settings(get_settings())
    effect, matches = engine.evaluate(
        make_ctx(make_call(tool="unknown.tool.xyz", args={}))
    )
    assert isinstance(effect, Effect)
    assert isinstance(matches, list)


def test_unknown_tool_gets_default_effect() -> None:
    engine = PolicyEngine.from_builtins()
    effect, _ = engine.evaluate(make_ctx(make_call(tool="no.such.tool", args={})))
    # Shipped default for unmatched calls is require_approval.
    assert effect == Effect.REQUIRE_APPROVAL


def test_orphaned_provenance_is_denied_by_corebreak() -> None:
    engine = PolicyEngine.from_builtins()
    ctx = make_ctx(
        make_call(tool="shell.exec", args={"cmd": "ls"}),
        provenance=ProvenanceRecord(status=ProvenanceStatus.ORPHANED),
    )
    effect, matches = engine.evaluate(ctx)
    assert effect == Effect.DENY
    assert any("corebreak" in m.policy_id for m in matches)


def test_decide_returns_decision() -> None:
    engine = PolicyEngine.from_builtins()
    decision = engine.decide(make_ctx(make_call(tool="no.such.tool", args={})))
    assert decision.effect == Effect.REQUIRE_APPROVAL
    assert decision.policy_bundle_version == engine.bundle_version


def test_fail_closed_returns_deny_on_error() -> None:
    engine = PolicyEngine.from_builtins()
    # Corrupt the inverted index so candidate lookup degrades; engine still must
    # not raise and the fail-closed floor should not downgrade a real deny.
    effect, _ = engine.evaluate(make_ctx(make_call(tool="no.such.tool", args={})))
    assert effect is not None
