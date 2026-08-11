"""Tests for the declarative policy model."""

from __future__ import annotations

import pytest

from aegis.core.types import Effect
from aegis.policy.model import (
    Policy,
    PolicyBundle,
    PolicyRule,
    RuleMatch,
    merge_defaults,
    validate_bundle,
    validate_rule,
)


def test_rule_round_trip() -> None:
    rule = PolicyRule(
        id="r1",
        description="deny dangerous tool",
        priority=500,
        effect="deny",
        when={"all": [{"field": "call.tool", "op": "eq", "value": "shell.exec"}]},
    )
    data = rule.to_dict()
    rebuilt = PolicyRule.from_dict(data)
    assert rebuilt.id == "r1"
    assert rebuilt.effect_enum == Effect.DENY
    assert rebuilt.when == rule.when


def test_validate_rule_missing_id() -> None:
    problems = validate_rule(PolicyRule(effect="allow", description="x", priority=1))
    assert any("id" in p for p in problems)


def test_validate_rule_unknown_effect() -> None:
    rule = PolicyRule(
        id="r",
        description="x",
        priority=1,
        effect="explode",
        when={"all": [{"field": "call.tool", "op": "eq", "value": "t"}]},
    )
    assert any("unknown effect" in p for p in validate_rule(rule))


def test_validate_rule_needs_when_or_match() -> None:
    rule = PolicyRule(id="r", description="x", priority=1, effect="allow")
    assert any("neither 'when' nor 'match'" in p for p in validate_rule(rule))


def test_bundle_from_dict_wraps_bare_rules() -> None:
    bundle = PolicyBundle.from_dict(
        {
            "id": "p1",
            "version": "1.0.0",
            "rules": [{"id": "r1", "description": "d", "priority": 1, "effect": "observe"}],
        }
    )
    assert bundle.policy("p1") is not None
    assert bundle.rule_count == 1


def test_validate_bundle_detects_cross_policy_rule_collision() -> None:
    policy_a = Policy(id="a", rules=[PolicyRule(id="dup", description="d", priority=1, effect="observe")])
    policy_b = Policy(id="b", rules=[PolicyRule(id="dup", description="d", priority=1, effect="observe")])
    bundle = PolicyBundle(policies=[policy_a, policy_b])
    problems = validate_bundle(bundle)
    assert any("dup" in p for p in problems)


def test_merge_defaults_last_wins() -> None:
    policies = [
        Policy(id="a", defaults={"effect": "observe"}),
        Policy(id="b", defaults={"effect": "deny"}),
    ]
    assert merge_defaults(policies)["effect"] == "deny"
