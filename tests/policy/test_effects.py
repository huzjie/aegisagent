"""Tests for effect arbitration and obligation merging."""

from __future__ import annotations

from aegis.core.types import Effect, PolicyMatch
from aegis.policy.effects import (
    EffectResolution,
    REDACTION_MASK,
    apply_redactions,
    merge_obligations,
    resolve,
    resolve_effect,
)


def _match(effect: Effect, priority: int = 0, obligations=None) -> PolicyMatch:
    return PolicyMatch(
        rule_id=f"r{priority}",
        policy_id="p",
        effect=effect,
        priority=priority,
        obligations=obligations or {},
    )


def test_most_restrictive_wins() -> None:
    effect = resolve_effect([_match(Effect.ALLOW), _match(Effect.DENY), _match(Effect.OBSERVE)])
    assert effect == Effect.DENY


def test_deny_beats_allow() -> None:
    assert Effect.most_restrictive([Effect.ALLOW, Effect.REQUIRE_APPROVAL]) == Effect.REQUIRE_APPROVAL


def test_merge_obligations_union_and_min() -> None:
    obligations = merge_obligations(
        [
            _match(Effect.REDACT, obligations={"redact": ["a.b"]}),
            _match(Effect.REDACT, obligations={"redact": ["a.c"], "throttle": {"per_minute": 10}}),
            _match(Effect.REDACT, obligations={"throttle": {"per_minute": 5}}),
        ]
    )
    assert set(obligations["redact"]) == {"a.b", "a.c"}
    assert obligations["throttle"]["per_minute"] == 5  # tightest wins


def test_merge_obligations_or_and_severity() -> None:
    obligations = merge_obligations(
        [
            _match(Effect.DENY, obligations={"incident": False, "severity": "low"}),
            _match(Effect.DENY, obligations={"incident": True, "severity": "critical"}),
        ]
    )
    assert obligations["incident"] is True
    assert obligations["severity"] == "critical"


def test_apply_redactions_masks_paths() -> None:
    payload = {"a": {"b": "secret", "c": "ok"}, "token": "x"}
    redacted, applied = apply_redactions(payload, ["a.b", "token"])
    assert redacted["a"]["b"] == REDACTION_MASK
    assert redacted["a"]["c"] == "ok"
    assert "token" in applied
    # original untouched
    assert payload["a"]["b"] == "secret"


def test_resolve_empty_uses_default() -> None:
    resolution = resolve([], default=Effect.REQUIRE_APPROVAL)
    assert resolution.effect == Effect.REQUIRE_APPROVAL
    assert resolution.blocks_execution  # require_approval blocks execution
    assert resolution.reason


def test_resolve_override_relaxes_effect() -> None:
    matches = [
        _match(Effect.DENY, priority=10),
        _match(Effect.ALLOW, priority=1, obligations={"override": True}),
    ]
    resolution = resolve(matches)
    assert resolution.effect == Effect.ALLOW
    assert resolution.overridden_by is not None
