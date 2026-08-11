"""Tests for the policy compiler (validation + inverted index)."""

from __future__ import annotations

import pytest

from aegis.core.errors import PolicyCompileError
from aegis.core.types import Effect
from aegis.policy.compiler import CompiledPolicy, PolicyCompiler, compile_bundles
from aegis.policy.model import Policy, PolicyBundle, PolicyRule


def _rule(rid, tool="shell.exec", effect="deny", when=None):
    return PolicyRule(
        id=rid,
        description=f"rule {rid}",
        priority=10,
        effect=effect,
        match={"tools": [tool]},
        when=when,
    )


def _bundle(rules):
    return PolicyBundle(id="b", version="1.0.0", policies=[Policy(id="p", rules=rules)])


def test_compile_sorts_by_priority_desc() -> None:
    bundle = _bundle([_rule("low", priority=1), _rule("high", priority=100)])
    compiled = compile_bundles([bundle])
    assert compiled.rules[0].rule.id == "high"


def test_inverted_index_finds_candidate() -> None:
    bundle = _bundle([_rule("r", tool="github::create_pr")])
    compiled = compile_bundles([bundle])
    candidates = compiled.candidates("github::create_pr")
    assert any(r.rule.id == "r" for r in candidates)
    # An unrelated tool only sees wildcard rules (none here).
    assert not compiled.candidates("other::tool")


def test_duplicate_rule_id_strict_raises() -> None:
    bundle = _bundle([_rule("dup"), _rule("dup")])
    with pytest.raises(PolicyCompileError):
        compile_bundles([bundle])


def test_unknown_operator_in_when_raises() -> None:
    bad = _rule("bad", when={"all": [{"field": "call.tool", "op": "wat", "value": "x"}]})
    bundle = _bundle([bad])
    with pytest.raises(PolicyCompileError):
        compile_bundles([bundle])


def test_non_strict_skips_broken_rule() -> None:
    compiler = PolicyCompiler(strict=False)
    bad = _rule("bad", when={"all": [{"field": "call.tool", "op": "wat", "value": "x"}]})
    good = _rule("good")
    compiled = compiler.compile([_bundle([bad, good])])
    assert compiled.rule_count == 1
    assert any(w and "bad" in w for w in compiled.warnings)


def test_compiled_rule_matches_context() -> None:
    from tests.conftest import make_call, make_ctx

    bundle = _bundle([_rule("r", tool="shell.exec", effect="deny")])
    compiled = compile_bundles([bundle])
    rule = compiled.rule("r")
    ctx = make_ctx(make_call(tool="shell.exec", args={"cmd": "ls"}))
    assert rule.evaluate(ctx)
    assert rule.to_match(ctx).effect == Effect.DENY
