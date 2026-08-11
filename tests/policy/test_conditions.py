"""Tests for the condition DSL and field resolution."""

from __future__ import annotations

import pytest

from aegis.core.errors import PolicyCompileError
from aegis.core.types import ProvenanceStatus
from aegis.policy.conditions import (
    Condition,
    compile_condition,
    resolve_field,
)
from aegis.core.types import ProvenanceRecord
from tests.conftest import make_call, make_ctx


def _ctx(**overrides):
    call = make_call(tool="shell.exec", args={"cmd": "ls", "host": "10.0.0.5"})
    base = dict(
        risk="high",
        risk_score=80.0,
        environment="production",
        provenance=ProvenanceRecord(status=ProvenanceStatus.ORPHANED),
    )
    base.update(overrides)
    return make_ctx(call, **base)


def test_leaf_eq_and_ne() -> None:
    cond = compile_condition({"field": "call.tool", "op": "eq", "value": "shell.exec"})
    assert cond.evaluate(_ctx())
    cond2 = compile_condition({"field": "call.tool", "op": "ne", "value": "shell.exec"})
    assert not cond2.evaluate(_ctx())


def test_args_alias_resolves_to_call_arguments() -> None:
    ctx = _ctx()
    assert resolve_field(ctx, "args.cmd") == "ls"
    assert resolve_field(ctx, "call.arguments.host") == "10.0.0.5"


def test_all_any_not() -> None:
    data = {
        "all": [
            {"field": "call.tool", "op": "eq", "value": "shell.exec"},
            {"any": [
                {"field": "args.cmd", "op": "eq", "value": "ls"},
                {"field": "args.cmd", "op": "eq", "value": "pwd"},
            ]},
        ]
    }
    cond = compile_condition(data)
    assert cond.evaluate(_ctx())
    not_cond = compile_condition({"not": data})
    assert not not_cond.evaluate(_ctx())


def test_operators_in_contains_cidr_glob_exists() -> None:
    assert compile_condition({"field": "call.tool", "op": "in", "value": ["a", "shell.exec"]}).evaluate(_ctx())
    assert compile_condition({"field": "args.cmd", "op": "contains", "value": "ls"}).evaluate(_ctx())
    assert compile_condition({"field": "args.host", "op": "cidr", "value": "10.0.0.0/24"}).evaluate(_ctx())
    assert compile_condition({"field": "args.cmd", "op": "glob", "value": "l*"}).evaluate(_ctx())
    assert compile_condition({"field": "args.missing", "op": "exists", "value": False}).evaluate(_ctx())
    assert compile_condition({"field": "args.cmd", "op": "exists"}).evaluate(_ctx())


def test_risk_numeric_comparison() -> None:
    cond = compile_condition({"field": "risk", "op": "gte", "value": "high"})
    assert cond.evaluate(_ctx())


def test_unknown_operator_raises() -> None:
    with pytest.raises(PolicyCompileError):
        compile_condition({"field": "call.tool", "op": "bogus", "value": "x"})


def test_missing_field_in_leaf_raises() -> None:
    with pytest.raises(PolicyCompileError):
        compile_condition({"op": "eq", "value": "x"})


def test_provenance_status_field() -> None:
    cond = compile_condition(
        {"field": "provenance.status", "op": "eq", "value": "orphaned"}
    )
    assert cond.evaluate(_ctx())
