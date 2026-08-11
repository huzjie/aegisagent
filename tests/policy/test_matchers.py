"""Tests for the structural matchers (cheap pre-filter)."""

from __future__ import annotations

from aegis.core.types import (
    ActionCategory,
    ProvenanceRecord,
    ProvenanceStatus,
    RiskLevel,
)
from aegis.policy.matchers import (
    ArgumentMatcher,
    CidrMatcher,
    CategoryMatcher,
    EnvironmentMatcher,
    ProvenanceMatcher,
    RiskMatcher,
    ToolMatcher,
    build_matchers,
    match_all,
    match_any,
)
from tests.conftest import make_call, make_ctx


def _ctx(tool="github::create_pr", risk="high", categories=None, provenance=None):
    call = make_call(tool=tool, args={"repo": "org/repo"})
    return make_ctx(
        call,
        risk=RiskLevel(risk),
        categories=categories or [],
        provenance=provenance,
    )


def test_tool_matcher_glob_and_exclude() -> None:
    m = ToolMatcher(patterns=["github::create_pr"])
    assert m.matches(_ctx("github::create_pr"))
    assert not m.matches(_ctx("github::delete_repo"))
    ex = ToolMatcher(patterns=["github::*"], exclude=["github::delete_repo"])
    assert ex.matches(_ctx("github::create_pr"))
    assert not ex.matches(_ctx("github::delete_repo"))


def test_category_matcher() -> None:
    m = CategoryMatcher(categories=["write", "execute"], mode="any")
    ctx = _ctx(categories=[ActionCategory.READ, ActionCategory.WRITE])
    assert m.matches(ctx)
    none = CategoryMatcher(categories=["destructive"], mode="none")
    assert none.matches(ctx)


def test_argument_matcher_path_and_ops() -> None:
    ctx = _ctx()
    assert ArgumentMatcher(path="args.repo", op="exists").matches(ctx)
    assert ArgumentMatcher(path="args.repo", op="equals", value="org/repo").matches(ctx)
    assert ArgumentMatcher(path="args.repo", op="startswith", value="org/").matches(ctx)
    assert not ArgumentMatcher(path="args.repo", op="equals", value="x/y").matches(ctx)


def test_risk_matcher_band() -> None:
    assert RiskMatcher(min_level="high").matches(_ctx(risk="high"))
    assert not RiskMatcher(min_level="critical").matches(_ctx(risk="high"))


def test_provenance_matcher_require_verified() -> None:
    good = _ctx(provenance=ProvenanceRecord(status=ProvenanceStatus.VERIFIED))
    bad = _ctx(provenance=ProvenanceRecord(status=ProvenanceStatus.ORPHANED))
    m = ProvenanceMatcher(require_verified=True)
    assert not m.matches(good)   # verified => should NOT fire
    assert m.matches(bad)


def test_environment_matcher() -> None:
    m = EnvironmentMatcher(environments=["production"])
    assert m.matches(_ctx())
    assert not EnvironmentMatcher(environments=["dev"]).matches(_ctx())


def test_cidr_matcher() -> None:
    from tests.conftest import make_call as mc

    call = mc(tool="http.get", args={}, caller_ip="192.168.1.50")
    ctx = make_ctx(call)
    assert CidrMatcher(networks=["192.168.1.0/24"]).matches(ctx)
    assert not CidrMatcher(networks=["10.0.0.0/8"]).matches(ctx)


def test_build_matchers_and_combinators() -> None:
    matchers = build_matchers({"tools": ["github::create_pr"]})
    assert match_all(matchers, _ctx("github::create_pr"))
    assert match_any([], _ctx()) is False
    assert match_all([], _ctx()) is True
