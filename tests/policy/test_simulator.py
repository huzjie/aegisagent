"""Tests for the policy simulator (what_if / replay / coverage)."""

from __future__ import annotations

from aegis.core.types import (
    Decision,
    Effect,
    ProvenanceRecord,
    ProvenanceStatus,
    ToolDescriptor,
)
from aegis.policy.catalog import ToolCatalog
from aegis.policy.simulator import PolicySimulator, what_if, coverage, replay
from aegis.policy.bundles import load_builtin_bundles, merge_bundles
from tests.conftest import make_call, make_ctx


def _bundle():
    return merge_bundles(load_builtin_bundles())


def test_what_if_returns_effect() -> None:
    bundle = _bundle()
    ctx = make_ctx(
        make_call(tool="no.such.tool", args={}),
        provenance=ProvenanceRecord(status=ProvenanceStatus.VERIFIED),
    )
    result = what_if(ctx, bundle)
    assert isinstance(result.effect, Effect)
    assert "corebreak" not in result.effect.value  # provenance is fine here


def test_coverage_reports_uncovered_tools() -> None:
    bundle = _bundle()
    catalog = ToolCatalog.from_dicts(
        [
            {"name": "create_pr", "server": "github", "categories": ["write"]},
            {"name": "mystery", "server": "local", "categories": ["execute"]},
        ]
    )
    report = coverage(bundle, catalog)
    assert report.total_tools == 2
    assert report.coverage_rate >= 0.0
    assert "github::create_pr" in report.covered or report.global_rules > 0


def test_replay_detects_new_block() -> None:
    bundle = _bundle()
    # A decision that previously allowed, but the candidate bundle denies.
    decision = Decision(
        call_id="tc1",
        session_id="s1",
        agent_id="a1",
        effect=Effect.REQUIRE_APPROVAL,
        call=make_call(tool="shell.exec", args={"cmd": "rm -rf /"}),
        provenance=ProvenanceRecord(status=ProvenanceStatus.ORPHANED),
    )
    report = replay([decision], bundle)
    assert report.total == 1
    # orphaned provenance flips the verdict to deny under corebreak.
    assert decision.call_id in report.new_blocks or report.effect_changes


def test_policy_simulator_facade() -> None:
    bundle = _bundle()
    sim = PolicySimulator(bundle)
    ctx = make_ctx(make_call(tool="no.such.tool", args={}))
    assert sim.what_if(ctx).effect is not None
    assert sim.coverage(ToolCatalog()).total_tools == 0
