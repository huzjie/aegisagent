"""Pre-flight analysis tools for policy authors.

These functions never touch production traffic.  They exist so an operator can
answer three questions *before* shipping a policy change:

* **what_if** - "if I deploy this bundle, what would it do to this call?"
* **replay** - "what changed between the policy I had and the one I'm shipping?"
* **coverage** - "which tools does this bundle actually govern, and which are
  silently ungoverned?"

All three are read-only and side-effect free.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from ..core.types import Decision, Effect, EvaluationContext
from .compiler import CompiledPolicy, PolicyCompiler
from .engine import PolicyEngine
from .effects import merge_obligations
from .model import PolicyBundle

__all__ = [
    "ChangeType",
    "DiffReport",
    "CoverageReport",
    "WhatIfResult",
    "PolicySimulator",
    "what_if",
    "replay",
    "coverage",
]


def _compile(bundle: Any) -> CompiledPolicy:
    """Compile one bundle, a sequence of bundles, or an already-compiled policy."""
    if isinstance(bundle, CompiledPolicy):
        return bundle
    bundles = list(bundle) if isinstance(bundle, (list, tuple)) else [bundle]
    return PolicyCompiler().compile([b for b in bundles if isinstance(b, PolicyBundle)])


def _engine_for(bundle: Any) -> PolicyEngine:
    """A throwaway engine over ``bundle``, with caching and reload disabled."""
    compiled = _compile(bundle)
    return PolicyEngine(
        compiled,
        default_effect=compiled.default_effect,
        hot_reload=False,
        cache_size=0,
        name="simulator",
    )


@dataclass
class WhatIfResult:
    """Outcome of dry-running a single context against a bundle."""

    effect: Effect
    matched_rules: List[str]
    obligations: Dict[str, Any]
    default_effect: Effect
    reason: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "effect": self.effect.value,
            "matched_rules": self.matched_rules,
            "obligations": self.obligations,
            "default_effect": self.default_effect.value,
            "reason": self.reason,
        }


def what_if(ctx: EvaluationContext, bundle: Any) -> WhatIfResult:
    """Evaluate ``ctx`` against ``bundle`` without affecting live state.

    A throwaway engine is compiled from the bundle on each call, so ``what_if``
    is safe to run against a candidate pack that has never been deployed.
    """
    engine = _engine_for(bundle)
    resolution = engine.resolve(ctx)
    return WhatIfResult(
        effect=resolution.effect,
        matched_rules=resolution.rule_ids,
        obligations=merge_obligations(resolution.contributing),
        default_effect=engine.default_effect,
        reason=resolution.reason,
    )


# --------------------------------------------------------------------------- #
# Replay / diff
# --------------------------------------------------------------------------- #
class ChangeType:
    """Categories of behavioural change between two policy versions."""

    NEW_BLOCK = "new_block"          # now denied / quarantined / requires approval
    NEW_ALLOW = "new_allow"          # now allowed (was blocked or approval)
    EFFECT_CHANGED = "effect_changed"  # still matched, different terminal effect
    UNCHANGED = "unchanged"


@dataclass
class DiffReport:
    """Comparison of decisions under an old vs a new bundle."""

    total: int = 0
    new_blocks: List[str] = field(default_factory=list)
    new_allows: List[str] = field(default_factory=list)
    effect_changes: List[Dict[str, Any]] = field(default_factory=list)
    unchanged: int = 0

    @property
    def has_blocking_regressions(self) -> bool:
        """True when a previously-allowed call became blocked."""
        return bool(self.new_blocks)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "new_blocks": self.new_blocks,
            "new_allows": self.new_allows,
            "effect_changes": self.effect_changes,
            "unchanged": self.unchanged,
        }


def replay(decisions: Sequence[Decision], new_bundle: Any) -> DiffReport:
    """Re-evaluate prior decisions against ``new_bundle`` and report the deltas.

    ``decisions`` are the historical :class:`~aegis.core.types.Decision` objects
    captured by the live engine.  Each is re-evaluated against the candidate
    bundle and compared with its originally recorded effect.
    """
    report = DiffReport()
    engine = _engine_for(new_bundle)

    for decision in decisions:
        # Live decisions carry no context object, so rebuild the parts policy
        # actually reads from the audit record.
        ctx = _context_from_decision(decision)
        new_effect, _ = engine.evaluate(ctx)
        old_effect = decision.effect
        report.total += 1
        if new_effect == old_effect:
            report.unchanged += 1
            continue
        entry = {
            "call_id": decision.call_id,
            "tool": _tool_of(decision),
            "old_effect": old_effect.value,
            "new_effect": new_effect.value,
        }
        if old_effect.blocks_execution and not new_effect.blocks_execution:
            report.new_allows.append(decision.call_id)
            entry["change"] = ChangeType.NEW_ALLOW
        elif not old_effect.blocks_execution and new_effect.blocks_execution:
            report.new_blocks.append(decision.call_id)
            entry["change"] = ChangeType.NEW_BLOCK
        else:
            entry["change"] = ChangeType.EFFECT_CHANGED
        report.effect_changes.append(entry)
    return report


# --------------------------------------------------------------------------- #
# Coverage
# --------------------------------------------------------------------------- #
@dataclass
class CoverageReport:
    """Which tools in a catalog are governed by a bundle, and which are not."""

    total_tools: int = 0
    covered: List[str] = field(default_factory=list)
    uncovered: List[str] = field(default_factory=list)
    rules_by_tool: Dict[str, int] = field(default_factory=dict)
    global_rules: int = 0

    @property
    def coverage_rate(self) -> float:
        if not self.total_tools:
            return 0.0
        return round(len(self.covered) / self.total_tools, 4)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "total_tools": self.total_tools,
            "covered": self.covered,
            "uncovered": self.uncovered,
            "rules_by_tool": self.rules_by_tool,
            "global_rules": self.global_rules,
            "coverage_rate": self.coverage_rate,
        }


def coverage(bundle: Any, tool_catalog: Any) -> CoverageReport:
    """Compute how thoroughly ``bundle`` governs the tools in ``tool_catalog``.

    A tool is "covered" when at least one rule's tool matcher globs it (or when a
    global rule exists that would apply regardless).  Tools with no governing
    rule are the gaps an attacker would probe first.
    """
    from .matchers import ToolMatcher

    compiled = _compile(bundle)
    report = CoverageReport()

    if hasattr(tool_catalog, "all"):
        tools = list(tool_catalog.all())
    elif isinstance(tool_catalog, (list, tuple)):
        tools = list(tool_catalog)
    else:
        tools = list(getattr(tool_catalog, "tools", []) or [])

    report.total_tools = len(tools)
    for rule in compiled.rules:
        tool_matchers = [m for m in rule.matchers if isinstance(m, ToolMatcher)]
        if not tool_matchers:
            report.global_rules += 1
            continue
        for tool in tools:
            qn = getattr(tool, "qualified_name", str(tool))
            for matcher in tool_matchers:
                if matcher.covers(qn):
                    if qn not in report.rules_by_tool:
                        report.rules_by_tool[qn] = 0
                    report.rules_by_tool[qn] += 1
                    if qn not in report.covered:
                        report.covered.append(qn)

    covered_set = set(report.covered)
    if report.global_rules and tools:
        # A global rule effectively covers everything.
        report.covered = [getattr(t, "qualified_name", str(t)) for t in tools]
        covered_set = set(report.covered)
        report.rules_by_tool = {qn: report.rules_by_tool.get(qn, report.global_rules) for qn in covered_set}
    report.uncovered = [
        getattr(t, "qualified_name", str(t)) for t in tools if getattr(t, "qualified_name", str(t)) not in covered_set
    ]
    return report


# --------------------------------------------------------------------------- #
# Decision -> context reconstruction
# --------------------------------------------------------------------------- #
def _context_from_decision(decision: Decision) -> EvaluationContext:
    from ..core.types import AgentIdentity, SessionRef, ToolCall

    call = getattr(decision, "call", None)
    if call is None:
        # A persisted Decision keeps ids, not the payload.  Replay is still
        # useful: provenance, risk and category rules all evaluate correctly;
        # only tool-name matchers degrade, which the caller can avoid by
        # attaching the original ToolCall as ``decision.call``.
        call = ToolCall(
            id=decision.call_id,
            tool=str(getattr(decision, "tool", "") or ""),
            session_id=decision.session_id,
            agent_id=decision.agent_id,
            tenant_id=decision.tenant_id,
        )
    ctx = EvaluationContext(
        call=call,
        agent=AgentIdentity(id=decision.agent_id),
        session=SessionRef(id=decision.session_id, agent_id=decision.agent_id),
        risk=decision.risk,
        risk_score=decision.risk_score,
        categories=list(decision.categories),
        provenance=decision.provenance,
        findings=list(decision.findings),
    )
    return ctx


def _tool_of(decision: Decision) -> str:
    call = getattr(decision, "call", None)
    if call is not None:
        return getattr(call, "qualified_name", getattr(call, "tool", "")) or "unknown"
    return str(getattr(decision, "tool", "") or "unknown")


# --------------------------------------------------------------------------- #
# Object façade (matches the contract's PolicySimulator surface)
# --------------------------------------------------------------------------- #
class PolicySimulator:
    """Stateful convenience wrapper over the :mod:`aegis.policy.simulator` API.

    The module-level functions are the canonical, side-effect-free entry points;
    this class simply binds a bundle so repeated ``what_if`` / ``replay`` /
    ``coverage`` calls do not recompile on every invocation.

    Example
    -------
    >>> sim = PolicySimulator(bundle)
    >>> result = sim.what_if(ctx)
    >>> diff = sim.replay(decisions, new_bundle)
    """

    def __init__(self, bundle: Any) -> None:
        self._bundle = bundle
        self._engine = _engine_for(bundle)

    def what_if(self, ctx: EvaluationContext) -> WhatIfResult:
        """Dry-run a single context against the bound bundle."""
        return what_if(ctx, self._bundle)

    def replay(
        self, decisions: Sequence[Decision], new_bundle: Any
    ) -> "DiffReport":
        """Diff an existing decision stream against a candidate bundle."""
        return replay(decisions, new_bundle)

    def coverage(self, tool_catalog: Any) -> "CoverageReport":
        """Report which tools the bound bundle actually governs."""
        return coverage(self._bundle, tool_catalog)

    @property
    def bundle(self) -> Any:
        """The bundle this simulator is bound to."""
        return self._bundle
