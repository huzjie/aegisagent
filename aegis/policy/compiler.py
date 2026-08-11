"""Compile authored policy bundles into an executable, indexed form.

Authoring format and evaluation format have different goals.  YAML is optimised
for humans: nested, forgiving, order-independent.  The evaluation path is
optimised for a p99 latency budget measured in microseconds, because it sits
directly in front of every tool call an agent makes.

The compiler bridges the two exactly once, at load time:

* every ``when`` / ``unless`` block becomes a :class:`~aegis.policy.conditions.Condition`
  tree with its regexes pre-compiled;
* every ``match`` block becomes a list of :class:`~aegis.policy.matchers.Matcher`
  objects;
* rules are bucketed into an **inverted index** keyed by tool name, so a call to
  ``github::create_pr`` only evaluates rules that could possibly apply to it
  instead of all several hundred.

It also front-loads every error.  A malformed rule raises
:class:`~aegis.core.errors.PolicyCompileError` naming the pack, rule id and
source line, at load time, rather than failing open at 3am on a call nobody is
watching.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from ..core.errors import PolicyCompileError
from ..core.logging import get_logger
from ..core.types import Effect, EvaluationContext, PolicyMatch
from ..core.utils import any_glob_match, glob_match
from .conditions import Condition, compile_condition, condition_fields, describe_condition
from .matchers import Matcher, build_matchers, describe_matchers, match_all
from .model import KNOWN_OBLIGATIONS, Policy, PolicyBundle, PolicyRule, validate_rule

__all__ = [
    "CompiledRule",
    "CompiledPolicy",
    "PolicyCompiler",
    "compile_bundles",
]

logger = get_logger(__name__)

#: Bucket key for rules whose tool patterns contain a wildcard.
_WILDCARD_BUCKET = "*"


# --------------------------------------------------------------------------- #
# Compiled rule
# --------------------------------------------------------------------------- #
@dataclass
class CompiledRule:
    """An authored rule with everything expensive already done."""

    rule: PolicyRule
    policy_id: str = ""
    condition: Optional[Condition] = None
    unless: Optional[Condition] = None
    matchers: List[Matcher] = field(default_factory=list)
    effect: Effect = Effect.OBSERVE
    priority: int = 0
    #: Literal (wildcard-free) tool patterns, used to build the inverted index.
    literal_tools: List[str] = field(default_factory=list)
    #: True when the rule can apply to any tool and must always be considered.
    is_wildcard: bool = False

    @property
    def id(self) -> str:
        return self.rule.id

    @property
    def source(self) -> str:
        return self.rule.source

    def evaluate(self, ctx: EvaluationContext) -> bool:
        """Return True when this rule fires for ``ctx``.

        Order matters for latency: the cheap structural matchers run first, the
        condition tree second and the (rarer) ``unless`` escape last.
        """
        if not match_all(self.matchers, ctx):
            return False
        if self.condition is not None and not self.condition.evaluate(ctx):
            return False
        if self.unless is not None and self.unless.evaluate(ctx):
            return False
        return True

    def to_match(self, ctx: Optional[EvaluationContext] = None) -> PolicyMatch:
        """Build the :class:`PolicyMatch` recorded on the decision."""
        return PolicyMatch(
            rule_id=self.rule.id,
            policy_id=self.policy_id,
            effect=self.effect,
            priority=self.priority,
            reason=self.rule.description or self.describe(),
            matched_on=self.matched_on(),
            obligations=dict(self.rule.obligations or {}),
        )

    def matched_on(self) -> List[str]:
        """The discriminators that make this rule explainable in a UI."""
        parts: List[str] = []
        if self.matchers:
            parts.append(describe_matchers(self.matchers))
        if self.condition is not None:
            parts.append(describe_condition(self.condition))
        if self.unless is not None:
            parts.append(f"unless {describe_condition(self.unless)}")
        return parts

    def describe(self) -> str:
        """Full human-readable rendering of the rule's logic."""
        return " AND ".join(self.matched_on()) or "any call"

    def fields(self) -> List[str]:
        """Every context field this rule reads - drives coverage analysis."""
        return sorted(set(condition_fields(self.condition) + condition_fields(self.unless)))


# --------------------------------------------------------------------------- #
# Compiled policy set
# --------------------------------------------------------------------------- #
@dataclass
class CompiledPolicy:
    """The full, indexed rule set the engine evaluates against."""

    rules: List[CompiledRule] = field(default_factory=list)
    defaults: Dict[str, Any] = field(default_factory=dict)
    version: str = "0.0.0"
    bundle_ids: List[str] = field(default_factory=list)
    policy_ids: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    compiled_at: float = field(default_factory=time.time)
    compile_ms: float = 0.0
    #: tool name -> rules mentioning it literally; ``*`` holds the rest.
    index: Dict[str, List[CompiledRule]] = field(default_factory=dict)

    @property
    def rule_count(self) -> int:
        return len(self.rules)

    @property
    def default_effect(self) -> Optional[Effect]:
        """Effect declared by ``defaults.effect`` across the loaded packs."""
        raw = self.defaults.get("effect")
        if not raw:
            return None
        try:
            return Effect(str(raw).strip().lower())
        except ValueError:
            return None

    def candidates(self, qualified_name: str, bare_name: str = "") -> List[CompiledRule]:
        """Rules that could match this tool, in evaluation order.

        This is the hot path.  Two dict lookups plus the wildcard bucket beats
        scanning every rule, and the result is deterministic: sorted by
        descending priority then rule id so explanations are stable.
        """
        seen: Set[int] = set()
        out: List[CompiledRule] = []
        for key in (qualified_name, bare_name or qualified_name.split("::")[-1]):
            for rule in self.index.get(key, ()):
                if id(rule) not in seen:
                    seen.add(id(rule))
                    out.append(rule)
        for rule in self.index.get(_WILDCARD_BUCKET, ()):
            if id(rule) not in seen:
                seen.add(id(rule))
                out.append(rule)
        return out

    def rule(self, rule_id: str) -> Optional[CompiledRule]:
        """Look up a compiled rule by id."""
        for candidate in self.rules:
            if candidate.rule.id == rule_id:
                return candidate
        return None

    def stats(self) -> Dict[str, Any]:
        """Compilation statistics, surfaced by the ``/healthz`` endpoint."""
        by_effect: Dict[str, int] = {}
        for rule in self.rules:
            by_effect[rule.effect.value] = by_effect.get(rule.effect.value, 0) + 1
        return {
            "rules": len(self.rules),
            "policies": len(self.policy_ids),
            "bundles": len(self.bundle_ids),
            "version": self.version,
            "indexed_tools": len([k for k in self.index if k != _WILDCARD_BUCKET]),
            "wildcard_rules": len(self.index.get(_WILDCARD_BUCKET, [])),
            "by_effect": by_effect,
            "warnings": len(self.warnings),
            "compile_ms": round(self.compile_ms, 3),
        }

    def covered_tools(self) -> List[str]:
        """Every tool name literally named by at least one rule."""
        return sorted(k for k in self.index if k != _WILDCARD_BUCKET)


# --------------------------------------------------------------------------- #
# Compiler
# --------------------------------------------------------------------------- #
class PolicyCompiler:
    """Turns :class:`PolicyBundle` objects into a :class:`CompiledPolicy`.

    Parameters
    ----------
    strict:
        When True (the default for production loads) any validation problem is
        fatal.  When False, broken rules are skipped and recorded as warnings so
        one bad pack cannot take the whole gateway offline - useful for the
        ``aegis policy lint`` command and for hot reload, where the previously
        good policy stays active.
    """

    def __init__(self, *, strict: bool = True) -> None:
        self.strict = strict
        self.warnings: List[str] = []

    # -- public API ------------------------------------------------------- #
    def compile(self, bundles: Sequence[PolicyBundle]) -> CompiledPolicy:
        """Compile every policy in every bundle into one indexed rule set."""
        started = time.perf_counter()
        self.warnings = []

        compiled: List[CompiledRule] = []
        defaults: Dict[str, Any] = {}
        bundle_ids: List[str] = []
        policy_ids: List[str] = []
        seen_rule_ids: Dict[str, str] = {}

        for bundle in bundles or []:
            bundle_ids.append(bundle.id)
            for policy in bundle.policies:
                policy_ids.append(policy.id)
                defaults.update(policy.defaults or {})
                for rule in policy.enabled_rules:
                    origin = f"{policy.id}/{rule.id}"
                    if rule.id in seen_rule_ids and seen_rule_ids[rule.id] != policy.id:
                        self._problem(
                            f"duplicate rule id {rule.id!r} in policies "
                            f"{seen_rule_ids[rule.id]!r} and {policy.id!r}",
                            rule=rule,
                            policy=policy,
                        )
                        continue
                    seen_rule_ids[rule.id] = policy.id
                    built = self._compile_rule(rule, policy)
                    if built is not None:
                        compiled.append(built)
                    else:
                        logger.warning("policy.rule_skipped", extra={"rule": origin})

        compiled.sort(key=lambda r: (-r.priority, r.policy_id, r.rule.id))
        result = CompiledPolicy(
            rules=compiled,
            defaults=defaults,
            version=self._derive_version(bundles),
            bundle_ids=bundle_ids,
            policy_ids=policy_ids,
            warnings=list(self.warnings),
            compile_ms=(time.perf_counter() - started) * 1000.0,
            index=self._build_index(compiled),
        )
        logger.info("policy.compiled", extra=result.stats())
        return result

    # -- rule compilation ------------------------------------------------- #
    def _compile_rule(self, rule: PolicyRule, policy: Policy) -> Optional[CompiledRule]:
        """Compile one rule, or return None when it is broken and non-strict."""
        problems = validate_rule(rule)
        # Unknown-obligation notices are advisory: they must not block a load.
        fatal = [p for p in problems if "unknown obligation key" not in p]
        for advisory in (p for p in problems if p not in fatal):
            self.warnings.append(self._locate(advisory, rule, policy))
        if fatal:
            self._problem("; ".join(fatal), rule=rule, policy=policy)
            return None

        try:
            condition = (
                compile_condition(rule.when, path=f"{rule.id}.when")
                if rule.when is not None
                else None
            )
            unless = (
                compile_condition(rule.unless, path=f"{rule.id}.unless")
                if rule.unless is not None
                else None
            )
        except PolicyCompileError as exc:
            self._problem(exc.message, rule=rule, policy=policy, details=exc.details)
            return None

        matchers = build_matchers(rule.match.to_dict())
        self._warn_unused_match_keys(rule, policy)

        tool_patterns = list(rule.match.tools or [])
        literal = [p for p in tool_patterns if not _has_wildcard(p)]
        is_wildcard = (not tool_patterns) or any(_has_wildcard(p) for p in tool_patterns)

        return CompiledRule(
            rule=rule,
            policy_id=policy.id,
            condition=condition,
            unless=unless,
            matchers=matchers,
            effect=rule.effect_enum,
            priority=rule.priority,
            literal_tools=literal,
            is_wildcard=is_wildcard,
        )

    def _warn_unused_match_keys(self, rule: PolicyRule, policy: Policy) -> None:
        """Flag obligations the effects layer will pass through untouched."""
        unknown = sorted(set(rule.obligations or {}) - KNOWN_OBLIGATIONS - {"override"})
        for key in unknown:
            self.warnings.append(
                self._locate(f"obligation {key!r} is not interpreted by any effect", rule, policy)
            )

    # -- indexing --------------------------------------------------------- #
    def _build_index(self, rules: Sequence[CompiledRule]) -> Dict[str, List[CompiledRule]]:
        """Bucket rules by the literal tool names they name.

        A rule with wildcard patterns (or no ``match.tools`` at all) goes into
        the wildcard bucket, which every lookup also scans.  Literal names give
        the big win: in a typical deployment most rules name concrete tools.
        """
        index: Dict[str, List[CompiledRule]] = {_WILDCARD_BUCKET: []}
        for rule in rules:
            if rule.is_wildcard:
                index[_WILDCARD_BUCKET].append(rule)
            for name in rule.literal_tools:
                index.setdefault(name, []).append(rule)
                # Also index the bare tool name so "github::create_pr" in a
                # policy is found by a lookup on either form.
                bare = name.split("::")[-1]
                if bare != name:
                    index.setdefault(bare, []).append(rule)
        return index

    # -- diagnostics ------------------------------------------------------ #
    def _problem(
        self,
        message: str,
        *,
        rule: PolicyRule,
        policy: Policy,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Raise in strict mode, otherwise record a warning and continue."""
        located = self._locate(message, rule, policy)
        if self.strict:
            raise PolicyCompileError(
                located,
                details={
                    "rule_id": rule.id,
                    "policy_id": policy.id,
                    "source": rule.source,
                    "line": rule.line,
                    **(details or {}),
                },
            )
        self.warnings.append(located)

    @staticmethod
    def _locate(message: str, rule: PolicyRule, policy: Policy) -> str:
        """Prefix a message with pack / rule / line so authors can find it."""
        where = rule.source or policy.source or policy.id or "<memory>"
        line = f":{rule.line}" if rule.line else ""
        return f"{where}{line} [{policy.id}/{rule.id or '<no id>'}] {message}"

    @staticmethod
    def _derive_version(bundles: Sequence[PolicyBundle]) -> str:
        """A stable, human-meaningful version for the whole loaded set."""
        versions = [b.version for b in bundles or [] if b.version and b.version != "0.0.0"]
        if not versions:
            return "0.0.0"
        if len(versions) == 1:
            return versions[0]
        return "+".join(sorted(set(versions)))


def compile_bundles(
    bundles: Sequence[PolicyBundle],
    *,
    strict: bool = True,
) -> CompiledPolicy:
    """Convenience wrapper around :class:`PolicyCompiler`."""
    return PolicyCompiler(strict=strict).compile(bundles)


def _has_wildcard(pattern: str) -> bool:
    """True when a tool pattern needs glob evaluation rather than a dict hit."""
    return any(ch in str(pattern) for ch in "*?[")
