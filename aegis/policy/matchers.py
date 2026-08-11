"""Structural matchers - the cheap pre-filter in front of the condition DSL.

A production gateway loads several hundred rules but evaluates one tool call at
a time.  Running every rule's condition tree against every call is wasteful and,
worse, makes latency depend on policy size - which is exactly the pressure that
leads teams to disable policies.

Matchers exist to make the common discriminators (tool name, category, agent
trust tier, environment, source IP, time of day) *indexable and O(1)-ish*, so
the condition DSL only runs for rules that are plausibly relevant.

Each matcher answers a single yes/no question about an
:class:`~aegis.core.types.EvaluationContext` and can explain itself.
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from ..core.types import ActionCategory, EvaluationContext, RiskLevel
from ..core.utils import any_glob_match, glob_match, safe_get

__all__ = [
    "Matcher",
    "ToolMatcher",
    "ArgumentMatcher",
    "CategoryMatcher",
    "RiskMatcher",
    "AgentMatcher",
    "TimeWindowMatcher",
    "CidrMatcher",
    "EnvironmentMatcher",
    "ProvenanceMatcher",
    "match_any",
    "match_all",
    "build_matchers",
]

WEEKDAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


class Matcher:
    """Base class: a named predicate over an evaluation context."""

    kind = "matcher"

    def matches(self, ctx: EvaluationContext) -> bool:
        """Evaluate the predicate.  Implementations must never raise."""
        raise NotImplementedError  # pragma: no cover - interface

    def describe(self) -> str:
        """Human-readable form used in explanations and the policy UI."""
        return self.kind

    def __call__(self, ctx: EvaluationContext) -> bool:
        return self.matches(ctx)

    def __str__(self) -> str:  # pragma: no cover - convenience
        return self.describe()


# --------------------------------------------------------------------------- #
# Tool identity
# --------------------------------------------------------------------------- #
@dataclass
class ToolMatcher(Matcher):
    """Glob match on ``server::tool``, with an optional exclusion list.

    Patterns are tried against the qualified name (``github::create_pr``), the
    bare tool name (``create_pr``) and the server alone, so authors can write
    whichever is clearest without memorising a convention.
    """

    kind = "tool"
    patterns: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)
    servers: List[str] = field(default_factory=list)

    def matches(self, ctx: EvaluationContext) -> bool:
        call = ctx.call
        qualified = call.qualified_name
        bare = call.tool
        if self.servers and not any_glob_match(call.server, self.servers):
            return False
        if self.exclude and (
            any_glob_match(qualified, self.exclude) or any_glob_match(bare, self.exclude)
        ):
            return False
        if not self.patterns:
            return True
        return any_glob_match(qualified, self.patterns) or any_glob_match(bare, self.patterns)

    def covers(self, qualified_name: str) -> bool:
        """Static check used by coverage analysis - no context required."""
        if self.exclude and any_glob_match(qualified_name, self.exclude):
            return False
        if not self.patterns:
            return True
        bare = qualified_name.split("::")[-1]
        return any_glob_match(qualified_name, self.patterns) or any_glob_match(
            bare, self.patterns
        )

    def describe(self) -> str:
        parts = [f"tool in {self.patterns or ['*']}"]
        if self.servers:
            parts.append(f"server in {self.servers}")
        if self.exclude:
            parts.append(f"tool not in {self.exclude}")
        return " and ".join(parts)


# --------------------------------------------------------------------------- #
# Arguments (jsonpath-lite)
# --------------------------------------------------------------------------- #
@dataclass
class ArgumentMatcher(Matcher):
    """Inspect one tool argument by dotted path.

    Path syntax is deliberately minimal - ``args.a.b.0.c`` - covering nested
    mappings and list indices.  It is *not* JSONPath: no filters, no wildcards,
    no recursive descent.  A policy language that can express arbitrary queries
    over untrusted input is an attack surface of its own.
    """

    kind = "argument"
    path: str = ""
    op: str = "exists"
    value: Any = None
    case_sensitive: bool = False

    _OPS = (
        "equals",
        "not_equals",
        "contains",
        "regex",
        "gt",
        "lt",
        "in",
        "exists",
        "startswith",
        "endswith",
    )

    def resolve(self, ctx: EvaluationContext) -> Any:
        """Pull the referenced argument out of the call, or ``None``."""
        path = self.path
        for prefix in ("args.", "arguments.", "call.arguments."):
            if path.startswith(prefix):
                path = path[len(prefix):]
                break
        return safe_get(ctx.call.arguments or {}, path) if path else ctx.call.arguments

    def matches(self, ctx: EvaluationContext) -> bool:
        resolved = self.resolve(ctx)
        op = (self.op or "exists").lower()

        if op == "exists":
            want = True if self.value is None else bool(self.value)
            return (resolved is not None) is want
        if resolved is None:
            return False

        left = self._fold(resolved)
        right = self._fold(self.value)

        if op == "equals":
            return left == right
        if op == "not_equals":
            return left != right
        if op == "contains":
            return self._contains(left, right)
        if op == "startswith":
            return isinstance(left, str) and left.startswith(str(right))
        if op == "endswith":
            return isinstance(left, str) and left.endswith(str(right))
        if op == "in":
            options = right if isinstance(right, (list, tuple, set)) else [right]
            return left in options
        if op == "regex":
            import re

            try:
                flags = 0 if self.case_sensitive else re.IGNORECASE
                return bool(re.search(str(self.value), str(resolved), flags | re.DOTALL))
            except re.error:
                return False
        if op in ("gt", "lt"):
            try:
                a, b = float(resolved), float(self.value)
            except (TypeError, ValueError):
                return False
            return a > b if op == "gt" else a < b
        return False

    def _fold(self, value: Any) -> Any:
        if not self.case_sensitive and isinstance(value, str):
            return value.lower()
        if not self.case_sensitive and isinstance(value, list):
            return [v.lower() if isinstance(v, str) else v for v in value]
        return value

    @staticmethod
    def _contains(haystack: Any, needle: Any) -> bool:
        if isinstance(haystack, str):
            return str(needle) in haystack
        if isinstance(haystack, (list, tuple, set, dict)):
            return needle in haystack
        return False

    def describe(self) -> str:
        return f"{self.path} {self.op} {self.value!r}"


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #
@dataclass
class CategoryMatcher(Matcher):
    """Match on the action categories assigned to a call by classification."""

    kind = "category"
    categories: List[str] = field(default_factory=list)
    mode: str = "any"        # any | all | none

    def matches(self, ctx: EvaluationContext) -> bool:
        if not self.categories:
            return True
        present = {c.value for c in ctx.categories}
        if ctx.descriptor is not None:
            present |= {c.value for c in (ctx.descriptor.categories or [])}
        wanted = {str(c).strip().lower() for c in self.categories}
        if self.mode == "all":
            return wanted.issubset(present)
        if self.mode == "none":
            return not (wanted & present)
        return bool(wanted & present)

    def describe(self) -> str:
        return f"categories {self.mode} of {sorted(self.categories)}"

    @staticmethod
    def normalise(values: Iterable[str]) -> List[ActionCategory]:
        """Coerce strings to :class:`ActionCategory`, dropping unknown names."""
        out: List[ActionCategory] = []
        for value in values or []:
            try:
                out.append(ActionCategory(str(value).strip().lower()))
            except ValueError:
                continue
        return out


@dataclass
class RiskMatcher(Matcher):
    """Match calls at or above (optionally below) a risk band."""

    kind = "risk"
    min_level: str = "low"
    max_level: str = ""

    def matches(self, ctx: EvaluationContext) -> bool:
        score = ctx.risk.score if isinstance(ctx.risk, RiskLevel) else 0
        if self.min_level:
            floor = self._score(self.min_level)
            if floor is not None and score < floor:
                return False
        if self.max_level:
            ceiling = self._score(self.max_level)
            if ceiling is not None and score > ceiling:
                return False
        return True

    @staticmethod
    def _score(level: str) -> Optional[int]:
        try:
            return RiskLevel(str(level).strip().lower()).score
        except ValueError:
            return None

    def describe(self) -> str:
        upper = f" and <= {self.max_level}" if self.max_level else ""
        return f"risk >= {self.min_level}{upper}"


# --------------------------------------------------------------------------- #
# Identity
# --------------------------------------------------------------------------- #
@dataclass
class AgentMatcher(Matcher):
    """Match on agent identity, trust tier, permission profile or labels."""

    kind = "agent"
    ids: List[str] = field(default_factory=list)
    names: List[str] = field(default_factory=list)
    trust_tiers: List[str] = field(default_factory=list)
    profiles: List[str] = field(default_factory=list)
    labels: Dict[str, str] = field(default_factory=dict)
    exclude_ids: List[str] = field(default_factory=list)

    def matches(self, ctx: EvaluationContext) -> bool:
        agent = ctx.agent
        if self.exclude_ids and any_glob_match(agent.id, self.exclude_ids):
            return False
        if self.ids and not any_glob_match(agent.id, self.ids):
            return False
        if self.names and not any_glob_match(agent.name, self.names):
            return False
        if self.trust_tiers and agent.trust_tier not in self.trust_tiers:
            return False
        if self.profiles and agent.permission_profile not in self.profiles:
            return False
        for key, expected in (self.labels or {}).items():
            if not glob_match(str(agent.labels.get(key, "")), str(expected)):
                return False
        return True

    def describe(self) -> str:
        parts: List[str] = []
        if self.ids:
            parts.append(f"agent.id in {self.ids}")
        if self.names:
            parts.append(f"agent.name in {self.names}")
        if self.trust_tiers:
            parts.append(f"agent.trust_tier in {self.trust_tiers}")
        if self.profiles:
            parts.append(f"agent.profile in {self.profiles}")
        if self.labels:
            parts.append(f"agent.labels ~ {self.labels}")
        return " and ".join(parts) or "any agent"


@dataclass
class EnvironmentMatcher(Matcher):
    """Match on deployment environment and tenant."""

    kind = "environment"
    environments: List[str] = field(default_factory=list)
    tenants: List[str] = field(default_factory=list)

    def matches(self, ctx: EvaluationContext) -> bool:
        if self.environments and not any_glob_match(ctx.environment, self.environments):
            return False
        if self.tenants and not any_glob_match(ctx.call.tenant_id, self.tenants):
            return False
        return True

    def describe(self) -> str:
        parts = []
        if self.environments:
            parts.append(f"environment in {self.environments}")
        if self.tenants:
            parts.append(f"tenant in {self.tenants}")
        return " and ".join(parts) or "any environment"


@dataclass
class ProvenanceMatcher(Matcher):
    """Match on the provenance verdict attached to the context.

    ``require_verified`` is the switch most policies actually want: it fires on
    anything that is not cryptographically bound to a model completion.
    """

    kind = "provenance"
    statuses: List[str] = field(default_factory=list)
    require_verified: bool = False
    treat_missing_as: str = "missing"

    def matches(self, ctx: EvaluationContext) -> bool:
        record = ctx.provenance
        status = record.status.value if record is not None else self.treat_missing_as
        if self.require_verified:
            return status != "verified"
        if not self.statuses:
            return True
        return status in {str(s).strip().lower() for s in self.statuses}

    def describe(self) -> str:
        if self.require_verified:
            return "provenance is not verified"
        return f"provenance.status in {sorted(self.statuses)}"


# --------------------------------------------------------------------------- #
# Temporal & network
# --------------------------------------------------------------------------- #
@dataclass
class TimeWindowMatcher(Matcher):
    """Match a recurring wall-clock window - business hours, change freezes.

    Windows are expressed in a fixed UTC offset rather than an IANA zone so the
    matcher stays standard-library only and, more importantly, so a policy
    cannot change meaning when the host's tz database is updated.

    A window whose ``end`` is earlier than its ``start`` wraps past midnight,
    which is how maintenance windows are usually written (``22:00`` - ``04:00``).
    """

    kind = "time_window"
    days: List[str] = field(default_factory=lambda: list(WEEKDAYS))
    start: str = "00:00"
    end: str = "23:59"
    utc_offset_hours: float = 0.0
    invert: bool = False

    def matches(self, ctx: EvaluationContext) -> bool:
        inside = self._inside(ctx.now)
        return (not inside) if self.invert else inside

    def _inside(self, now: float) -> bool:
        shifted = now + self.utc_offset_hours * 3600.0
        parts = time.gmtime(shifted)
        day = WEEKDAYS[parts.tm_wday]
        allowed = {str(d).strip().lower()[:3] for d in (self.days or WEEKDAYS)}
        minutes = parts.tm_hour * 60 + parts.tm_min
        start = self._minutes(self.start, 0)
        end = self._minutes(self.end, 24 * 60 - 1)

        if start <= end:
            if day not in allowed:
                return False
            return start <= minutes <= end
        # Wrapping window: the tail belongs to the previous day's entry.
        if minutes >= start:
            return day in allowed
        previous = WEEKDAYS[(parts.tm_wday - 1) % 7]
        return minutes <= end and previous in allowed

    @staticmethod
    def _minutes(value: str, default: int) -> int:
        try:
            hours, _, mins = str(value).partition(":")
            return max(0, min(24 * 60 - 1, int(hours) * 60 + int(mins or 0)))
        except (TypeError, ValueError):
            return default

    def describe(self) -> str:
        prefix = "outside" if self.invert else "within"
        return f"{prefix} {self.start}-{self.end} UTC{self.utc_offset_hours:+g} on {self.days}"


@dataclass
class CidrMatcher(Matcher):
    """Match the caller's source address against a set of networks."""

    kind = "cidr"
    networks: List[str] = field(default_factory=list)
    field_path: str = "call.caller_ip"
    invert: bool = False

    def matches(self, ctx: EvaluationContext) -> bool:
        raw = ctx.attribute(self.field_path)
        inside = self._inside(str(raw or ""))
        return (not inside) if self.invert else inside

    def _inside(self, address: str) -> bool:
        if not address or not self.networks:
            return False
        try:
            ip = ipaddress.ip_address(address.strip())
        except ValueError:
            return False
        for entry in self.networks:
            try:
                if ip in ipaddress.ip_network(str(entry), strict=False):
                    return True
            except ValueError:
                continue
        return False

    def describe(self) -> str:
        prefix = "not in" if self.invert else "in"
        return f"{self.field_path} {prefix} {self.networks}"


# --------------------------------------------------------------------------- #
# Combinators
# --------------------------------------------------------------------------- #
def match_any(matchers: Sequence[Matcher], ctx: EvaluationContext) -> bool:
    """True when at least one matcher fires (vacuously False when empty)."""
    return any(m.matches(ctx) for m in matchers or [])


def match_all(matchers: Sequence[Matcher], ctx: EvaluationContext) -> bool:
    """True when every matcher fires (vacuously True when empty)."""
    return all(m.matches(ctx) for m in matchers or [])


def first_match(matchers: Sequence[Matcher], ctx: EvaluationContext) -> Optional[Matcher]:
    """Return the first matcher that fires, for explanation purposes."""
    for matcher in matchers or []:
        if matcher.matches(ctx):
            return matcher
    return None


def build_matchers(spec: Dict[str, Any]) -> List[Matcher]:
    """Assemble matchers from a rule's ``match`` block.

    Unknown keys are ignored here on purpose - the compiler is responsible for
    reporting them, and this function must stay usable for ad-hoc filters built
    at runtime (for example by the simulator).
    """
    matchers: List[Matcher] = []
    if not isinstance(spec, dict):
        return matchers

    tools = spec.get("tools") or []
    exclude = spec.get("exclude_tools") or []
    servers = spec.get("servers") or []
    if tools or exclude or servers:
        matchers.append(
            ToolMatcher(
                patterns=[str(t) for t in tools],
                exclude=[str(t) for t in exclude],
                servers=[str(s) for s in servers],
            )
        )

    if spec.get("categories"):
        matchers.append(
            CategoryMatcher(
                categories=[str(c) for c in spec["categories"]],
                mode=str(spec.get("categories_mode", "any")),
            )
        )
    if spec.get("min_risk") or spec.get("max_risk"):
        matchers.append(
            RiskMatcher(
                min_level=str(spec.get("min_risk", "") or "none"),
                max_level=str(spec.get("max_risk", "") or ""),
            )
        )
    if spec.get("agents") or spec.get("trust_tiers"):
        matchers.append(
            AgentMatcher(
                ids=[str(a) for a in (spec.get("agents") or [])],
                trust_tiers=[str(t) for t in (spec.get("trust_tiers") or [])],
            )
        )
    if spec.get("environments") or spec.get("tenants"):
        matchers.append(
            EnvironmentMatcher(
                environments=[str(e) for e in (spec.get("environments") or [])],
                tenants=[str(t) for t in (spec.get("tenants") or [])],
            )
        )
    if spec.get("networks"):
        matchers.append(CidrMatcher(networks=[str(n) for n in spec["networks"]]))
    if spec.get("time_window"):
        window = spec["time_window"]
        if isinstance(window, dict):
            matchers.append(
                TimeWindowMatcher(
                    days=[str(d) for d in (window.get("days") or WEEKDAYS)],
                    start=str(window.get("start", "00:00")),
                    end=str(window.get("end", "23:59")),
                    utc_offset_hours=float(window.get("utc_offset_hours", 0) or 0),
                    invert=bool(window.get("invert", False)),
                )
            )
    return matchers


def describe_matchers(matchers: Sequence[Matcher]) -> str:
    """Join matcher descriptions into one reviewable line."""
    return " AND ".join(m.describe() for m in matchers) if matchers else "any call"


def as_predicate(matchers: Sequence[Matcher]) -> Callable[[EvaluationContext], bool]:
    """Fold a matcher list into a single callable predicate."""

    def predicate(ctx: EvaluationContext) -> bool:
        return match_all(matchers, ctx)

    return predicate
