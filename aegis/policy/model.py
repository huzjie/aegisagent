"""Declarative policy model - plain dataclasses, no validation framework.

A policy author writes YAML; this module is the in-memory shape that YAML
deserialises into, *before* compilation.  Keeping it as inert dataclasses (no
pydantic, no descriptors) matters for three reasons:

1. Policy bundles are security artefacts that get signed.  A model with implicit
   coercion would let two byte-different bundles hash to the same object.
2. The compiler needs to report errors with the author's original field names,
   so nothing may be silently renamed or defaulted away on load.
3. ``aegis.core`` is standard-library only, and the policy layer sits below the
   API layer where a validation framework would be reasonable.

Structure::

    PolicyBundle          # signed, versioned distribution unit
      └── Policy          # one YAML file / one concern (e.g. "corebreak")
            └── PolicyRule
                  ├── match        pre-filter: tools, categories, agents, envs
                  ├── when         condition that must hold
                  ├── unless       condition that must NOT hold
                  └── obligations  side conditions attached to the effect
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from ..core.types import Effect, new_id, utc_now

__all__ = [
    "VALID_EFFECTS",
    "RuleMatch",
    "PolicyRule",
    "Policy",
    "PolicyBundle",
    "validate_rule",
    "validate_policy",
    "validate_bundle",
]

#: Every effect a rule may declare, as written in YAML.
VALID_EFFECTS: List[str] = [e.value for e in Effect]

#: Obligation keys the effects layer knows how to merge.  Unknown keys are
#: preserved (forward compatibility) but reported as warnings by the compiler.
KNOWN_OBLIGATIONS = {
    "redact",            # list[str]  - argument paths to mask
    "redact_result",     # list[str]  - result paths to mask
    "throttle",          # dict       - {per_minute: int, burst: int}
    "sandbox",           # dict       - SandboxSpec overrides
    "approval_roles",    # list[str]  - roles allowed to approve
    "approval_ttl_s",    # int
    "require_step_up",   # bool
    "incident",          # bool       - open an incident
    "severity",          # str        - incident severity
    "notify",            # list[str]  - channels
    "annotate",          # dict       - free-form metadata for the decision
    "max_bytes_out",     # int
    "reason",            # str        - operator-facing explanation
}


# --------------------------------------------------------------------------- #
# Rule pre-filter
# --------------------------------------------------------------------------- #
@dataclass
class RuleMatch:
    """Cheap structural pre-filter evaluated before the condition DSL.

    Everything here is indexable, which is what lets the compiler build an
    inverted index and skip the vast majority of rules for any given call.
    """

    tools: List[str] = field(default_factory=list)
    exclude_tools: List[str] = field(default_factory=list)
    servers: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    agents: List[str] = field(default_factory=list)
    trust_tiers: List[str] = field(default_factory=list)
    environments: List[str] = field(default_factory=list)
    tenants: List[str] = field(default_factory=list)
    min_risk: str = ""

    @property
    def is_empty(self) -> bool:
        """True when the rule applies to every call (a "global" rule)."""
        return not any(
            [
                self.tools,
                self.exclude_tools,
                self.servers,
                self.categories,
                self.agents,
                self.trust_tiers,
                self.environments,
                self.tenants,
                self.min_risk,
            ]
        )

    @classmethod
    def from_dict(cls, data: Any) -> "RuleMatch":
        """Build from a parsed YAML mapping, tolerating scalars for list fields."""
        if not isinstance(data, dict):
            return cls()
        return cls(
            tools=_as_list(data.get("tools")),
            exclude_tools=_as_list(data.get("exclude_tools")),
            servers=_as_list(data.get("servers")),
            categories=_as_list(data.get("categories")),
            agents=_as_list(data.get("agents")),
            trust_tiers=_as_list(data.get("trust_tiers")),
            environments=_as_list(data.get("environments")),
            tenants=_as_list(data.get("tenants")),
            min_risk=str(data.get("min_risk", "") or ""),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialise back to the YAML shape, dropping empty fields."""
        out: Dict[str, Any] = {}
        for key in (
            "tools",
            "exclude_tools",
            "servers",
            "categories",
            "agents",
            "trust_tiers",
            "environments",
            "tenants",
        ):
            value = getattr(self, key)
            if value:
                out[key] = list(value)
        if self.min_risk:
            out["min_risk"] = self.min_risk
        return out


# --------------------------------------------------------------------------- #
# Rule
# --------------------------------------------------------------------------- #
@dataclass
class PolicyRule:
    """One authored rule: *when this holds, apply that effect*."""

    id: str = ""
    description: str = ""
    priority: int = 0
    effect: str = Effect.OBSERVE.value
    when: Optional[Dict[str, Any]] = None
    unless: Optional[Dict[str, Any]] = None
    match: RuleMatch = field(default_factory=RuleMatch)
    obligations: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    enabled: bool = True
    source: str = ""
    line: int = 0

    @property
    def effect_enum(self) -> Effect:
        """The declared effect as an :class:`Effect`, defaulting to ``OBSERVE``."""
        try:
            return Effect(str(self.effect).strip().lower())
        except ValueError:
            return Effect.OBSERVE

    @property
    def is_global(self) -> bool:
        """True when nothing in ``match`` restricts which tools this applies to."""
        return not self.match.tools

    @classmethod
    def from_dict(cls, data: Dict[str, Any], *, source: str = "") -> "PolicyRule":
        """Build a rule from parsed YAML."""
        if not isinstance(data, dict):
            raise TypeError(f"rule must be a mapping, got {type(data).__name__}")
        return cls(
            id=str(data.get("id", "") or ""),
            description=str(data.get("description", "") or ""),
            priority=_as_int(data.get("priority"), 0),
            effect=str(data.get("effect", Effect.OBSERVE.value) or Effect.OBSERVE.value).lower(),
            when=data.get("when") if isinstance(data.get("when"), dict) else None,
            unless=data.get("unless") if isinstance(data.get("unless"), dict) else None,
            match=RuleMatch.from_dict(data.get("match")),
            obligations=dict(data.get("obligations") or {}),
            tags=_as_list(data.get("tags")),
            references=_as_list(data.get("references")),
            enabled=_as_bool(data.get("enabled"), True),
            source=source,
            line=_as_int(data.get("__line__"), 0),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialise back to the authored YAML shape."""
        out: Dict[str, Any] = {
            "id": self.id,
            "description": self.description,
            "priority": self.priority,
            "effect": self.effect,
        }
        if self.match.to_dict():
            out["match"] = self.match.to_dict()
        if self.when:
            out["when"] = self.when
        if self.unless:
            out["unless"] = self.unless
        if self.obligations:
            out["obligations"] = dict(self.obligations)
        if self.tags:
            out["tags"] = list(self.tags)
        if self.references:
            out["references"] = list(self.references)
        if not self.enabled:
            out["enabled"] = False
        return out

    def validate(self) -> List[str]:
        """Return a list of human-readable problems (empty means valid)."""
        return validate_rule(self)


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #
@dataclass
class Policy:
    """A named collection of rules addressing one concern."""

    id: str = ""
    name: str = ""
    version: str = "0.0.0"
    description: str = ""
    rules: List[PolicyRule] = field(default_factory=list)
    defaults: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    source: str = ""

    @property
    def default_effect(self) -> Optional[Effect]:
        """Effect applied when no rule in this policy matches, if declared."""
        raw = self.defaults.get("effect")
        if not raw:
            return None
        try:
            return Effect(str(raw).strip().lower())
        except ValueError:
            return None

    @property
    def enabled_rules(self) -> List[PolicyRule]:
        """Rules that are not explicitly disabled."""
        return [r for r in self.rules if r.enabled]

    def rule(self, rule_id: str) -> Optional[PolicyRule]:
        """Look up a rule by id."""
        for candidate in self.rules:
            if candidate.id == rule_id:
                return candidate
        return None

    @classmethod
    def from_dict(cls, data: Dict[str, Any], *, source: str = "") -> "Policy":
        """Build a policy from a parsed YAML document."""
        if not isinstance(data, dict):
            raise TypeError(f"policy must be a mapping, got {type(data).__name__}")
        raw_rules = data.get("rules") or []
        if isinstance(raw_rules, dict):
            # Tolerate `rules: {id: {...}}` authoring style.
            raw_rules = [{"id": k, **(v or {})} for k, v in raw_rules.items()]
        rules = [PolicyRule.from_dict(r, source=source) for r in raw_rules if isinstance(r, dict)]
        return cls(
            id=str(data.get("id", "") or ""),
            name=str(data.get("name", "") or ""),
            version=str(data.get("version", "0.0.0") or "0.0.0"),
            description=str(data.get("description", "") or ""),
            rules=rules,
            defaults=dict(data.get("defaults") or {}),
            metadata=dict(data.get("metadata") or {}),
            source=source,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialise back to the authored YAML shape."""
        out: Dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "rules": [r.to_dict() for r in self.rules],
        }
        if self.defaults:
            out["defaults"] = dict(self.defaults)
        if self.metadata:
            out["metadata"] = dict(self.metadata)
        return out

    def validate(self) -> List[str]:
        """Return every problem found in this policy and its rules."""
        return validate_policy(self)


# --------------------------------------------------------------------------- #
# Bundle
# --------------------------------------------------------------------------- #
@dataclass
class PolicyBundle:
    """A signed, versioned set of policies - the unit that gets distributed."""

    id: str = field(default_factory=lambda: new_id("bundle"))
    version: str = "0.0.0"
    policies: List[Policy] = field(default_factory=list)
    signature: str = ""
    source: str = ""
    created_at: float = field(default_factory=utc_now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def rules(self) -> List[PolicyRule]:
        """Flattened view of every rule in the bundle."""
        return [rule for policy in self.policies for rule in policy.rules]

    @property
    def rule_count(self) -> int:
        return len(self.rules)

    @property
    def is_signed(self) -> bool:
        return bool(self.signature)

    def policy(self, policy_id: str) -> Optional[Policy]:
        """Look up a policy by id."""
        for candidate in self.policies:
            if candidate.id == policy_id:
                return candidate
        return None

    def signing_payload(self) -> Dict[str, Any]:
        """The canonical, signature-covered view of the bundle.

        The signature deliberately excludes itself, ``source`` (a local
        filesystem path that differs per host) and ``metadata.digest`` - the
        latter is a self-reference computed *after* signing, so including it
        would make every verification fail.
        """
        metadata = {
            k: v for k, v in self.metadata.items() if k != "digest"
        }
        return {
            "id": self.id,
            "version": self.version,
            "created_at": round(float(self.created_at), 3),
            "policies": [p.to_dict() for p in self.policies],
            "metadata": metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], *, source: str = "") -> "PolicyBundle":
        """Build a bundle from a parsed document.

        A document holding ``rules`` directly (i.e. a bare policy file) is
        wrapped into a single-policy bundle, which is how the built-in packs are
        loaded.
        """
        if not isinstance(data, dict):
            raise TypeError(f"bundle must be a mapping, got {type(data).__name__}")
        if "policies" in data:
            policies = [
                Policy.from_dict(p, source=source)
                for p in (data.get("policies") or [])
                if isinstance(p, dict)
            ]
        else:
            policies = [Policy.from_dict(data, source=source)]
        return cls(
            id=str(data.get("id") or (policies[0].id if policies else new_id("bundle"))),
            version=str(data.get("version", "0.0.0") or "0.0.0"),
            policies=policies,
            signature=str(data.get("signature", "") or ""),
            source=source,
            metadata=dict(data.get("metadata") or {}),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialise, including the detached signature."""
        payload = self.signing_payload()
        payload["signature"] = self.signature
        payload["source"] = self.source
        return payload

    def validate(self) -> List[str]:
        """Return every problem found across the bundle."""
        return validate_bundle(self)


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
def validate_rule(rule: PolicyRule) -> List[str]:
    """Structural checks on a single rule.

    This is intentionally *semantic-free*: it does not evaluate conditions, only
    verifies that the rule is well-formed enough for the compiler to work with.
    Condition-operator validation happens in the compiler, which owns the DSL.
    """
    problems: List[str] = []
    where = f"rule {rule.id or '<missing id>'}"

    if not rule.id:
        problems.append("rule is missing a required 'id'")
    elif not all(ch.isalnum() or ch in "-_." for ch in rule.id):
        problems.append(
            f"{where}: id may only contain alphanumerics, '-', '_' and '.'"
        )

    if str(rule.effect).lower() not in VALID_EFFECTS:
        problems.append(
            f"{where}: unknown effect {rule.effect!r}; expected one of {VALID_EFFECTS}"
        )

    if not rule.description:
        problems.append(f"{where}: missing 'description' - rules must be explainable to auditors")

    if rule.priority < 0:
        problems.append(f"{where}: priority must be >= 0, got {rule.priority}")

    if rule.when is not None and not isinstance(rule.when, dict):
        problems.append(f"{where}: 'when' must be a mapping")
    if rule.unless is not None and not isinstance(rule.unless, dict):
        problems.append(f"{where}: 'unless' must be a mapping")

    if rule.when is None and rule.match.is_empty:
        problems.append(
            f"{where}: has neither 'when' nor 'match' - it would fire on every call"
        )

    if not isinstance(rule.obligations, dict):
        problems.append(f"{where}: 'obligations' must be a mapping")
    else:
        unknown = sorted(set(rule.obligations) - KNOWN_OBLIGATIONS)
        if unknown:
            problems.append(
                f"{where}: unknown obligation key(s) {unknown} - they will be passed "
                f"through untouched"
            )

    effect = rule.effect_enum
    if effect is Effect.REDACT and not rule.obligations.get("redact"):
        problems.append(f"{where}: effect 'redact' requires an obligations.redact path list")
    if effect is Effect.THROTTLE and not rule.obligations.get("throttle"):
        problems.append(f"{where}: effect 'throttle' requires an obligations.throttle spec")

    return problems


def validate_policy(policy: Policy) -> List[str]:
    """Validate a policy and every rule inside it, including id uniqueness."""
    problems: List[str] = []
    if not policy.id:
        problems.append("policy is missing a required 'id'")
    if not policy.rules:
        problems.append(f"policy {policy.id!r} declares no rules")

    seen: Dict[str, int] = {}
    for index, rule in enumerate(policy.rules):
        problems.extend(f"[{policy.id}] {p}" for p in validate_rule(rule))
        if rule.id:
            if rule.id in seen:
                problems.append(
                    f"[{policy.id}] duplicate rule id {rule.id!r} at index {index} "
                    f"(first seen at index {seen[rule.id]})"
                )
            else:
                seen[rule.id] = index

    default_effect = policy.defaults.get("effect")
    if default_effect and str(default_effect).lower() not in VALID_EFFECTS:
        problems.append(
            f"[{policy.id}] defaults.effect {default_effect!r} is not a valid effect"
        )
    return problems


def validate_bundle(bundle: PolicyBundle) -> List[str]:
    """Validate every policy in a bundle and check cross-policy rule uniqueness."""
    problems: List[str] = []
    if not bundle.policies:
        problems.append(f"bundle {bundle.id!r} contains no policies")

    seen_policies: Dict[str, bool] = {}
    seen_rules: Dict[str, str] = {}
    for policy in bundle.policies:
        problems.extend(validate_policy(policy))
        if policy.id in seen_policies:
            problems.append(f"bundle {bundle.id!r}: duplicate policy id {policy.id!r}")
        seen_policies[policy.id] = True
        for rule in policy.rules:
            if not rule.id:
                continue
            if rule.id in seen_rules and seen_rules[rule.id] != policy.id:
                problems.append(
                    f"bundle {bundle.id!r}: rule id {rule.id!r} is used by both "
                    f"{seen_rules[rule.id]!r} and {policy.id!r}"
                )
            seen_rules[rule.id] = policy.id
    return problems


# --------------------------------------------------------------------------- #
# Coercion helpers
# --------------------------------------------------------------------------- #
def _as_list(value: Any) -> List[str]:
    """Coerce a YAML scalar / sequence into a list of strings."""
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if v is not None and str(v) != ""]
    return [str(value)]


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on", "enabled")


def merge_defaults(policies: Sequence[Policy]) -> Dict[str, Any]:
    """Fold the ``defaults`` blocks of several policies, last writer wins."""
    out: Dict[str, Any] = {}
    for policy in policies:
        out.update(policy.defaults or {})
    return out
