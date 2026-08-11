"""Effect arbitration and obligation merging.

When several rules fire on one tool call the gateway has to collapse them into
*one* enforceable answer.  Two things must be decided:

1. **The effect.**  AegisAgent always takes the most restrictive effect that any
   matching rule asked for.  This is the only defensible default for a security
   control: a rule that says ``deny`` must never be overridden by a rule that
   says ``allow`` simply because it was authored later or loaded from a
   different pack.  Priority orders *explanations*, not outcomes.

2. **The obligations.**  Effects are coarse; obligations carry the detail
   (which arguments to mask, how hard to throttle, which roles may approve).
   Obligations from every matching rule are merged, again biased towards the
   safer value - the smaller rate limit, the larger redaction set, the stricter
   sandbox.  Merging is *not* "last writer wins": that would let a permissive
   pack quietly widen a restrictive one.

An explicit escape hatch exists for the one case where "most restrictive" is
wrong: a rule may set ``obligations.override: true`` to declare itself
authoritative.  Overrides are recorded in the resolution so an auditor can see
exactly which rule relaxed the outcome and why.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..core.types import Effect, PolicyMatch

__all__ = [
    "REDACTION_MASK",
    "EffectResolution",
    "resolve_effect",
    "merge_obligations",
    "resolve",
    "apply_redactions",
    "redact_paths",
    "explain_effect",
    "effect_from_string",
    "throttle_spec",
    "sandbox_spec",
    "approval_spec",
]

#: What redacted values are replaced with.  Deliberately not the empty string:
#: downstream tools behave very differently when a key is missing versus masked,
#: and an auditor must be able to see that redaction happened.
REDACTION_MASK = "***REDACTED***"

#: Obligation keys merged by taking the *union* of their list values.
_UNION_KEYS = ("redact", "redact_result", "notify", "approval_roles")

#: Obligation keys merged by taking the *minimum* (smaller == more restrictive).
_MIN_KEYS = ("approval_ttl_s", "max_bytes_out")

#: Obligation keys merged by taking the logical OR (True == more restrictive).
_OR_KEYS = ("require_step_up", "incident")

#: Severity ordering used when merging the ``severity`` obligation.
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# --------------------------------------------------------------------------- #
# Resolution result
# --------------------------------------------------------------------------- #
@dataclass
class EffectResolution:
    """The collapsed outcome of every rule that matched one call."""

    effect: Effect = Effect.ALLOW
    obligations: Dict[str, Any] = field(default_factory=dict)
    decisive: Optional[PolicyMatch] = None
    contributing: List[PolicyMatch] = field(default_factory=list)
    overridden_by: Optional[PolicyMatch] = None
    reason: str = ""

    @property
    def blocks_execution(self) -> bool:
        """True when the call must not reach the tool."""
        return self.effect.blocks_execution

    @property
    def rule_ids(self) -> List[str]:
        """Ids of every rule that contributed, decisive one first."""
        ids = [m.rule_id for m in self.contributing if m.rule_id]
        if self.decisive and self.decisive.rule_id in ids:
            ids.remove(self.decisive.rule_id)
            ids.insert(0, self.decisive.rule_id)
        return ids

    def to_dict(self) -> Dict[str, Any]:
        """Serialise for audit records and API responses."""
        return {
            "effect": self.effect.value,
            "obligations": copy.deepcopy(self.obligations),
            "decisive_rule": self.decisive.rule_id if self.decisive else "",
            "contributing_rules": self.rule_ids,
            "overridden_by": self.overridden_by.rule_id if self.overridden_by else "",
            "reason": self.reason,
        }


# --------------------------------------------------------------------------- #
# Effect arbitration
# --------------------------------------------------------------------------- #
def effect_from_string(value: Any, default: Effect = Effect.OBSERVE) -> Effect:
    """Parse an authored effect string, falling back to ``default``."""
    try:
        return Effect(str(value).strip().lower())
    except (ValueError, AttributeError):
        return default


def resolve_effect(
    matches: Sequence[PolicyMatch],
    default: Effect = Effect.ALLOW,
) -> Effect:
    """Collapse matches into a single effect (most restrictive wins).

    ``default`` is returned when nothing matched, which is how the engine
    applies its configured ``policy.default_effect``.
    """
    if not matches:
        return default
    override = _find_override(matches)
    if override is not None:
        return override.effect
    return Effect.most_restrictive([m.effect for m in matches])


def _find_override(matches: Sequence[PolicyMatch]) -> Optional[PolicyMatch]:
    """Return the highest-priority rule claiming ``obligations.override``.

    Ties are broken deterministically by rule id so two hosts loading the same
    bundle always reach the same verdict.
    """
    candidates = [
        m for m in matches if _truthy((m.obligations or {}).get("override"))
    ]
    if not candidates:
        return None
    return sorted(candidates, key=lambda m: (-m.priority, m.rule_id))[0]


def _truthy(value: Any) -> bool:
    """Coerce a YAML scalar to bool without surprising on the string 'false'."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def resolve(
    matches: Sequence[PolicyMatch],
    *,
    default: Effect = Effect.ALLOW,
    fail_closed_effect: Optional[Effect] = None,
) -> EffectResolution:
    """Produce a full :class:`EffectResolution` from a set of matches.

    Parameters
    ----------
    matches:
        Every rule that fired, in any order.
    default:
        Effect applied when ``matches`` is empty.
    fail_closed_effect:
        When given, the floor for the final effect.  The engine passes this
        after an internal error so a compile or evaluation failure can never
        downgrade enforcement.
    """
    ordered = sorted(matches or [], key=lambda m: (-m.effect.rank, -m.priority, m.rule_id))

    if not ordered:
        effect = default
        resolution = EffectResolution(
            effect=effect,
            obligations={},
            decisive=None,
            contributing=[],
            reason=f"no rule matched; applied default effect '{effect.value}'",
        )
    else:
        override = _find_override(ordered)
        if override is not None:
            effect = override.effect
            decisive = override
            reason = (
                f"rule '{override.rule_id}' declared obligations.override and set "
                f"effect '{effect.value}', superseding "
                f"{len(ordered) - 1} other matching rule(s)"
            )
        else:
            effect = Effect.most_restrictive([m.effect for m in ordered])
            decisive = next((m for m in ordered if m.effect is effect), ordered[0])
            reason = (
                f"rule '{decisive.rule_id}' produced the most restrictive effect "
                f"'{effect.value}' across {len(ordered)} matching rule(s)"
            )
        resolution = EffectResolution(
            effect=effect,
            obligations=merge_obligations(ordered),
            decisive=decisive,
            contributing=list(ordered),
            overridden_by=override,
            reason=reason,
        )

    if fail_closed_effect is not None and fail_closed_effect.rank > resolution.effect.rank:
        resolution.reason = (
            f"{resolution.reason}; raised to '{fail_closed_effect.value}' by "
            f"fail-closed policy"
        )
        resolution.effect = fail_closed_effect
    return resolution


# --------------------------------------------------------------------------- #
# Obligation merging
# --------------------------------------------------------------------------- #
def merge_obligations(matches: Iterable[PolicyMatch]) -> Dict[str, Any]:
    """Fold every rule's obligations into one dict, biased towards safety.

    Merge strategy per key family:

    ``redact`` / ``redact_result`` / ``notify`` / ``approval_roles``
        Union, order-preserving and de-duplicated.  A path masked by any rule
        stays masked.
    ``throttle``
        Minimum of each numeric field - the tightest budget wins.
    ``sandbox``
        Strictest of each field (``network: deny`` beats ``allow``, smaller
        timeout/memory wins).
    ``approval_ttl_s`` / ``max_bytes_out``
        Minimum.
    ``require_step_up`` / ``incident``
        Logical OR.
    ``severity``
        Maximum band.
    ``annotate``
        Shallow dict union (later rules may add keys, not remove them).
    ``reason``
        Concatenated, de-duplicated, so the operator sees every justification.

    Unknown keys are carried through with last-writer-wins; the compiler warns
    about them at load time so this stays a forward-compatibility path rather
    than a silent behaviour.
    """
    out: Dict[str, Any] = {}
    reasons: List[str] = []

    for match in matches or []:
        obligations = match.obligations or {}
        if not isinstance(obligations, dict):
            continue
        for key, value in obligations.items():
            if key == "override":
                continue
            if key == "reason":
                text = str(value).strip()
                if text and text not in reasons:
                    reasons.append(text)
            elif key in _UNION_KEYS:
                out[key] = _union(out.get(key), value)
            elif key == "throttle":
                out[key] = _merge_throttle(out.get(key), value)
            elif key == "sandbox":
                out[key] = _merge_sandbox(out.get(key), value)
            elif key in _MIN_KEYS:
                out[key] = _min_numeric(out.get(key), value)
            elif key in _OR_KEYS:
                out[key] = _truthy(out.get(key)) or _truthy(value)
            elif key == "severity":
                out[key] = _max_severity(out.get(key), value)
            elif key == "annotate":
                merged = dict(out.get(key) or {})
                if isinstance(value, dict):
                    merged.update(value)
                out[key] = merged
            else:
                out[key] = copy.deepcopy(value)

    if reasons:
        out["reason"] = "; ".join(reasons)
    return out


def _union(existing: Any, incoming: Any) -> List[str]:
    """Order-preserving de-duplicated union of two scalar-or-list values."""
    out: List[str] = []
    for source in (existing, incoming):
        if source is None:
            continue
        items = source if isinstance(source, (list, tuple, set)) else [source]
        for item in items:
            text = str(item)
            if text and text not in out:
                out.append(text)
    return out


def _min_numeric(existing: Any, incoming: Any) -> Any:
    """Minimum of two numeric-ish values, ignoring unparseable ones."""
    values = [v for v in (_number(existing), _number(incoming)) if v is not None]
    if not values:
        return incoming
    smallest = min(values)
    return int(smallest) if float(smallest).is_integer() else smallest


def _number(value: Any) -> Optional[float]:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _max_severity(existing: Any, incoming: Any) -> str:
    """Higher of two severity bands."""
    left = str(existing or "info").strip().lower()
    right = str(incoming or "info").strip().lower()
    return left if _SEVERITY_RANK.get(left, 0) >= _SEVERITY_RANK.get(right, 0) else right


def _merge_throttle(existing: Any, incoming: Any) -> Dict[str, Any]:
    """Tightest rate limit across rules."""
    merged: Dict[str, Any] = dict(existing or {}) if isinstance(existing, dict) else {}
    if not isinstance(incoming, dict):
        return merged
    for key, value in incoming.items():
        if key in merged:
            merged[key] = _min_numeric(merged[key], value)
        else:
            merged[key] = value
    return merged


def _merge_sandbox(existing: Any, incoming: Any) -> Dict[str, Any]:
    """Strictest isolation spec across rules."""
    merged: Dict[str, Any] = dict(existing or {}) if isinstance(existing, dict) else {}
    if not isinstance(incoming, dict):
        return merged
    for key, value in incoming.items():
        if key not in merged:
            merged[key] = value
            continue
        if key == "network":
            # deny > allowlist > allow
            order = {"deny": 2, "allowlist": 1, "allow": 0}
            current, candidate = str(merged[key]).lower(), str(value).lower()
            merged[key] = current if order.get(current, 0) >= order.get(candidate, 0) else candidate
        elif key == "egress_allowlist":
            # Intersection: a host must be permitted by *every* rule.
            current_list = merged[key] if isinstance(merged[key], list) else [merged[key]]
            candidate_list = value if isinstance(value, list) else [value]
            merged[key] = [h for h in current_list if h in candidate_list]
        elif key in ("read_only", "drop_privileges", "no_new_privileges"):
            merged[key] = _truthy(merged[key]) or _truthy(value)
        else:
            merged[key] = _min_numeric(merged[key], value)
    return merged


# --------------------------------------------------------------------------- #
# Typed obligation accessors
# --------------------------------------------------------------------------- #
def throttle_spec(obligations: Dict[str, Any]) -> Tuple[float, int]:
    """Return ``(per_minute, burst)`` from a merged obligation dict."""
    spec = obligations.get("throttle") or {}
    if not isinstance(spec, dict):
        return (0.0, 0)
    per_minute = _number(spec.get("per_minute")) or 0.0
    burst = _number(spec.get("burst")) or max(1.0, per_minute / 4.0)
    return (float(per_minute), int(burst))


def sandbox_spec(obligations: Dict[str, Any]) -> Dict[str, Any]:
    """Return the merged sandbox overrides (empty dict when unset)."""
    spec = obligations.get("sandbox")
    return dict(spec) if isinstance(spec, dict) else {}


def approval_spec(obligations: Dict[str, Any]) -> Dict[str, Any]:
    """Return approval parameters in the shape the approval layer expects."""
    return {
        "roles": list(obligations.get("approval_roles") or []),
        "ttl_s": _number(obligations.get("approval_ttl_s")) or 0.0,
        "require_step_up": _truthy(obligations.get("require_step_up")),
    }


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #
def apply_redactions(
    payload: Any,
    paths: Sequence[str],
    *,
    mask: str = REDACTION_MASK,
) -> Tuple[Any, List[str]]:
    """Mask values at the given paths, returning ``(copy, applied_paths)``.

    Paths use the same jsonpath-lite dialect as the matchers: dotted segments,
    numeric list indices and ``*`` to mean "every element at this level".  The
    leading ``args.`` / ``arguments.`` prefix is stripped so a policy can reuse
    the same string it wrote in a condition.

    The input is never mutated - the gateway keeps the original arguments for
    the audit record and forwards only the redacted copy.
    """
    if not paths:
        return (payload, [])
    result = copy.deepcopy(payload)
    applied: List[str] = []
    for raw_path in paths:
        path = str(raw_path).strip()
        for prefix in ("args.", "arguments."):
            if path.startswith(prefix):
                path = path[len(prefix):]
                break
        if not path:
            continue
        if _mask_path(result, path.split("."), mask):
            applied.append(str(raw_path))
    return (result, applied)


def _mask_path(node: Any, segments: Sequence[str], mask: str) -> bool:
    """Recursively walk ``segments`` and mask the leaf.  Returns True on a hit."""
    if not segments:
        return False
    head, rest = segments[0], segments[1:]

    if head == "*":
        hit = False
        if isinstance(node, dict):
            for key in list(node.keys()):
                hit = _mask_child(node, key, rest, mask) or hit
        elif isinstance(node, list):
            for index in range(len(node)):
                hit = _mask_child(node, index, rest, mask) or hit
        return hit

    if isinstance(node, dict):
        if head not in node:
            return False
        return _mask_child(node, head, rest, mask)

    if isinstance(node, list):
        try:
            index = int(head)
        except ValueError:
            return False
        if not -len(node) <= index < len(node):
            return False
        return _mask_child(node, index, rest, mask)

    return False


def _mask_child(container: Any, key: Any, rest: Sequence[str], mask: str) -> bool:
    """Mask ``container[key]`` outright, or recurse when the path continues."""
    if rest:
        return _mask_path(container[key], rest, mask)
    if container[key] is None:
        return False
    container[key] = mask
    return True


def redact_paths(obligations: Dict[str, Any], *, results: bool = False) -> List[str]:
    """Extract the redaction path list from merged obligations."""
    key = "redact_result" if results else "redact"
    value = obligations.get(key) or []
    return [str(v) for v in value] if isinstance(value, (list, tuple)) else [str(value)]


# --------------------------------------------------------------------------- #
# Explanation
# --------------------------------------------------------------------------- #
def explain_effect(effect: Effect, matches: Sequence[PolicyMatch]) -> str:
    """One-line, operator-facing explanation of why a call got its effect.

    This string ends up in incident tickets and CLI output, so it names the
    decisive rule rather than dumping the whole match list.
    """
    if not matches:
        return f"{effect.value}: no policy rule matched, default effect applied"

    decisive = next((m for m in matches if m.effect is effect), matches[0])
    detail = decisive.reason or "matched"
    others = len(matches) - 1
    suffix = f" (+{others} other rule{'s' if others != 1 else ''})" if others > 0 else ""
    return f"{effect.value}: {decisive.rule_id} - {detail}{suffix}"
