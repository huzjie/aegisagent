"""The condition DSL: a small, total, side-effect-free expression language.

Policies must be reviewable by security engineers who are not Python
programmers, and they must be *safe to load from disk* - so the DSL is data, not
code.  There is no ``eval``, no lambda, no import hook: a condition is a nested
mapping of ``all`` / ``any`` / ``not`` around leaves of the form::

    {field: <dotted.path>, op: <operator>, value: <literal>}

Every operator is total: given any pair of operands it returns a bool rather
than raising, because a policy that throws at evaluation time is a policy that
fails open (or takes the gateway down).  Type errors surface at *compile* time,
where an author can still fix them.

Field paths resolve through :meth:`aegis.core.types.EvaluationContext.attribute`,
plus a handful of ergonomic aliases so authors can write ``args.command``
instead of ``call.arguments.command``.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from ..core.errors import PolicyCompileError
from ..core.types import EvaluationContext, RiskLevel, Severity
from ..core.utils import any_glob_match, glob_match, host_matches_allowlist

__all__ = [
    "VALID_OPS",
    "OPERATORS",
    "resolve_field",
    "Condition",
    "AlwaysCondition",
    "LeafCondition",
    "AllCondition",
    "AnyCondition",
    "NotCondition",
    "compile_condition",
]


# --------------------------------------------------------------------------- #
# Field resolution
# --------------------------------------------------------------------------- #
#: Author-friendly prefixes rewritten before hitting ``EvaluationContext``.
FIELD_ALIASES: List[Tuple[str, str]] = [
    ("args.", "call.arguments."),
    ("arguments.", "call.arguments."),
    ("metadata.", "call.metadata."),
    ("agent_id", "call.agent_id"),
    ("tenant", "call.tenant_id"),
    ("source", "call.source"),
    ("caller_ip", "call.caller_ip"),
    ("tool_name", "call.tool"),
    ("qualified_name", "call.qualified_name"),
]


def _apply_alias(path: str) -> str:
    for prefix, replacement in FIELD_ALIASES:
        if prefix.endswith(".") and path.startswith(prefix):
            return replacement + path[len(prefix):]
        if not prefix.endswith(".") and path == prefix:
            return replacement
    return path


def _findings_attribute(ctx: EvaluationContext, leaf: str) -> Any:
    """Derived aggregates over ``ctx.findings`` - the detector output."""
    findings = ctx.findings or []
    if leaf in ("", "count", "len"):
        return len(findings)
    if leaf == "max_severity":
        if not findings:
            return Severity.INFO.value
        return max(findings, key=lambda f: f.severity.score).severity.value
    if leaf == "max_score":
        return max((f.weighted_score for f in findings), default=0.0)
    if leaf == "total_score":
        return sum(f.weighted_score for f in findings)
    if leaf == "kinds":
        return [f.kind.value for f in findings]
    if leaf == "detectors":
        return [f.detector for f in findings]
    if leaf == "titles":
        return [f.title for f in findings]
    if leaf == "tags":
        return [tag for f in findings for tag in f.tags]
    if leaf == "references":
        return [ref for f in findings for ref in f.references]
    return None


def resolve_field(ctx: EvaluationContext, path: str) -> Any:
    """Resolve a dotted field path against an evaluation context.

    Returns ``None`` for anything that cannot be resolved; operators are written
    so that ``None`` never produces a spurious match.
    """
    if not path:
        return None
    path = _apply_alias(str(path).strip())
    root, _, rest = path.partition(".")

    if root == "findings":
        return _findings_attribute(ctx, rest)
    if root == "history":
        history = list(ctx.history or [])
        if rest in ("", "all"):
            return history
        if rest == "count":
            return len(history)
        if rest == "last":
            return history[-1] if history else None
        if rest == "distinct":
            return sorted(set(history))
        return None
    if root == "now" and not rest:
        return ctx.now
    if root == "risk_score" and not rest:
        return ctx.risk_score
    if root == "environment" and not rest:
        return ctx.environment
    return ctx.attribute(path)


# --------------------------------------------------------------------------- #
# Operand normalisation
# --------------------------------------------------------------------------- #
_RISK_ORDER = {level.value: level.score for level in RiskLevel}
_SEVERITY_ORDER = {level.value: level.score for level in Severity}


def _numeric(value: Any) -> Optional[float]:
    """Best-effort numeric coercion, including risk/severity bands."""
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        token = value.strip().lower()
        if token in _RISK_ORDER:
            return float(_RISK_ORDER[token])
        if token in _SEVERITY_ORDER:
            return float(_SEVERITY_ORDER[token])
        try:
            return float(token)
        except ValueError:
            return None
    return None


def _as_sequence(value: Any) -> List[Any]:
    """Treat scalars as one-element sequences so ``in``/``glob`` accept both."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    if isinstance(value, dict):
        return list(value.keys())
    return [value]


def _same(a: Any, b: Any) -> bool:
    """Equality with string case-insensitivity and numeric coercion.

    A missing field (``None``) only equals an explicit ``null`` literal.  This
    matters for security policies: without it, ``{field: extra.foo, op: eq,
    value: false}`` would fire on every call where ``extra.foo`` was simply
    never populated, silently turning targeted deny rules into catch-alls.
    Use the ``exists`` operator to test for presence.
    """
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, bool) or isinstance(b, bool):
        return bool(a) == bool(b)
    if isinstance(a, str) and isinstance(b, str):
        return a.strip().lower() == b.strip().lower()
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return float(a) == float(b)
    na, nb = _numeric(a), _numeric(b)
    if na is not None and nb is not None and (isinstance(a, str) != isinstance(b, str)):
        return na == nb
    return a == b


def _compare(left: Any, right: Any, op: str) -> bool:
    """Ordered comparison, numeric when possible and lexicographic otherwise."""
    nl, nr = _numeric(left), _numeric(right)
    if nl is None or nr is None:
        if left is None or right is None:
            return False
        nl, nr = None, None
        sl, sr = str(left), str(right)
        pairs = {"gt": sl > sr, "gte": sl >= sr, "lt": sl < sr, "lte": sl <= sr}
        return bool(pairs[op])
    pairs = {"gt": nl > nr, "gte": nl >= nr, "lt": nl < nr, "lte": nl <= nr}
    return bool(pairs[op])


def _contains(haystack: Any, needle: Any) -> bool:
    """Substring for strings, membership for collections."""
    if haystack is None:
        return False
    if isinstance(haystack, str):
        needles = _as_sequence(needle)
        low = haystack.lower()
        return any(str(n).lower() in low for n in needles)
    if isinstance(haystack, dict):
        return any(_same(key, needle) for key in haystack)
    if isinstance(haystack, (list, tuple, set, frozenset)):
        needles = _as_sequence(needle)
        return any(_same(item, n) for item in haystack for n in needles)
    return _same(haystack, needle)


def _in(left: Any, right: Any) -> bool:
    """``left`` is inside collection ``right`` (or overlaps it, when a list)."""
    options = _as_sequence(right)
    if not options:
        return False
    if isinstance(left, (list, tuple, set, frozenset)):
        return any(_same(item, option) for item in left for option in options)
    return any(_same(left, option) for option in options)


def _matches(value: Any, pattern: Any) -> bool:
    """Case-insensitive regex search over the string form of ``value``."""
    if value is None:
        return False
    text = value if isinstance(value, str) else str(value)
    for candidate in _as_sequence(pattern):
        try:
            if re.search(str(candidate), text, re.IGNORECASE | re.DOTALL):
                return True
        except re.error:
            continue
    return False


def _glob(value: Any, pattern: Any) -> bool:
    if value is None:
        return False
    patterns = [str(p) for p in _as_sequence(pattern)]
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(any_glob_match(str(item), patterns) for item in value)
    return any_glob_match(str(value), patterns)


def _exists(value: Any, expected: Any) -> bool:
    """Presence test.  ``value: false`` inverts it into an absence test."""
    present = value is not None and value != "" and value != [] and value != {}
    want = True if expected is None else bool(expected)
    return present is want


def _startswith(value: Any, prefix: Any) -> bool:
    if value is None:
        return False
    text = str(value).lower()
    return any(text.startswith(str(p).lower()) for p in _as_sequence(prefix))


def _endswith(value: Any, suffix: Any) -> bool:
    if value is None:
        return False
    text = str(value).lower()
    return any(text.endswith(str(s).lower()) for s in _as_sequence(suffix))


def _cidr(value: Any, networks: Any) -> bool:
    """Membership of an IP (or the host of a URL) in one of several networks."""
    if value is None:
        return False
    candidates = [str(n) for n in _as_sequence(networks)]
    text = str(value).strip()
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return host_matches_allowlist(text, candidates)
    for network in candidates:
        try:
            if address in ipaddress.ip_network(network, strict=False):
                return True
        except ValueError:
            continue
    return False


def _subset_of(value: Any, superset: Any) -> bool:
    """Every element of ``value`` appears in ``superset``."""
    items = _as_sequence(value)
    allowed = _as_sequence(superset)
    if not items:
        return True
    return all(any(_same(item, option) for option in allowed) for item in items)


def _length_gt(value: Any, threshold: Any) -> bool:
    limit = _numeric(threshold)
    if limit is None:
        return False
    if value is None:
        return False
    try:
        return len(value) > limit  # type: ignore[arg-type]
    except TypeError:
        return len(str(value)) > limit


#: ``op`` name -> ``(left, right) -> bool``.  Every entry is total.
OPERATORS: Dict[str, Callable[[Any, Any], bool]] = {
    "eq": _same,
    "equals": _same,
    "ne": lambda a, b: not _same(a, b),
    "not_equals": lambda a, b: not _same(a, b),
    "gt": lambda a, b: _compare(a, b, "gt"),
    "gte": lambda a, b: _compare(a, b, "gte"),
    "lt": lambda a, b: _compare(a, b, "lt"),
    "lte": lambda a, b: _compare(a, b, "lte"),
    "in": _in,
    "not_in": lambda a, b: not _in(a, b),
    "contains": _contains,
    "not_contains": lambda a, b: not _contains(a, b),
    "matches": _matches,
    "regex": _matches,
    "not_matches": lambda a, b: not _matches(a, b),
    "glob": _glob,
    "not_glob": lambda a, b: not _glob(a, b),
    "exists": _exists,
    "startswith": _startswith,
    "endswith": _endswith,
    "cidr": _cidr,
    "not_cidr": lambda a, b: not _cidr(a, b),
    "subset_of": _subset_of,
    "length_gt": _length_gt,
}

#: Sorted operator names, used by the compiler for "did you mean" diagnostics.
VALID_OPS: List[str] = sorted(OPERATORS)


# --------------------------------------------------------------------------- #
# Condition tree
# --------------------------------------------------------------------------- #
class Condition:
    """Base class for every node of a compiled condition tree."""

    def evaluate(self, ctx: EvaluationContext) -> bool:
        """Evaluate this node against a context.  Must never raise."""
        raise NotImplementedError  # pragma: no cover - interface

    def describe(self) -> str:
        """Render the node as a readable expression for reviewers and the UI."""
        raise NotImplementedError  # pragma: no cover - interface

    def fields(self) -> List[str]:
        """Every field path this subtree reads - used for coverage analysis."""
        return []

    def __str__(self) -> str:  # pragma: no cover - convenience
        return self.describe()

    # -- construction ---------------------------------------------------- #
    @staticmethod
    def from_dict(data: Any, *, path: str = "when") -> "Condition":
        """Compile a parsed YAML mapping into a condition tree.

        Raises
        ------
        PolicyCompileError
            On unknown operators, malformed nodes or empty groups - all of which
            are author mistakes that must not reach production silently.
        """
        return compile_condition(data, path=path)


class AlwaysCondition(Condition):
    """Constant node - used for rules that rely purely on ``match``."""

    def __init__(self, value: bool = True) -> None:
        self.value = bool(value)

    def evaluate(self, ctx: EvaluationContext) -> bool:
        return self.value

    def describe(self) -> str:
        return "always" if self.value else "never"


class LeafCondition(Condition):
    """A single ``{field, op, value}`` comparison."""

    def __init__(self, field: str, op: str, value: Any) -> None:
        self.field = field
        self.op = op
        self.value = value
        self._fn = OPERATORS[op]
        self._regex: Optional[List[re.Pattern]] = None
        if op in ("matches", "regex", "not_matches"):
            self._regex = []
            for pattern in _as_sequence(value):
                try:
                    self._regex.append(re.compile(str(pattern), re.IGNORECASE | re.DOTALL))
                except re.error as exc:
                    raise PolicyCompileError(
                        f"invalid regular expression {pattern!r} for field {field!r}: {exc}",
                        details={"field": field, "op": op, "pattern": str(pattern)},
                    ) from exc

    def evaluate(self, ctx: EvaluationContext) -> bool:
        resolved = resolve_field(ctx, self.field)
        if self._regex is not None:
            text = "" if resolved is None else str(resolved)
            hit = any(rx.search(text) for rx in self._regex)
            return (not hit) if self.op == "not_matches" else hit
        try:
            return bool(self._fn(resolved, self.value))
        except Exception:  # noqa: BLE001 - a total DSL never propagates
            return False

    def describe(self) -> str:
        return f"{self.field} {self.op} {self.value!r}"

    def fields(self) -> List[str]:
        return [self.field]


class AllCondition(Condition):
    """Logical AND over child conditions (short-circuiting)."""

    def __init__(self, children: Sequence[Condition]) -> None:
        self.children = list(children)

    def evaluate(self, ctx: EvaluationContext) -> bool:
        return all(child.evaluate(ctx) for child in self.children)

    def describe(self) -> str:
        if not self.children:
            return "always"
        if len(self.children) == 1:
            return self.children[0].describe()
        return "(" + " AND ".join(child.describe() for child in self.children) + ")"

    def fields(self) -> List[str]:
        return [f for child in self.children for f in child.fields()]


class AnyCondition(Condition):
    """Logical OR over child conditions (short-circuiting)."""

    def __init__(self, children: Sequence[Condition]) -> None:
        self.children = list(children)

    def evaluate(self, ctx: EvaluationContext) -> bool:
        return any(child.evaluate(ctx) for child in self.children)

    def describe(self) -> str:
        if not self.children:
            return "never"
        if len(self.children) == 1:
            return self.children[0].describe()
        return "(" + " OR ".join(child.describe() for child in self.children) + ")"

    def fields(self) -> List[str]:
        return [f for child in self.children for f in child.fields()]


class NotCondition(Condition):
    """Logical negation of a single child."""

    def __init__(self, child: Condition) -> None:
        self.child = child

    def evaluate(self, ctx: EvaluationContext) -> bool:
        return not self.child.evaluate(ctx)

    def describe(self) -> str:
        return f"NOT {self.child.describe()}"

    def fields(self) -> List[str]:
        return self.child.fields()


# --------------------------------------------------------------------------- #
# Compilation
# --------------------------------------------------------------------------- #
_GROUP_KEYS = ("all", "any", "not", "none")


def compile_condition(data: Any, *, path: str = "when") -> Condition:
    """Turn a parsed YAML condition into an executable :class:`Condition`.

    ``path`` is a breadcrumb (``when.all[2]``) included in compile errors so an
    author can find the offending line in a 25-rule pack.
    """
    if data is None:
        return AlwaysCondition(True)
    if isinstance(data, bool):
        return AlwaysCondition(data)
    if isinstance(data, list):
        # A bare list is an implicit AND, matching how humans read YAML.
        return AllCondition(
            [compile_condition(item, path=f"{path}[{i}]") for i, item in enumerate(data)]
        )
    if not isinstance(data, dict):
        raise PolicyCompileError(
            f"condition at {path} must be a mapping, got {type(data).__name__}",
            details={"path": path},
        )

    group_keys = [key for key in _GROUP_KEYS if key in data]
    if group_keys:
        parts: List[Condition] = []
        for key in group_keys:
            child = data[key]
            if key == "all":
                parts.append(AllCondition(_compile_children(child, f"{path}.all")))
            elif key == "any":
                parts.append(AnyCondition(_compile_children(child, f"{path}.any")))
            elif key == "not":
                if isinstance(child, list):
                    parts.append(NotCondition(AllCondition(_compile_children(child, f"{path}.not"))))
                else:
                    parts.append(NotCondition(compile_condition(child, path=f"{path}.not")))
            else:  # "none" - sugar for NOT any(...)
                parts.append(
                    NotCondition(AnyCondition(_compile_children(child, f"{path}.none")))
                )
        leftovers = set(data) - set(group_keys)
        if leftovers:
            raise PolicyCompileError(
                f"condition at {path} mixes group keys {group_keys} with "
                f"{sorted(leftovers)}; wrap the leaf in an 'all' block instead",
                details={"path": path, "unexpected": sorted(leftovers)},
            )
        return parts[0] if len(parts) == 1 else AllCondition(parts)

    return _compile_leaf(data, path)


def _compile_children(node: Any, path: str) -> List[Condition]:
    if node is None:
        return []
    if isinstance(node, dict):
        node = [node]
    if not isinstance(node, list):
        raise PolicyCompileError(
            f"{path} must be a sequence of conditions, got {type(node).__name__}",
            details={"path": path},
        )
    if not node:
        raise PolicyCompileError(
            f"{path} is empty - an empty group silently matches everything, which is "
            f"never what a security policy wants",
            details={"path": path},
        )
    return [compile_condition(item, path=f"{path}[{i}]") for i, item in enumerate(node)]


def _compile_leaf(data: Dict[str, Any], path: str) -> Condition:
    field = data.get("field")
    if not field:
        raise PolicyCompileError(
            f"leaf condition at {path} is missing 'field' (keys present: {sorted(data)})",
            details={"path": path, "keys": sorted(data)},
        )
    op = str(data.get("op", "eq") or "eq").strip().lower()
    if op not in OPERATORS:
        suggestion = _closest_op(op)
        hint = f"; did you mean {suggestion!r}?" if suggestion else ""
        raise PolicyCompileError(
            f"unknown operator {op!r} at {path} for field {field!r}{hint}. "
            f"Valid operators: {VALID_OPS}",
            details={"path": path, "field": str(field), "op": op, "valid": VALID_OPS},
        )
    if "value" not in data and op != "exists":
        raise PolicyCompileError(
            f"leaf condition at {path} ({field} {op}) is missing 'value'",
            details={"path": path, "field": str(field), "op": op},
        )
    return LeafCondition(str(field), op, data.get("value"))


def _closest_op(op: str) -> Optional[str]:
    """Cheap nearest-operator hint for typos, using prefix and containment."""
    if not op:
        return None
    for candidate in VALID_OPS:
        if candidate.startswith(op) or op.startswith(candidate):
            return candidate
    for candidate in VALID_OPS:
        if op in candidate or candidate in op:
            return candidate
    return None


def describe_condition(condition: Optional[Condition]) -> str:
    """Safe describe() for optional conditions."""
    return condition.describe() if condition is not None else "always"


def condition_fields(condition: Optional[Condition]) -> List[str]:
    """Unique, sorted list of field paths a condition reads."""
    if condition is None:
        return []
    return sorted(set(condition.fields()))


def evaluate_all(conditions: Iterable[Condition], ctx: EvaluationContext) -> bool:
    """Evaluate several conditions with AND semantics."""
    return all(condition.evaluate(ctx) for condition in conditions)
