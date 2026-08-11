"""Argument risk rules for AegisAgent.

Where :mod:`aegis.classify.scoring` decides *how bad* a call is, this module
decides *whether the call's arguments look dangerous* in isolation.  Rules are
shipped as YAML (``aegis/classify/rules/*.yaml``) so a security engineer can add
a new dangerous-pattern without touching Python, and the same fail-open-per-rule
discipline from the detection signature engine applies: one malformed regex never
disables the whole pack.

Each rule is tied to an :class:`~aegis.core.types.ActionCategory` so a hit can be
folded straight into the classifier's category set and the risk scorer's work.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from ..core.config import Settings, load_structured_file
from ..core.logging import get_logger
from ..core.types import ActionCategory, EvaluationContext, Severity, ToolCall, utc_now
from ..core.utils import truncate
from .taxonomy import CATEGORY_ALIASES, _as_category

__all__ = [
    "RULES_DIR",
    "Rule",
    "RuleHit",
    "ArgumentRisk",
    "RuleSet",
    "ArgumentRiskRules",
    "default_rule_set",
]

LOGGER = get_logger("classify.argument_rules")

#: Directory holding the shipped YAML rule packs.
RULES_DIR = Path(__file__).resolve().parent / "rules"

#: Cap on scanned text per evaluation (regex DoS guard).
MAX_SCAN_CHARS = 200_000

_SEVERITY_ALIASES = {
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
}


def _as_severity(value: Any, default: Severity = Severity.MEDIUM) -> Severity:
    """Coerce a YAML scalar into a :class:`Severity`."""
    if isinstance(value, Severity):
        return value
    return _SEVERITY_ALIASES.get(str(value or "").strip().lower(), default)


def _extract_records(document: Any) -> List[Dict[str, Any]]:
    """Pull rule records out of a parsed pack, tolerating both YAML parsers.

    Accepts ``{"rules": [...]}`` (PyYAML) and ``{"rules": {"rules": [...]}}``
    (bundled minimal parser), plus a bare top-level list.
    """
    if isinstance(document, list):
        return [r for r in document if isinstance(r, dict)]
    if not isinstance(document, dict):
        return []
    node: Any = document.get("rules", [])
    for _ in range(3):
        if isinstance(node, dict):
            if "rules" in node:
                node = node["rules"]
                continue
            values = [v for v in node.values() if isinstance(v, list)]
            node = values[0] if values else []
        break
    if isinstance(node, list):
        return [r for r in node if isinstance(r, dict)]
    return []


@dataclass
class Rule:
    """One compiled argument-safety rule.

    Attributes:
        id: Stable rule identifier, unique within a pack (e.g. ``sh-014``).
        pattern: The raw regular expression source.
        severity: Severity assigned to matches.
        confidence: Base confidence in ``[0, 1]``.
        category: The :class:`ActionCategory` this rule advances.
        description: Human-readable explanation (Chinese or English).
        tags: Free-form labels grouping technique families.
        pack: Originating pack id (``shell`` / ``sql`` / ``filesystem`` / ``cloud``).
        regex: Compiled pattern (``None`` when the source failed to compile).
        compile_error: Parser error text, empty when compilation succeeded.
    """

    id: str
    pattern: str
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.6
    category: ActionCategory = ActionCategory.UNKNOWN
    description: str = ""
    tags: List[str] = field(default_factory=list)
    pack: str = ""
    regex: Optional[re.Pattern[str]] = field(default=None, repr=False, compare=False)
    compile_error: str = ""

    def compile(self) -> "Rule":
        """Compile :attr:`pattern`, recording (not raising) any regex error."""
        try:
            self.regex = re.compile(self.pattern, re.IGNORECASE | re.UNICODE)
            self.compile_error = ""
        except re.error as exc:
            self.regex = None
            self.compile_error = str(exc)
            LOGGER.warning("argument rule failed to compile", rule=self.id, error=str(exc))
        return self

    @property
    def usable(self) -> bool:
        """True when the rule compiled successfully."""
        return self.regex is not None

    @classmethod
    def from_mapping(cls, data: Dict[str, Any], pack: str = "") -> "Rule":
        """Build (and compile) a rule from a parsed YAML record."""
        rule_id = str(data.get("id") or "").strip()
        pattern = data.get("pattern")
        if not rule_id:
            raise ValueError("argument rule record is missing 'id'")
        if not isinstance(pattern, str) or not pattern:
            raise ValueError(f"argument rule {rule_id} is missing 'pattern'")
        tags = [str(t).strip() for t in (data.get("tags") or []) if str(t).strip()]
        confidence = data.get("confidence", 0.6)
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = 0.6
        category = _as_category(data.get("category")) or ActionCategory.UNKNOWN
        return cls(
            id=rule_id,
            pattern=pattern,
            severity=_as_severity(data.get("severity")),
            confidence=max(0.0, min(1.0, confidence)),
            category=category,
            description=str(data.get("description") or "").strip(),
            tags=tags,
            pack=pack,
        ).compile()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "pack": self.pack,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "category": self.category.value,
            "description": self.description,
            "tags": self.tags,
            "usable": self.usable,
            "compile_error": self.compile_error,
        }


@dataclass
class RuleHit:
    """A rule that fired, with enough context to justify the alert."""

    rule: Rule
    matched: str
    start: int
    end: int
    location: str = ""

    @property
    def id(self) -> str:
        return self.rule.id

    @property
    def severity(self) -> Severity:
        return self.rule.severity

    @property
    def category(self) -> ActionCategory:
        return self.rule.category

    @property
    def confidence(self) -> float:
        return self.rule.confidence

    @property
    def evidence(self) -> str:
        """Compact evidence line: ``[sh-014] matched text``."""
        return f"[{self.rule.id}] {truncate(self.matched, 160)}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.rule.id,
            "pack": self.rule.pack,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "category": self.category.value,
            "description": self.rule.description,
            "matched": truncate(self.matched, 160),
            "location": self.location,
            "span": [self.start, self.end],
            "tags": self.rule.tags,
        }


@dataclass
class ArgumentRisk:
    """A concrete risky argument observation surfaced to scoring/classification.

    Attributes:
        rule_id: The firing rule.
        category: Action category the rule maps to.
        severity: Severity of the match.
        confidence: Effective confidence (rule base, possibly scaled by location).
        matched: The offending substring.
        location: Dotted path of the argument value that contained it.
        description: Human-readable explanation.
        tags: Rule tags.
    """

    rule_id: str
    category: ActionCategory
    severity: Severity
    confidence: float
    matched: str
    location: str = ""
    description: str = ""
    tags: List[str] = field(default_factory=list)
    pack: str = ""

    @property
    def weighted_score(self) -> float:
        """Severity score times confidence, the unit scoring consumes."""
        return self.severity.score * max(0.0, min(1.0, self.confidence))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "matched": truncate(self.matched, 160),
            "location": self.location,
            "description": self.description,
            "tags": self.tags,
            "pack": self.pack,
        }


class RuleSet:
    """An indexed, thread-safe collection of compiled argument rules."""

    def __init__(self, rules: Optional[Iterable[Rule]] = None) -> None:
        """Args:
        rules: Initial rules; usually supplied by :meth:`from_directory`.
        """
        self._lock = threading.RLock()
        self._rules: List[Rule] = []
        self._by_id: Dict[str, Rule] = {}
        self._by_pack: Dict[str, List[Rule]] = {}
        self._by_category: Dict[str, List[Rule]] = {}
        self.versions: Dict[str, str] = {}
        for rule in rules or []:
            self.add(rule)

    # ------------------------------------------------------------------ #
    # Construction
    # ------------------------------------------------------------------ #
    @classmethod
    def from_directory(cls, directory: Optional[Path] = None) -> "RuleSet":
        """Build a set from every ``*.yaml`` pack in ``directory``."""
        instance = cls()
        directory = directory or RULES_DIR
        if not directory.is_dir():
            LOGGER.warning("rule directory missing", path=str(directory))
            return instance
        for path in sorted(directory.glob("*.yaml")):
            document = load_structured_file(path)
            pack_id = str((document or {}).get("id") or path.stem)
            version = str((document or {}).get("version") or "0")
            instance.versions[pack_id] = version
            for record in _extract_records(document):
                try:
                    instance.add(Rule.from_mapping(record, pack=pack_id))
                except ValueError as exc:
                    LOGGER.warning("skipping malformed argument rule", pack=pack_id, error=str(exc))
        LOGGER.info(
            "argument rule set loaded",
            packs=len(instance.versions),
            rules=len(instance._rules),
            unusable=sum(1 for r in instance._rules if not r.usable),
        )
        return instance

    @classmethod
    def from_records(cls, records: Sequence[Dict[str, Any]], pack: str = "inline") -> "RuleSet":
        """Build a set from in-memory records (tests, API-supplied rules)."""
        instance = cls()
        for record in records:
            try:
                instance.add(Rule.from_mapping(record, pack=pack))
            except ValueError as exc:
                LOGGER.warning("skipping inline argument rule", error=str(exc))
        return instance

    # ------------------------------------------------------------------ #
    # Mutation
    # ------------------------------------------------------------------ #
    def add(self, rule: Rule) -> None:
        """Insert a rule, replacing any earlier rule with the same id."""
        with self._lock:
            if rule.id in self._by_id:
                self.remove(rule.id)
            self._rules.append(rule)
            self._by_id[rule.id] = rule
            self._by_pack.setdefault(rule.pack, []).append(rule)
            self._by_category.setdefault(rule.category.value, []).append(rule)

    def remove(self, rule_id: str) -> bool:
        """Remove a rule by id. Returns ``True`` when something was removed."""
        with self._lock:
            rule = self._by_id.pop(rule_id, None)
            if rule is None:
                return False
            self._rules = [r for r in self._rules if r.id != rule_id]
            for bucket in (self._by_pack, self._by_category):
                for key, items in list(bucket.items()):
                    bucket[key] = [r for r in items if r.id != rule_id]
            return True

    # ------------------------------------------------------------------ #
    # Query & scan
    # ------------------------------------------------------------------ #
    def get(self, rule_id: str) -> Optional[Rule]:
        """Look up one rule by id."""
        return self._by_id.get(rule_id)

    def pack(self, pack_id: str) -> List[Rule]:
        """All rules belonging to ``pack_id``."""
        return list(self._by_pack.get(pack_id, []))

    def select(
        self,
        packs: Optional[Sequence[str]] = None,
        categories: Optional[Sequence[ActionCategory]] = None,
        min_severity: Severity = Severity.INFO,
    ) -> List[Rule]:
        """Filter rules by pack / category / minimum severity."""
        with self._lock:
            candidates = list(self._rules)
        if packs:
            wanted = {p.lower() for p in packs}
            candidates = [r for r in candidates if r.pack.lower() in wanted]
        if categories:
            wanted = {c.value for c in categories}
            candidates = [r for r in candidates if r.category.value in wanted]
        cut = min_severity.score
        candidates = [r for r in candidates if r.severity.score >= cut]
        return candidates

    def scan(self, text: str, *, location: str = "", max_hits: int = 64) -> List[RuleHit]:
        """Run every usable rule against ``text``.

        Args:
            text: Serialised arguments to scan (truncated to :data:`MAX_SCAN_CHARS`).
            location: Provenance label copied onto each hit.
            max_hits: Global cap on returned hits.

        Returns:
            Hits ordered by ``severity * confidence`` descending.
        """
        if not text:
            return []
        haystack = text[:MAX_SCAN_CHARS]
        hits: List[RuleHit] = []
        for rule in self._rules:
            if not rule.usable:
                continue
            for match in rule.regex.finditer(haystack):  # type: ignore[union-attr]
                matched = match.group(0)
                hits.append(
                    RuleHit(
                        rule=rule,
                        matched=matched,
                        start=match.start(),
                        end=match.end(),
                        location=location,
                    )
                )
                if len(hits) >= max_hits:
                    break
            if len(hits) >= max_hits:
                break
        hits.sort(key=lambda h: h.severity.score * h.confidence, reverse=True)
        return hits

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #
    def __len__(self) -> int:
        return len(self._rules)

    def stats(self) -> Dict[str, Any]:
        """Counts by pack / severity plus any compile failures."""
        by_pack = {pack: len(items) for pack, items in self._by_pack.items() if pack}
        by_severity: Dict[str, int] = {}
        broken: List[str] = []
        for rule in self._rules:
            by_severity[rule.severity.value] = by_severity.get(rule.severity.value, 0) + 1
            if rule.compile_error:
                broken.append(f"{rule.id}: {rule.compile_error}")
        return {
            "total": len(self._rules),
            "packs": by_pack,
            "versions": dict(self.versions),
            "by_severity": by_severity,
            "compile_errors": broken,
        }


_DEFAULT_SET: Optional[RuleSet] = None
_DEFAULT_LOCK = threading.Lock()


def default_rule_set(reload: bool = False) -> RuleSet:
    """Process-wide rule set loaded from the bundled pack directory."""
    global _DEFAULT_SET
    with _DEFAULT_LOCK:
        if _DEFAULT_SET is None or reload:
            _DEFAULT_SET = RuleSet.from_directory()
        return _DEFAULT_SET


class ArgumentRiskRules:
    """Evaluate a tool call's arguments against the rule packs.

    The evaluator renders the arguments to a bounded JSON blob and scans it once
    per applicable pack, then converts each hit into an :class:`ArgumentRisk`.
    Matches inside untrusted/retrieved content carry a small confidence bump
    because an injected dangerous path is more likely to be an attack than a
    benign developer value.
    """

    def __init__(
        self,
        rule_set: Optional[RuleSet] = None,
        *,
        min_confidence: float = 0.3,
        max_risks: int = 50,
    ) -> None:
        """Args:
        rule_set: Rule set; the bundled default is used when omitted.
        min_confidence: Hits below this confidence are discarded.
        max_risks: Cap applied after ranking.
        """
        self.rule_set = rule_set or default_rule_set()
        self.min_confidence = float(min_confidence)
        self.max_risks = int(max_risks)

    @classmethod
    def from_settings(cls, settings: Optional[Settings] = None, **kwargs: Any) -> "ArgumentRiskRules":
        """Build from the ``classification`` config section (falls back to default)."""
        if settings is not None:
            section = getattr(settings, "section", lambda _: {}).__call__("classification")
            if isinstance(section, dict):
                kwargs.setdefault("min_confidence", float(section.get("min_confidence", 0.3)))
        return cls(default_rule_set(), **kwargs)

    @classmethod
    def from_directory(cls, directory: Path, **kwargs: Any) -> "ArgumentRiskRules":
        """Build from an explicit rule directory (tests, custom packs)."""
        return cls(RuleSet.from_directory(directory), **kwargs)

    # ------------------------------------------------------------------ #
    # Evaluation
    # ------------------------------------------------------------------ #
    def evaluate_call(self, call: ToolCall, *, untrusted: bool = False) -> List[ArgumentRisk]:
        """Scan one tool call's arguments, returning ranked risks."""
        import json

        arguments = call.arguments or {}
        try:
            rendered = json.dumps(arguments, ensure_ascii=False, sort_keys=True, default=str)
        except (TypeError, ValueError):
            rendered = str(arguments)
        location = f"arguments:{call.qualified_name}" if call.qualified_name else "arguments"

        risks: List[ArgumentRisk] = []
        for hit in self.rule_set.scan(rendered, location=location, max_hits=self.max_risks * 2):
            confidence = hit.confidence
            if untrusted:
                confidence = min(1.0, confidence + 0.05)
            if confidence < self.min_confidence:
                continue
            risks.append(
                ArgumentRisk(
                    rule_id=hit.id,
                    category=hit.category,
                    severity=hit.severity,
                    confidence=round(confidence, 4),
                    matched=hit.matched,
                    location=hit.location,
                    description=hit.rule.description,
                    tags=list(hit.rule.tags),
                    pack=hit.rule.pack,
                )
            )
        risks.sort(key=lambda r: r.weighted_score, reverse=True)
        return risks[: self.max_risks]

    def evaluate(self, ctx: EvaluationContext) -> List[ArgumentRisk]:
        """Scan an evaluation context's call (convenience for the pipeline)."""
        untrusted = bool(ctx.call.source and ctx.call.source != "model")
        return self.evaluate_call(ctx.call, untrusted=untrusted)

    def categories(self, risks: Sequence[ArgumentRisk]) -> List[ActionCategory]:
        """Distinct categories implied by a list of argument risks."""
        seen: List[ActionCategory] = []
        for risk in risks:
            if risk.category is not ActionCategory.UNKNOWN and risk.category not in seen:
                seen.append(risk.category)
        return seen

    def describe(self) -> Dict[str, Any]:
        """Machine-readable summary for ``/v1/classifiers`` and the CLI."""
        stats = self.rule_set.stats()
        stats["min_confidence"] = self.min_confidence
        stats["max_risks"] = self.max_risks
        stats["rules"] = len(self.rule_set)
        return stats
