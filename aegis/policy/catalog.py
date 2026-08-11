"""The tool catalog: what tools exist, what they do, and whether they changed.

Policy is written against tool *names*, but enforcement needs more than a name.
Deciding that ``github::create_pr`` is a ``write`` action, or that ``shell::exec``
is irreversible, requires a description of the tool itself - and that
description has to come from somewhere trustworthy.

The catalog is that somewhere.  It holds a :class:`~aegis.core.types.ToolDescriptor`
per tool and, critically, **pins its schema**.  MCP servers can change a tool's
description or parameters at any time after the client first connected, which is
the "rug pull" / tool-poisoning pattern (CVE-2026-64650 family): a tool that was
benign at approval time silently becomes something else.  Comparing a freshly
advertised descriptor against the pinned ``schema_hash`` turns that from an
invisible change into a detectable event.

The catalog is read-mostly and read from the hot path, so every mutation takes a
lock but reads of the internal dict are lock-free by construction (replacement,
never in-place edit, of the descriptor objects).
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from ..core.crypto import canonical_json, sha256_hex
from ..core.errors import NotFoundError, ValidationError
from ..core.logging import get_logger
from ..core.types import (
    ActionCategory,
    RiskLevel,
    ToolDescriptor,
    ToolParameter,
    TransportKind,
    utc_now,
)
from ..core.utils import any_glob_match, glob_match

__all__ = [
    "SchemaDrift",
    "ToolCatalog",
    "schema_hash",
    "descriptor_from_dict",
    "descriptor_to_dict",
]

logger = get_logger(__name__)


# --------------------------------------------------------------------------- #
# Schema pinning
# --------------------------------------------------------------------------- #
def schema_hash(descriptor: ToolDescriptor) -> str:
    """Stable hash over the security-relevant surface of a tool.

    Deliberately covers the *description* as well as the parameter list.  A
    prompt-injection payload hidden in a tool description is a real attack -
    the model reads that text - so a description change must invalidate the pin
    exactly like a signature change does.

    Fields that legitimately churn without changing behaviour (``version``,
    free-form ``metadata``, ``tags``) are excluded to keep the pin usable.
    """
    payload = {
        "name": descriptor.name,
        "server": descriptor.server,
        "description": descriptor.description,
        "transport": descriptor.transport.value,
        "parameters": [
            {
                "name": p.name,
                "type": p.type,
                "description": p.description,
                "required": p.required,
                "enum": list(p.enum),
                "max_length": p.max_length,
                "pattern": p.pattern,
            }
            for p in sorted(descriptor.parameters, key=lambda p: p.name)
        ],
        "categories": sorted(c.value for c in descriptor.categories),
        "reversible": descriptor.reversible,
        "idempotent": descriptor.idempotent,
        "requires_approval": descriptor.requires_approval,
    }
    return sha256_hex(canonical_json(payload))


@dataclass
class SchemaDrift:
    """A detected difference between a pinned tool and its current advert."""

    tool: str = ""
    server: str = ""
    pinned_hash: str = ""
    observed_hash: str = ""
    changed_fields: List[str] = field(default_factory=list)
    detected_at: float = field(default_factory=utc_now)

    @property
    def is_drift(self) -> bool:
        return bool(self.pinned_hash) and self.pinned_hash != self.observed_hash

    @property
    def qualified_name(self) -> str:
        return f"{self.server}::{self.tool}" if self.server else self.tool

    def describe(self) -> str:
        """Operator-facing summary suitable for an alert body."""
        if not self.is_drift:
            return f"{self.qualified_name}: schema unchanged"
        fields = ", ".join(self.changed_fields) or "unknown fields"
        return (
            f"{self.qualified_name}: schema changed after pinning ({fields}); "
            f"pinned={self.pinned_hash[:12]} observed={self.observed_hash[:12]}"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "server": self.server,
            "qualified_name": self.qualified_name,
            "pinned_hash": self.pinned_hash,
            "observed_hash": self.observed_hash,
            "changed_fields": list(self.changed_fields),
            "detected_at": self.detected_at,
            "is_drift": self.is_drift,
        }


# --------------------------------------------------------------------------- #
# Serialisation
# --------------------------------------------------------------------------- #
def descriptor_from_dict(data: Dict[str, Any]) -> ToolDescriptor:
    """Build a :class:`ToolDescriptor` from a plain mapping.

    Tolerant by design: this parses data advertised by third-party MCP servers,
    so unknown categories and transports degrade to safe defaults rather than
    rejecting the whole server.
    """
    if not isinstance(data, dict):
        raise ValidationError(
            f"tool descriptor must be a mapping, got {type(data).__name__}"
        )
    name = str(data.get("name", "") or "").strip()
    if not name:
        raise ValidationError("tool descriptor is missing a 'name'")

    parameters: List[ToolParameter] = []
    raw_params = data.get("parameters") or data.get("input_schema") or []
    if isinstance(raw_params, dict):
        # JSON-Schema style: {"properties": {...}, "required": [...]}
        required = set(raw_params.get("required") or [])
        for key, spec in (raw_params.get("properties") or {}).items():
            spec = spec if isinstance(spec, dict) else {}
            parameters.append(
                ToolParameter(
                    name=str(key),
                    type=str(spec.get("type", "string")),
                    description=str(spec.get("description", "")),
                    required=key in required,
                    enum=list(spec.get("enum") or []),
                    max_length=spec.get("maxLength"),
                    pattern=spec.get("pattern"),
                )
            )
    elif isinstance(raw_params, list):
        for spec in raw_params:
            if not isinstance(spec, dict):
                continue
            parameters.append(
                ToolParameter(
                    name=str(spec.get("name", "")),
                    type=str(spec.get("type", "string")),
                    description=str(spec.get("description", "")),
                    required=bool(spec.get("required", False)),
                    enum=list(spec.get("enum") or []),
                    max_length=spec.get("max_length"),
                    pattern=spec.get("pattern"),
                )
            )

    categories: List[ActionCategory] = []
    for raw in data.get("categories") or []:
        try:
            categories.append(ActionCategory(str(raw).strip().lower()))
        except ValueError:
            logger.debug("catalog.unknown_category", extra={"value": str(raw)})

    try:
        transport = TransportKind(str(data.get("transport", "inproc")).strip().lower())
    except ValueError:
        transport = TransportKind.INPROC

    descriptor = ToolDescriptor(
        name=name,
        description=str(data.get("description", "") or ""),
        server=str(data.get("server", "local") or "local"),
        transport=transport,
        parameters=parameters,
        categories=categories,
        reversible=bool(data.get("reversible", True)),
        idempotent=bool(data.get("idempotent", False)),
        requires_approval=bool(data.get("requires_approval", False)),
        version=str(data.get("version", "1.0.0") or "1.0.0"),
        tags=[str(t) for t in (data.get("tags") or [])],
        metadata=dict(data.get("metadata") or {}),
    )
    descriptor.schema_hash = str(data.get("schema_hash") or "") or schema_hash(descriptor)
    return descriptor


def descriptor_to_dict(descriptor: ToolDescriptor) -> Dict[str, Any]:
    """Serialise a descriptor back to a plain mapping."""
    return {
        "name": descriptor.name,
        "description": descriptor.description,
        "server": descriptor.server,
        "transport": descriptor.transport.value,
        "parameters": [
            {
                "name": p.name,
                "type": p.type,
                "description": p.description,
                "required": p.required,
                "enum": list(p.enum),
                "max_length": p.max_length,
                "pattern": p.pattern,
            }
            for p in descriptor.parameters
        ],
        "categories": [c.value for c in descriptor.categories],
        "reversible": descriptor.reversible,
        "idempotent": descriptor.idempotent,
        "requires_approval": descriptor.requires_approval,
        "schema_hash": descriptor.schema_hash,
        "version": descriptor.version,
        "tags": list(descriptor.tags),
        "metadata": dict(descriptor.metadata),
    }


# --------------------------------------------------------------------------- #
# Catalog
# --------------------------------------------------------------------------- #
class ToolCatalog:
    """Thread-safe registry of known tools, keyed by ``server::tool``.

    Registration pins the schema on first sight.  Re-registering the *same*
    tool with a changed schema is reported as drift and, unless
    ``allow_drift`` is set, leaves the pinned descriptor in place: the gateway
    keeps enforcing against the version a human approved, not the version a
    server just pushed.
    """

    def __init__(self, *, allow_drift: bool = False) -> None:
        self.allow_drift = allow_drift
        self._tools: Dict[str, ToolDescriptor] = {}
        self._drift: Dict[str, SchemaDrift] = {}
        self._lock = threading.RLock()

    # -- registration ----------------------------------------------------- #
    def register(
        self,
        descriptor: ToolDescriptor,
        *,
        repin: bool = False,
    ) -> SchemaDrift:
        """Add or update a tool, returning the drift verdict.

        ``repin=True`` accepts the new schema as the pinned one - the explicit
        action an operator takes after reviewing a legitimate tool update.
        """
        key = descriptor.qualified_name
        observed = schema_hash(descriptor)

        with self._lock:
            existing = self._tools.get(key)
            if existing is None:
                if not descriptor.schema_hash:
                    descriptor.schema_hash = observed
                self._tools[key] = descriptor
                logger.info("catalog.registered", extra={"tool": key})
                return SchemaDrift(
                    tool=descriptor.name,
                    server=descriptor.server,
                    pinned_hash=descriptor.schema_hash,
                    observed_hash=observed,
                )

            pinned = existing.schema_hash or schema_hash(existing)
            drift = SchemaDrift(
                tool=descriptor.name,
                server=descriptor.server,
                pinned_hash=pinned,
                observed_hash=observed,
                changed_fields=_diff_descriptors(existing, descriptor),
            )
            if not drift.is_drift:
                self._tools[key] = descriptor
                return drift

            self._drift[key] = drift
            logger.warning("catalog.schema_drift", extra={"tool": key, "fields": drift.changed_fields})
            if repin or self.allow_drift:
                descriptor.schema_hash = observed
                self._tools[key] = descriptor
                logger.info("catalog.repinned", extra={"tool": key})
            return drift

    def register_many(self, descriptors: Iterable[ToolDescriptor]) -> List[SchemaDrift]:
        """Register a batch, returning only the entries that actually drifted."""
        return [d for d in (self.register(desc) for desc in descriptors) if d.is_drift]

    def unregister(self, qualified_name: str) -> bool:
        """Remove a tool.  Returns True when something was removed."""
        with self._lock:
            self._drift.pop(qualified_name, None)
            return self._tools.pop(qualified_name, None) is not None

    # -- lookup ----------------------------------------------------------- #
    def get(self, name: str, server: str = "") -> Optional[ToolDescriptor]:
        """Look up by qualified name, or by bare name when unambiguous."""
        if server:
            return self._tools.get(f"{server}::{name}")
        if "::" in name:
            return self._tools.get(name)
        direct = self._tools.get(f"local::{name}")
        if direct is not None:
            return direct
        matches = [d for k, d in self._tools.items() if k.split("::")[-1] == name]
        return matches[0] if len(matches) == 1 else None

    def require(self, name: str, server: str = "") -> ToolDescriptor:
        """Like :meth:`get` but raises when the tool is unknown."""
        descriptor = self.get(name, server)
        if descriptor is None:
            raise NotFoundError(
                f"tool {server + '::' if server else ''}{name} is not in the catalog",
                details={"tool": name, "server": server},
            )
        return descriptor

    def search(
        self,
        pattern: str = "*",
        *,
        categories: Optional[Sequence[str]] = None,
        server: str = "",
        min_risk: str = "",
    ) -> List[ToolDescriptor]:
        """Filter the catalog by glob, category, server and inherent risk."""
        wanted = {str(c).strip().lower() for c in (categories or [])}
        floor = _risk_score(min_risk)

        out: List[ToolDescriptor] = []
        for key, descriptor in list(self._tools.items()):
            if pattern and pattern != "*":
                bare = key.split("::")[-1]
                if not (glob_match(key, pattern) or glob_match(bare, pattern)):
                    continue
            if server and not glob_match(descriptor.server, server):
                continue
            if wanted and not wanted & {c.value for c in descriptor.categories}:
                continue
            if floor is not None and _descriptor_risk(descriptor).score < floor:
                continue
            out.append(descriptor)
        return sorted(out, key=lambda d: d.qualified_name)

    def categories_for(self, name: str, server: str = "") -> List[ActionCategory]:
        """Categories of a tool, empty when it is unknown."""
        descriptor = self.get(name, server)
        return list(descriptor.categories) if descriptor else []

    def risk_for(self, name: str, server: str = "") -> RiskLevel:
        """Inherent risk of a tool, derived from its categories."""
        descriptor = self.get(name, server)
        return _descriptor_risk(descriptor) if descriptor else RiskLevel.MEDIUM

    # -- drift ------------------------------------------------------------ #
    def check_drift(self, descriptor: ToolDescriptor) -> SchemaDrift:
        """Compare a freshly advertised descriptor against the pin, read-only."""
        key = descriptor.qualified_name
        existing = self._tools.get(key)
        observed = schema_hash(descriptor)
        if existing is None:
            return SchemaDrift(
                tool=descriptor.name,
                server=descriptor.server,
                pinned_hash="",
                observed_hash=observed,
            )
        return SchemaDrift(
            tool=descriptor.name,
            server=descriptor.server,
            pinned_hash=existing.schema_hash or schema_hash(existing),
            observed_hash=observed,
            changed_fields=_diff_descriptors(existing, descriptor),
        )

    def drifted(self) -> List[SchemaDrift]:
        """Every drift recorded since the catalog was created."""
        return [d for d in self._drift.values() if d.is_drift]

    def clear_drift(self, qualified_name: str = "") -> None:
        """Acknowledge drift for one tool, or all of them."""
        with self._lock:
            if qualified_name:
                self._drift.pop(qualified_name, None)
            else:
                self._drift.clear()

    # -- bulk I/O --------------------------------------------------------- #
    def export(self) -> Dict[str, Any]:
        """Serialise the whole catalog, suitable for pinning into git."""
        return {
            "version": "1",
            "exported_at": utc_now(),
            "tools": [descriptor_to_dict(d) for d in self.all()],
        }

    def import_(self, data: Dict[str, Any], *, replace: bool = False) -> int:
        """Load an exported catalog.  Returns the number of tools imported."""
        tools = (data or {}).get("tools") or []
        if not isinstance(tools, list):
            raise ValidationError("catalog import: 'tools' must be a list")
        with self._lock:
            if replace:
                self._tools.clear()
                self._drift.clear()
            count = 0
            for entry in tools:
                try:
                    descriptor = descriptor_from_dict(entry)
                except ValidationError as exc:
                    logger.warning("catalog.import_skipped", extra={"error": str(exc)})
                    continue
                self._tools[descriptor.qualified_name] = descriptor
                count += 1
        logger.info("catalog.imported", extra={"count": count})
        return count

    def dump_json(self, *, indent: int = 2) -> str:
        """Export as a JSON string."""
        return json.dumps(self.export(), indent=indent, sort_keys=True, ensure_ascii=False)

    # -- container protocol ----------------------------------------------- #
    def all(self) -> List[ToolDescriptor]:
        """Every descriptor, sorted by qualified name."""
        return sorted(self._tools.values(), key=lambda d: d.qualified_name)

    def names(self) -> List[str]:
        """Every qualified tool name."""
        return sorted(self._tools)

    def stats(self) -> Dict[str, Any]:
        """Counts by server and category, for the dashboard."""
        by_server: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        for descriptor in self._tools.values():
            by_server[descriptor.server] = by_server.get(descriptor.server, 0) + 1
            for category in descriptor.categories:
                by_category[category.value] = by_category.get(category.value, 0) + 1
        return {
            "tools": len(self._tools),
            "servers": len(by_server),
            "by_server": by_server,
            "by_category": by_category,
            "drifted": len(self.drifted()),
        }

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: object) -> bool:
        return self.get(str(name)) is not None

    def __iter__(self) -> Iterator[ToolDescriptor]:
        return iter(self.all())

    @classmethod
    def from_dicts(cls, entries: Sequence[Dict[str, Any]], **kwargs: Any) -> "ToolCatalog":
        """Build a catalog from raw mappings, skipping unparseable entries."""
        catalog = cls(**kwargs)
        for entry in entries or []:
            try:
                catalog.register(descriptor_from_dict(entry))
            except ValidationError as exc:
                logger.warning("catalog.entry_skipped", extra={"error": str(exc)})
        return catalog


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _descriptor_risk(descriptor: ToolDescriptor) -> RiskLevel:
    """Highest default risk across a tool's categories."""
    if not descriptor.categories:
        return RiskLevel.MEDIUM
    return max((c.default_risk for c in descriptor.categories), key=lambda r: r.score)


def _risk_score(level: str) -> Optional[int]:
    if not level:
        return None
    try:
        return RiskLevel(str(level).strip().lower()).score
    except ValueError:
        return None


def _diff_descriptors(old: ToolDescriptor, new: ToolDescriptor) -> List[str]:
    """Name the fields that changed between two versions of a tool.

    Used to make drift alerts actionable - "description changed" and "a required
    parameter was added" call for very different responses.
    """
    changed: List[str] = []
    if old.description != new.description:
        changed.append("description")
    if old.transport != new.transport:
        changed.append("transport")
    if {c.value for c in old.categories} != {c.value for c in new.categories}:
        changed.append("categories")
    if old.reversible != new.reversible:
        changed.append("reversible")
    if old.idempotent != new.idempotent:
        changed.append("idempotent")
    if old.requires_approval != new.requires_approval:
        changed.append("requires_approval")

    old_params = {p.name: p for p in old.parameters}
    new_params = {p.name: p for p in new.parameters}
    for added in sorted(set(new_params) - set(old_params)):
        changed.append(f"parameter added: {added}")
    for removed in sorted(set(old_params) - set(new_params)):
        changed.append(f"parameter removed: {removed}")
    for name in sorted(set(old_params) & set(new_params)):
        before, after = old_params[name], new_params[name]
        if (before.type, before.required, before.pattern, tuple(before.enum)) != (
            after.type,
            after.required,
            after.pattern,
            tuple(after.enum),
        ):
            changed.append(f"parameter changed: {name}")
    return changed
