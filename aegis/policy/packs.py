"""Catalogue of the policy packs shipped with (or available to) AegisAgent.

A *pack* is a single YAML file that becomes one :class:`~aegis.policy.model.Policy`
when loaded.  Operators and the control-plane UI need a cheap, read-only view of
what is available without compiling the whole rule set, so this module exposes a
:class:`PolicyPackInfo` dataclass and :func:`list_packs`, which is what the CLI
``aegis policy list`` and the API ``GET /policies`` render.

The implementation is standard-library only and reuses the bundle loader so the
metadata can never drift from what the engine actually compiles.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from ..core.config import Settings, get_settings
from .bundles import BUILTIN_PACKS, builtin_pack_dir, load_bundles

__all__ = [
    "PolicyPackInfo",
    "list_packs",
    "pack_info",
    "pack_id_of",
]

#: Effects considered "blocking" so the catalogue can flag a pack's posture.
_RESTRICTIVE_EFFECTS = frozenset({"deny", "quarantine", "require_approval", "sandbox"})


@dataclass
class PolicyPackInfo:
    """A read-only, presentation-oriented view of one policy pack file.

    Built from a loaded :class:`~aegis.policy.model.PolicyBundle`; ``pack`` and
    ``policy`` are used loosely as synonyms here because every built-in pack is a
    single-policy document.
    """

    id: str
    name: str
    version: str
    description: str
    rules: int
    path: str
    enabled: bool = True
    signed: bool = False
    signature: Optional[str] = None
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    restrictive_rules: int = 0
    default_effect: Optional[str] = None
    policy_count: int = 1
    health: str = "ok"

    @property
    def short_id(self) -> str:
        """A stable, file-stem friendly identifier."""
        return self.id

    @property
    def is_restrictive(self) -> bool:
        """True when the pack carries at least one blocking rule."""
        return self.restrictive_rules > 0

    def to_dict(self) -> Dict[str, Any]:
        """Serialise for the CLI / API."""
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "rules": self.rules,
            "path": self.path,
            "enabled": self.enabled,
            "signed": self.signed,
            "references": list(self.references),
            "tags": list(self.tags),
            "restrictive_rules": self.restrictive_rules,
            "default_effect": self.default_effect,
            "policy_count": self.policy_count,
            "health": self.health,
        }

    def __str__(self) -> str:  # pragma: no cover - debug convenience
        flag = "" if self.enabled else " [disabled]"
        return (
            f"{self.id} v{self.version} - {self.rules} rules, "
            f"{self.restrictive_rules} blocking{flag} ({self.health})"
        )


def pack_id_of(bundle: Any) -> str:
    """Best-effort pack id for a loaded bundle (file stem when missing)."""
    if getattr(bundle, "id", ""):
        return str(bundle.id)
    if getattr(bundle, "source", ""):
        from pathlib import Path

        return Path(bundle.source).stem
    return "<unknown>"


def pack_info(bundle: Any, *, enabled: bool = True) -> PolicyPackInfo:
    """Build a :class:`PolicyPackInfo` from a loaded bundle object.

    ``bundle`` may be any object exposing ``id``, ``version``, ``policies``,
    ``signature`` and ``source`` (i.e. :class:`~aegis.policy.model.PolicyBundle`).
    """
    policies = list(getattr(bundle, "policies", []) or [])
    first = policies[0] if policies else None

    references: List[str] = []
    tags: List[str] = []
    rules = 0
    restrictive = 0
    default_effect: Optional[str] = None
    for policy in policies:
        default_effect = policy.defaults.get("effect") if policy.defaults else default_effect
        for rule in policy.enabled_rules:
            rules += 1
            if str(rule.effect).lower() in _RESTRICTIVE_EFFECTS:
                restrictive += 1
            references.extend(rule.references or [])
            tags.extend(rule.tags or [])

    name = getattr(first, "name", "") or pack_id_of(bundle)
    description = getattr(first, "description", "") or ""
    version = str(getattr(bundle, "version", "") or "0.0.0")

    # De-duplicate while preserving order.
    seen_r: set[str] = set()
    references = [r for r in references if not (r in seen_r or seen_r.add(r))]
    seen_t: set[str] = set()
    tags = [t for t in tags if not (t in seen_t or seen_t.add(t))]

    signature = getattr(bundle, "signature", "") or None
    source = getattr(bundle, "source", "") or ""
    health = "unsigned" if signature else "ok"
    if policies and not getattr(policies[0], "rules", None):
        health = "empty"

    return PolicyPackInfo(
        id=pack_id_of(bundle),
        name=name,
        version=version,
        description=description,
        rules=rules,
        path=source,
        enabled=enabled,
        signed=bool(signature),
        signature=signature,
        references=references,
        tags=tags,
        restrictive_rules=restrictive,
        default_effect=default_effect,
        policy_count=len(policies),
        health=health,
    )


def list_packs(
    names: Optional[Sequence[str]] = None,
    *,
    directory: Optional[str] = None,
    settings: Optional[Settings] = None,
    include_disabled: bool = False,
    missing_ok: bool = True,
) -> List[PolicyPackInfo]:
    """Return :class:`PolicyPackInfo` for the requested packs.

    Parameters
    ----------
    names:
        Pack file stems to include (e.g. ``["corebreak", "secrets"]``).  When
        ``None`` every built-in pack is listed (or every pack in ``directory``).
    directory:
        Load the catalogue from a directory instead of the built-ins.  This is
        how the CLI shows operator-supplied packs alongside the shipped set.
    settings:
        Used to derive the ``enabled`` flag from ``policy.enabled_packs``; when
        omitted the built-in set is treated as fully enabled.
    include_disabled:
        When ``False`` (default) packs not listed in ``policy.enabled_packs`` are
        omitted entirely.
    """
    settings = settings or get_settings()
    source_dir = directory or str(builtin_pack_dir())
    resolved_names: Optional[List[str]] = (
        list(names) if names is not None else None
    )

    if resolved_names is None:
        resolved_names = list(BUILTIN_PACKS)

    enabled_raw = settings.get("policy.enabled_packs", list(BUILTIN_PACKS))
    enabled_set = set(enabled_raw) if isinstance(enabled_raw, (list, tuple)) else set()

    bundles = load_bundles(
        source_dir,
        names=resolved_names,
        validate=True,
        missing_ok=missing_ok,
    )

    infos: List[PolicyPackInfo] = []
    for bundle in bundles:
        pid = pack_id_of(bundle)
        is_enabled = pid in enabled_set
        if not is_enabled and not include_disabled:
            continue
        infos.append(pack_info(bundle, enabled=is_enabled))

    infos.sort(key=lambda info: (not info.enabled, info.id))
    return infos
