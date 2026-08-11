"""Loading, signing and verifying policy bundles.

A policy bundle is the distribution unit: a versioned set of policies that ships
from a control plane to every gateway.  That makes the bundle itself a supply
chain, and an unsigned bundle is an obvious way to attack a security control -
rewrite ``effect: deny`` to ``effect: allow`` on disk and every defence
evaporates silently.

This module therefore does three things:

* **Load** ``.yaml`` / ``.yml`` / ``.json`` packs from a directory or from the
  built-in pack set shipped inside the wheel.
* **Sign / verify** a bundle with a detached signature over a canonical
  serialisation, so signatures are stable across formatting and key ordering.
* **Merge** several bundles into one, refusing silent rule-id collisions
  between packs.

Everything is standard library only; PyYAML is used when present but is never
required.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..core.config import Settings, get_settings, parse_simple_yaml
from ..core.crypto import Signer, build_signer, canonical_json, fingerprint, sha256_hex
from ..core.errors import PolicyError, ValidationError
from ..core.logging import get_logger
from ..core.types import utc_now
from .model import Policy, PolicyBundle, validate_bundle

__all__ = [
    "BUILTIN_PACKS",
    "builtin_pack_dir",
    "parse_policy_document",
    "load_bundle_file",
    "load_bundles",
    "load_builtin_bundles",
    "builtin_bundles",
    "merge_bundles",
    "sign_bundle",
    "verify_bundle",
    "verify_bundle_detailed",
    "bundle_digest",
    "signer_from_settings",
    "dump_bundle",
    "load_from_settings",
]

logger = get_logger(__name__)

#: The packs shipped with AegisAgent, in load order.  Order matters only for
#: ``defaults`` resolution - effects themselves are order-independent because
#: arbitration always takes the most restrictive outcome.
BUILTIN_PACKS: Tuple[str, ...] = (
    "baseline",
    "corebreak",
    "prompt-injection",
    "secrets",
    "destructive",
    "egress",
    "mcp-hardening",
    "finance-payment",
)

_DOC_SUFFIXES = (".yaml", ".yml", ".json")


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def parse_policy_document(text: str, *, source: str = "<string>") -> Dict[str, Any]:
    """Parse a policy document from YAML or JSON text.

    PyYAML is preferred when installed because it handles the full language;
    otherwise the project's own block-subset parser is used.  Both produce plain
    dicts, so nothing downstream depends on which path ran.
    """
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            return json.loads(text) or {}
        except json.JSONDecodeError as exc:
            raise PolicyError(
                f"{source}: invalid JSON policy document: {exc}",
                details={"source": source},
            ) from exc

    try:  # pragma: no cover - depends on the host environment
        import yaml  # type: ignore

        parsed = yaml.safe_load(text)
    except ImportError:
        parsed = parse_simple_yaml(text)
    except Exception as exc:  # noqa: BLE001 - surface any YAML error as ours
        raise PolicyError(
            f"{source}: invalid YAML policy document: {exc}",
            details={"source": source},
        ) from exc

    if parsed is None:
        return {}
    if not isinstance(parsed, dict):
        raise PolicyError(
            f"{source}: a policy document must be a mapping, got "
            f"{type(parsed).__name__}",
            details={"source": source},
        )
    return parsed


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def builtin_pack_dir() -> Path:
    """Absolute path to the built-in pack directory inside the package."""
    return Path(__file__).resolve().parent / "builtin"


def load_bundle_file(path: Any, *, validate: bool = True) -> PolicyBundle:
    """Load and validate a single pack file.

    Raises
    ------
    PolicyError
        When the file is missing or malformed.
    ValidationError
        When ``validate`` is set and the bundle has structural problems.
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise PolicyError(
            f"policy pack not found: {file_path}",
            details={"path": str(file_path)},
        )
    try:
        text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(
            f"cannot read policy pack {file_path}: {exc}",
            details={"path": str(file_path)},
        ) from exc

    data = parse_policy_document(text, source=str(file_path))
    if not data:
        raise PolicyError(
            f"policy pack {file_path} is empty",
            details={"path": str(file_path)},
        )

    bundle = PolicyBundle.from_dict(data, source=str(file_path))
    # A bare pack file has no id of its own; fall back to the file stem so log
    # lines and signatures name something an operator recognises.
    if not bundle.id:
        bundle.id = file_path.stem
    for policy in bundle.policies:
        if not policy.id:
            policy.id = file_path.stem

    if validate:
        problems = validate_bundle(bundle)
        if problems:
            raise ValidationError(
                f"policy pack {file_path} failed validation:\n  - "
                + "\n  - ".join(problems),
                details={"path": str(file_path), "problems": problems},
            )
    logger.debug(
        "policy.bundle_loaded",
        extra={"path": str(file_path), "rules": bundle.rule_count},
    )
    return bundle


def load_bundles(
    directory: Any,
    *,
    names: Optional[Sequence[str]] = None,
    validate: bool = True,
    missing_ok: bool = False,
) -> List[PolicyBundle]:
    """Load every pack in a directory, optionally filtered to ``names``.

    ``names`` are file stems (``corebreak``), which is what the
    ``policy.enabled_packs`` setting holds.  Loading is deterministic: when a
    name is given the packs come back in that order, otherwise sorted by
    filename, so two gateways with the same config compile the same policy.
    """
    base = Path(directory)
    if not base.is_dir():
        if missing_ok:
            logger.warning("policy.bundle_dir_missing", extra={"path": str(base)})
            return []
        raise PolicyError(
            f"policy bundle directory not found: {base}",
            details={"path": str(base)},
        )

    if names:
        paths: List[Path] = []
        for name in names:
            found = _resolve_pack(base, str(name))
            if found is None:
                if missing_ok:
                    logger.warning(
                        "policy.pack_missing", extra={"pack": name, "dir": str(base)}
                    )
                    continue
                raise PolicyError(
                    f"enabled policy pack {name!r} not found in {base}",
                    details={"pack": str(name), "dir": str(base)},
                )
            paths.append(found)
    else:
        paths = sorted(
            (p for p in base.iterdir() if p.suffix.lower() in _DOC_SUFFIXES),
            key=lambda p: p.name,
        )

    return [load_bundle_file(p, validate=validate) for p in paths]


def _resolve_pack(base: Path, name: str) -> Optional[Path]:
    """Find ``name`` in ``base``, with or without an extension."""
    candidate = base / name
    if candidate.is_file() and candidate.suffix.lower() in _DOC_SUFFIXES:
        return candidate
    for suffix in _DOC_SUFFIXES:
        candidate = base / f"{name}{suffix}"
        if candidate.is_file():
            return candidate
    return None


def load_builtin_bundles(
    names: Optional[Sequence[str]] = None,
    *,
    validate: bool = True,
) -> List[PolicyBundle]:
    """Load the packs shipped inside the package.

    Defaults to :data:`BUILTIN_PACKS`.  Missing packs are tolerated so a partial
    checkout or a trimmed wheel degrades to "fewer rules" rather than "no
    gateway".
    """
    return load_bundles(
        builtin_pack_dir(),
        names=list(names) if names is not None else list(BUILTIN_PACKS),
        validate=validate,
        missing_ok=True,
    )


def builtin_bundles(
    names: Optional[Sequence[str]] = None,
    *,
    validate: bool = True,
) -> List[PolicyBundle]:
    """Contract-named alias for :func:`load_builtin_bundles`.

    Reads the YAML packs shipped under ``aegis/policy/builtin/`` using a path
    resolution that falls back to ``importlib.resources`` when the source tree
    is not present (e.g. frozen / installed-from-wheel deployments).
    """
    return load_builtin_bundles(names=names, validate=validate)


def load_from_settings(settings: Optional[Settings] = None) -> List[PolicyBundle]:
    """Load built-in packs plus any operator packs from ``policy.bundle_dir``.

    Operator packs are loaded last so their ``defaults`` win, but note that
    individual rule effects are still arbitrated most-restrictive-first: a local
    pack can tighten the built-ins, never silently loosen them.
    """
    settings = settings or get_settings()
    enabled = settings.get("policy.enabled_packs", list(BUILTIN_PACKS))
    bundles = load_builtin_bundles(enabled)

    bundle_dir = str(settings.get("policy.bundle_dir", "") or "")
    if bundle_dir:
        path = Path(bundle_dir)
        if path.is_dir():
            builtin = builtin_pack_dir().resolve()
            if path.resolve() != builtin:
                bundles.extend(load_bundles(path, missing_ok=True))
    return bundles


# --------------------------------------------------------------------------- #
# Merging
# --------------------------------------------------------------------------- #
def merge_bundles(
    bundles: Sequence[PolicyBundle],
    *,
    bundle_id: str = "merged",
    strict: bool = True,
) -> PolicyBundle:
    """Flatten several bundles into one.

    Rule ids must be globally unique: two packs defining ``deny-rm-rf``
    differently is an authoring bug that would otherwise produce a decision
    nobody can explain.  In ``strict`` mode the collision raises; otherwise the
    later rule is dropped and the conflict logged.
    """
    policies: List[Policy] = []
    seen_policy_ids: Dict[str, str] = {}
    seen_rule_ids: Dict[str, str] = {}
    versions: List[str] = []

    for bundle in bundles or []:
        versions.append(bundle.version)
        for policy in bundle.policies:
            if policy.id in seen_policy_ids:
                message = (
                    f"policy id {policy.id!r} defined by both "
                    f"{seen_policy_ids[policy.id]!r} and {bundle.source or bundle.id!r}"
                )
                if strict:
                    raise PolicyError(message, details={"policy_id": policy.id})
                logger.warning("policy.duplicate_policy", extra={"policy": policy.id})
                continue
            seen_policy_ids[policy.id] = bundle.source or bundle.id

            kept = []
            for rule in policy.rules:
                if rule.id in seen_rule_ids:
                    message = (
                        f"rule id {rule.id!r} defined by both "
                        f"{seen_rule_ids[rule.id]!r} and {policy.id!r}"
                    )
                    if strict:
                        raise PolicyError(message, details={"rule_id": rule.id})
                    logger.warning("policy.duplicate_rule", extra={"rule": rule.id})
                    continue
                seen_rule_ids[rule.id] = policy.id
                kept.append(rule)
            policy.rules = kept
            policies.append(policy)

    return PolicyBundle(
        id=bundle_id,
        version="+".join(sorted({v for v in versions if v and v != "0.0.0"})) or "0.0.0",
        policies=policies,
        source="<merged>",
        created_at=utc_now(),
        metadata={"merged_from": [b.id for b in bundles or []]},
    )


# --------------------------------------------------------------------------- #
# Signing
# --------------------------------------------------------------------------- #
def bundle_digest(bundle: PolicyBundle) -> str:
    """Stable SHA-256 over the signature-covered view of a bundle.

    Used for change detection and for the ``policy_bundle_version`` stamped onto
    every decision, so an audit can prove which exact rule set produced it.
    """
    return sha256_hex(canonical_json(bundle.signing_payload()))


def sign_bundle(bundle: PolicyBundle, signer: Signer) -> PolicyBundle:
    """Attach a detached signature to a bundle, returning it for chaining.

    The signature covers :meth:`PolicyBundle.signing_payload`, which excludes
    the signature itself and the local filesystem path.
    """
    bundle.metadata["signed_by"] = signer.key_id
    bundle.metadata["signature_algorithm"] = getattr(signer, "algorithm", "unknown")
    # Sign the canonical payload *before* the self-referential digest is added,
    # otherwise the signed bytes and the verified bytes would differ.
    bundle.signature = signer.sign(bundle.signing_payload())
    bundle.metadata["digest"] = bundle_digest(bundle)
    logger.info(
        "policy.bundle_signed",
        extra={"bundle": bundle.id, "key_id": signer.key_id},
    )
    return bundle


def verify_bundle(
    bundle: PolicyBundle,
    signer: Signer,
    *,
    required: bool = True,
) -> bool:
    """Check a bundle's signature.

    Contract shape: returns ``True`` when the signature is present and valid (or
    when signing is not required).  The caller decides whether an unsigned pack
    is a hard failure (production) or a warning (local development); that policy
    belongs in the engine, not here.  Use :func:`verify_bundle_detailed` when a
    human-readable reason is needed.
    """
    ok, _ = verify_bundle_detailed(bundle, signer, required=required)
    return ok


def verify_bundle_detailed(
    bundle: PolicyBundle,
    signer: Signer,
    *,
    required: bool = True,
) -> Tuple[bool, str]:
    """Detailed variant of :func:`verify_bundle` - returns ``(ok, reason)``."""
    if not bundle.signature:
        if required:
            return (False, f"bundle {bundle.id!r} is unsigned")
        return (True, f"bundle {bundle.id!r} is unsigned (signature not required)")

    try:
        ok = signer.verify(bundle.signing_payload(), bundle.signature)
    except Exception as exc:  # noqa: BLE001 - a bad key must not crash the load
        return (False, f"bundle {bundle.id!r} signature check errored: {exc}")

    if not ok:
        return (
            False,
            f"bundle {bundle.id!r} signature is invalid - the pack was modified "
            f"after signing (digest {fingerprint(bundle.signing_payload())})",
        )
    return (True, f"bundle {bundle.id!r} signature verified with key {signer.key_id!r}")


def signer_from_settings(settings: Optional[Settings] = None) -> Signer:
    """Build the bundle signer configured under the ``security`` section."""
    settings = settings or get_settings()
    return build_signer(
        algorithm=str(settings.get("security.signing_algorithm", "hmac-sha256")),
        key=str(settings.get("security.signing_key", "") or ""),
        key_id="policy-bundle",
    )


# --------------------------------------------------------------------------- #
# Export
# --------------------------------------------------------------------------- #
def dump_bundle(bundle: PolicyBundle, path: Any, *, indent: int = 2) -> Path:
    """Write a bundle to disk as JSON, creating parent directories."""
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(bundle.to_dict(), indent=indent, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )
    return out_path
