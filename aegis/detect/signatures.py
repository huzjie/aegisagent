"""YAML-backed regex signature engine.

Signatures live in ``aegis/detect/signatures/*.yaml`` so security engineers can
ship new detections without touching Python.  Each pack declares an ``id``, a
``version`` and a list of signature records:

.. code-block:: yaml

    id: prompt-injection
    version: "2026.08.11"
    signatures:
      - { id: pi-001, pattern: 'ignore\\s+previous', severity: high, ... }

Design notes
------------
* Every pattern is compiled once at load time; a malformed pattern disables
  that single signature instead of failing the whole pack (fail-open per rule,
  fail-closed is handled by the policy layer).
* The bundled minimal YAML parser nests the list under ``signatures.signatures``
  whereas PyYAML yields ``signatures``; :func:`_extract_records` accepts both,
  plus a bare top-level list, so packs load identically either way.
* Scanning is linear in the number of signatures.  Packs are cached per file
  mtime so repeated ``from_settings`` calls are free.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..core.config import load_structured_file
from ..core.errors import ValidationError
from ..core.logging import get_logger
from ..core.types import Severity
from ..core.utils import truncate

__all__ = [
    "Signature",
    "SignatureHit",
    "SignatureSet",
    "SIGNATURE_DIR",
    "load_pack",
    "load_all_packs",
    "default_signature_set",
]

LOGGER = get_logger("detect.signatures")

#: Directory holding the shipped YAML packs.
SIGNATURE_DIR = Path(__file__).resolve().parent / "signatures"

#: Cap on scanned text length per signature pass (regex DoS guard).
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


def _as_list(value: Any) -> List[str]:
    """Coerce a YAML scalar/list into a list of trimmed strings."""
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [part.strip() for part in str(value).split(",") if part.strip()]


@dataclass
class Signature:
    """One compiled detection rule.

    Attributes:
        id: Stable rule identifier, unique within a pack (e.g. ``pi-014``).
        pattern: The raw regular expression source.
        severity: Severity assigned to matches.
        confidence: Base confidence in ``[0, 1]``; the detector may scale it.
        description: Human-readable explanation, may be Chinese or English.
        tags: Free-form labels; ``en``/``zh`` denote the language the rule
            targets, other tags group techniques (``override``, ``ssrf`` ...).
        references: External links (OWASP, CVE, vendor advisories).
        lang: Primary language this signature is written for.
        enabled: Disabled signatures stay loaded but never match.
        flags: Extra regex flags requested by the pack (``i``, ``m``, ``s``).
    """

    id: str
    pattern: str
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.6
    description: str = ""
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    lang: str = "any"
    enabled: bool = True
    flags: str = ""
    pack: str = ""
    regex: Optional[re.Pattern[str]] = field(default=None, repr=False, compare=False)
    compile_error: str = ""

    def compile(self) -> "Signature":
        """Compile :attr:`pattern`, recording (not raising) any regex error."""
        flags = re.UNICODE
        for flag in (self.flags or "").lower():
            flags |= {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL, "x": re.VERBOSE}.get(flag, 0)
        try:
            self.regex = re.compile(self.pattern, flags)
            self.compile_error = ""
        except re.error as exc:
            self.regex = None
            self.compile_error = str(exc)
            LOGGER.warning("signature failed to compile", signature=self.id, error=str(exc))
        return self

    @property
    def usable(self) -> bool:
        """True when the signature is enabled and successfully compiled."""
        return self.enabled and self.regex is not None

    def search(self, text: str) -> Optional[re.Match[str]]:
        """Return the first match in ``text`` or ``None``."""
        if not self.usable or not text:
            return None
        return self.regex.search(text)  # type: ignore[union-attr]

    def finditer(self, text: str, limit: int = 8) -> List[re.Match[str]]:
        """Return up to ``limit`` matches in ``text``."""
        if not self.usable or not text:
            return []
        out: List[re.Match[str]] = []
        for match in self.regex.finditer(text):  # type: ignore[union-attr]
            out.append(match)
            if len(out) >= limit:
                break
        return out

    @classmethod
    def from_mapping(cls, data: Dict[str, Any], pack: str = "") -> "Signature":
        """Build (and compile) a signature from a parsed YAML record.

        Raises:
            ValidationError: When ``id`` or ``pattern`` is missing.
        """
        sig_id = str(data.get("id") or "").strip()
        pattern = data.get("pattern")
        if not sig_id:
            raise ValidationError("signature record is missing 'id'", details={"pack": pack})
        if not isinstance(pattern, str) or not pattern:
            raise ValidationError(f"signature {sig_id} is missing 'pattern'", details={"pack": pack})
        tags = _as_list(data.get("tags"))
        lang = str(data.get("lang") or "").strip().lower()
        if not lang:
            lang = "zh" if "zh" in tags else ("en" if "en" in tags else "any")
        confidence = data.get("confidence", 0.6)
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = 0.6
        return cls(
            id=sig_id,
            pattern=pattern,
            severity=_as_severity(data.get("severity")),
            confidence=max(0.0, min(1.0, confidence)),
            description=str(data.get("description") or "").strip(),
            tags=tags,
            references=_as_list(data.get("references")),
            lang=lang,
            enabled=data.get("enabled", True) is not False,
            flags=str(data.get("flags") or ""),
            pack=pack,
        ).compile()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "pack": self.pack,
            "pattern": self.pattern,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "description": self.description,
            "tags": self.tags,
            "lang": self.lang,
            "enabled": self.enabled,
            "usable": self.usable,
            "compile_error": self.compile_error,
        }


@dataclass
class SignatureHit:
    """A signature that fired, with enough context to justify the alert."""

    signature: Signature
    matched: str
    start: int
    end: int
    location: str = ""
    line: int = 0

    @property
    def id(self) -> str:
        return self.signature.id

    @property
    def severity(self) -> Severity:
        return self.signature.severity

    @property
    def confidence(self) -> float:
        return self.signature.confidence

    @property
    def evidence(self) -> str:
        """Compact evidence line: ``[pi-001] matched text``."""
        return f"[{self.signature.id}] {truncate(self.matched, 160)}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.signature.id,
            "pack": self.signature.pack,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "description": self.signature.description,
            "matched": truncate(self.matched, 160),
            "location": self.location,
            "span": [self.start, self.end],
            "tags": self.signature.tags,
        }


def _extract_records(document: Any) -> List[Dict[str, Any]]:
    """Pull the signature records out of a parsed pack, tolerating both parsers.

    Accepts ``{"signatures": [...]}`` (PyYAML), ``{"signatures": {"signatures":
    [...]}}`` (bundled minimal parser) and a bare top-level list.
    """
    if isinstance(document, list):
        return [r for r in document if isinstance(r, dict)]
    if not isinstance(document, dict):
        return []
    node: Any = document.get("signatures", [])
    # The minimal parser wraps list-under-key one level deeper.
    for _ in range(3):
        if isinstance(node, dict):
            if "signatures" in node:
                node = node["signatures"]
                continue
            values = [v for v in node.values() if isinstance(v, list)]
            node = values[0] if values else []
        break
    if isinstance(node, list):
        return [r for r in node if isinstance(r, dict)]
    return []


def load_pack(path: Path) -> Tuple[str, str, List[Signature]]:
    """Load one YAML pack.

    Args:
        path: Path to the ``.yaml`` file.

    Returns:
        ``(pack_id, version, signatures)``.  Individual malformed records are
        logged and skipped so one typo cannot disable a whole pack.
    """
    document = load_structured_file(path)
    pack_id = str((document or {}).get("id") or path.stem)
    version = str((document or {}).get("version") or "0")
    signatures: List[Signature] = []
    seen: set[str] = set()
    for record in _extract_records(document):
        try:
            signature = Signature.from_mapping(record, pack=pack_id)
        except ValidationError as exc:
            LOGGER.warning("skipping malformed signature", pack=pack_id, error=str(exc))
            continue
        if signature.id in seen:
            LOGGER.warning("duplicate signature id", pack=pack_id, signature=signature.id)
            continue
        seen.add(signature.id)
        signatures.append(signature)
    return pack_id, version, signatures


def load_all_packs(directory: Optional[Path] = None) -> Dict[str, Tuple[str, List[Signature]]]:
    """Load every ``*.yaml`` pack in ``directory`` (defaults to the bundled one).

    Returns:
        Mapping ``pack_id -> (version, signatures)``.
    """
    directory = directory or SIGNATURE_DIR
    out: Dict[str, Tuple[str, List[Signature]]] = {}
    if not directory.is_dir():
        LOGGER.warning("signature directory missing", path=str(directory))
        return out
    for path in sorted(directory.glob("*.yaml")):
        try:
            pack_id, version, signatures = load_pack(path)
        except Exception as exc:  # noqa: BLE001 - a bad pack must not kill startup
            LOGGER.error("failed to load signature pack", path=str(path), error=str(exc))
            continue
        out[pack_id] = (version, signatures)
    return out


class SignatureSet:
    """An indexed, thread-safe collection of compiled signatures.

    Signatures are indexed by pack and by tag so a detector can cheaply scan
    only the rules relevant to it (``set.scan(text, packs=["exfiltration"])``).
    """

    def __init__(self, signatures: Optional[Iterable[Signature]] = None) -> None:
        """Args:
        signatures: Initial signatures; usually supplied by :meth:`from_directory`.
        """
        self._lock = threading.RLock()
        self._signatures: List[Signature] = []
        self._by_id: Dict[str, Signature] = {}
        self._by_pack: Dict[str, List[Signature]] = {}
        self._by_tag: Dict[str, List[Signature]] = {}
        self.versions: Dict[str, str] = {}
        for signature in signatures or []:
            self.add(signature)

    # ------------------------------------------------------------------ #
    # Construction
    # ------------------------------------------------------------------ #
    @classmethod
    def from_directory(cls, directory: Optional[Path] = None) -> "SignatureSet":
        """Build a set from every pack in a directory."""
        instance = cls()
        for pack_id, (version, signatures) in load_all_packs(directory).items():
            instance.versions[pack_id] = version
            for signature in signatures:
                instance.add(signature)
        LOGGER.info(
            "signature set loaded",
            packs=len(instance.versions),
            signatures=len(instance._signatures),
            unusable=sum(1 for s in instance._signatures if not s.usable),
        )
        return instance

    @classmethod
    def load_all(cls, directory: Optional[Path] = None) -> "Dict[str, SignatureSet]":
        """Load each YAML pack as its own :class:`SignatureSet`.

        Unlike :meth:`from_directory` (which merges every pack into one set),
        this returns ``{pack_id: SignatureSet}`` so a caller can load and scan a
        single pack in isolation.  Used by the signature package so detectors can
        address rules by pack.

        Args:
            directory: Pack directory; defaults to the bundled
                ``aegis/detect/signatures`` directory.

        Returns:
            Mapping of pack id to a self-contained signature set.
        """
        return {
            pack_id: cls(signatures=signatures)
            for pack_id, (version, signatures) in load_all_packs(directory).items()
        }

    @classmethod
    def from_records(cls, records: Sequence[Dict[str, Any]], pack: str = "inline") -> "SignatureSet":
        """Build a set from in-memory records (tests, API-supplied rules)."""
        instance = cls()
        for record in records:
            try:
                instance.add(Signature.from_mapping(record, pack=pack))
            except ValidationError as exc:
                LOGGER.warning("skipping inline signature", error=str(exc))
        return instance

    # ------------------------------------------------------------------ #
    # Mutation
    # ------------------------------------------------------------------ #
    def add(self, signature: Signature) -> None:
        """Insert a signature, replacing any earlier rule with the same id."""
        with self._lock:
            if signature.id in self._by_id:
                self.remove(signature.id)
            self._signatures.append(signature)
            self._by_id[signature.id] = signature
            self._by_pack.setdefault(signature.pack, []).append(signature)
            for tag in signature.tags:
                self._by_tag.setdefault(tag.lower(), []).append(signature)

    def remove(self, signature_id: str) -> bool:
        """Remove a signature by id. Returns ``True`` when something was removed."""
        with self._lock:
            signature = self._by_id.pop(signature_id, None)
            if signature is None:
                return False
            self._signatures = [s for s in self._signatures if s.id != signature_id]
            for bucket in (self._by_pack, self._by_tag):
                for key, items in list(bucket.items()):
                    bucket[key] = [s for s in items if s.id != signature_id]
            return True

    def disable(self, *signature_ids: str) -> int:
        """Disable signatures by id (kept loaded, never matched)."""
        count = 0
        with self._lock:
            for sid in signature_ids:
                signature = self._by_id.get(sid)
                if signature and signature.enabled:
                    signature.enabled = False
                    count += 1
        return count

    # ------------------------------------------------------------------ #
    # Query
    # ------------------------------------------------------------------ #
    def get(self, signature_id: str) -> Optional[Signature]:
        """Look up one signature by id."""
        return self._by_id.get(signature_id)

    def pack(self, pack_id: str) -> List[Signature]:
        """All signatures belonging to ``pack_id``."""
        return list(self._by_pack.get(pack_id, []))

    def tagged(self, tag: str) -> List[Signature]:
        """All signatures carrying ``tag``."""
        return list(self._by_tag.get(tag.lower(), []))

    def select(
        self,
        packs: Optional[Sequence[str]] = None,
        tags: Optional[Sequence[str]] = None,
        min_confidence: float = 0.0,
    ) -> List[Signature]:
        """Filter signatures by pack, tag and minimum confidence."""
        with self._lock:
            candidates = list(self._signatures)
        if packs:
            wanted = {p.lower() for p in packs}
            candidates = [s for s in candidates if s.pack.lower() in wanted]
        if tags:
            wanted_tags = {t.lower() for t in tags}
            candidates = [s for s in candidates if wanted_tags & {t.lower() for t in s.tags}]
        if min_confidence > 0:
            candidates = [s for s in candidates if s.confidence >= min_confidence]
        return candidates

    # ------------------------------------------------------------------ #
    # Scanning
    # ------------------------------------------------------------------ #
    def scan(
        self,
        text: str,
        *,
        packs: Optional[Sequence[str]] = None,
        tags: Optional[Sequence[str]] = None,
        location: str = "",
        max_hits: int = 64,
        matches_per_signature: int = 2,
    ) -> List[SignatureHit]:
        """Run signatures against ``text``.

        Args:
            text: Content to scan (truncated to :data:`MAX_SCAN_CHARS`).
            packs: Restrict to these pack ids.
            tags: Restrict to signatures carrying any of these tags.
            location: Provenance label copied onto each hit.
            max_hits: Global cap on returned hits.
            matches_per_signature: Cap per individual signature.

        Returns:
            Hits ordered by ``severity * confidence`` descending.
        """
        if not text:
            return []
        haystack = text[:MAX_SCAN_CHARS]
        hits: List[SignatureHit] = []
        for signature in self.select(packs=packs, tags=tags):
            if not signature.usable:
                continue
            for match in signature.finditer(haystack, limit=matches_per_signature):
                matched = match.group(0)
                hits.append(
                    SignatureHit(
                        signature=signature,
                        matched=matched,
                        start=match.start(),
                        end=match.end(),
                        location=location,
                        line=haystack.count("\n", 0, match.start()) + 1,
                    )
                )
                if len(hits) >= max_hits:
                    break
            if len(hits) >= max_hits:
                break
        hits.sort(key=lambda h: h.severity.score * h.confidence, reverse=True)
        return hits

    def matches_any(self, text: str, *, packs: Optional[Sequence[str]] = None) -> bool:
        """Fast boolean probe - stops at the first firing signature."""
        haystack = (text or "")[:MAX_SCAN_CHARS]
        for signature in self.select(packs=packs):
            if signature.search(haystack) is not None:
                return True
        return False

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #
    def __len__(self) -> int:
        return len(self._signatures)

    def __iter__(self):
        return iter(list(self._signatures))

    def stats(self) -> Dict[str, Any]:
        """Counts by pack / severity plus any compile failures."""
        by_pack = {pack: len(items) for pack, items in self._by_pack.items() if pack}
        by_severity: Dict[str, int] = {}
        broken: List[str] = []
        for signature in self._signatures:
            by_severity[signature.severity.value] = by_severity.get(signature.severity.value, 0) + 1
            if signature.compile_error:
                broken.append(f"{signature.id}: {signature.compile_error}")
        return {
            "total": len(self._signatures),
            "packs": by_pack,
            "versions": dict(self.versions),
            "by_severity": by_severity,
            "disabled": sum(1 for s in self._signatures if not s.enabled),
            "compile_errors": broken,
        }


_DEFAULT_SET: Optional[SignatureSet] = None
_DEFAULT_LOCK = threading.Lock()


def default_signature_set(reload: bool = False) -> SignatureSet:
    """Process-wide signature set loaded from the bundled pack directory.

    Args:
        reload: Force a re-read from disk (used by the hot-reload watcher).
    """
    global _DEFAULT_SET
    with _DEFAULT_LOCK:
        if _DEFAULT_SET is None or reload:
            _DEFAULT_SET = SignatureSet.from_directory()
        return _DEFAULT_SET
