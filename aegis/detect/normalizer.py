"""Layered de-obfuscation so detectors see what the *model* will see.

Attackers do not paste ``ignore previous instructions`` in plain text any more.
The 2026 payloads observed in the wild are wrapped in one or more reversible
encodings: base64 inside a Markdown comment, percent-encoding inside a URL,
hex inside a JSON string, ROT13 inside an HTML attribute.  An LLM happily
decodes those on its own, so the detection layer has to as well.

:func:`decoded_variants` applies a bounded, cycle-safe cascade and returns each
distinct plaintext it recovered together with the chain of transforms used,
which becomes human-readable evidence on the resulting :class:`Finding`.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import html
import re
import zlib
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import unquote_plus

from ..core.utils import normalise_unicode

__all__ = [
    "DecodedVariant",
    "decoded_variants",
    "try_base64",
    "try_hex",
    "try_url",
    "try_rot13",
    "try_html_entities",
    "try_gzip",
    "printable_ratio",
    "looks_like_text",
    "canonical_text",
]

_BASE64_RE = re.compile(r"[A-Za-z0-9+/=_-]{24,}")
_HEX_RE = re.compile(r"(?:0x)?(?:[0-9a-fA-F]{2}[\s:,-]?){12,}")
_PERCENT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_ENTITY_RE = re.compile(r"&(?:#x?[0-9a-fA-F]{2,6}|[a-zA-Z]{2,10});")
_WORD_RE = re.compile(r"[A-Za-z\u4e00-\u9fff]{3,}")

#: Minimum ratio of printable characters for a decode to be considered "text".
PRINTABLE_THRESHOLD = 0.85

#: Maximum number of decode layers.  Two is enough for every payload family we
#: have observed and keeps the cascade cheap.
MAX_DEPTH = 2


@dataclass(frozen=True)
class DecodedVariant:
    """One successfully recovered plaintext.

    Attributes:
        text: The decoded content.
        chain: Ordered transform names, e.g. ``("base64", "url")``.
        source: The encoded substring that produced it (truncated).
    """

    text: str
    chain: Tuple[str, ...]
    source: str = ""

    @property
    def label(self) -> str:
        return "+".join(self.chain) or "plain"


def printable_ratio(text: str) -> float:
    """Fraction of characters that are printable ASCII, CJK or whitespace."""
    if not text:
        return 0.0
    good = 0
    for ch in text:
        code = ord(ch)
        if 32 <= code < 127 or ch in "\r\n\t" or 0x4E00 <= code <= 0x9FFF:
            good += 1
    return good / len(text)


def looks_like_text(text: str, *, min_words: int = 2) -> bool:
    """Heuristic gate: is a decode plausible natural language, not binary noise."""
    if len(text) < 8:
        return False
    if printable_ratio(text) < PRINTABLE_THRESHOLD:
        return False
    return len(_WORD_RE.findall(text)) >= min_words


def try_base64(text: str) -> List[Tuple[str, str]]:
    """Decode standard and URL-safe base64 blobs embedded anywhere in ``text``."""
    out: List[Tuple[str, str]] = []
    for match in _BASE64_RE.finditer(text):
        blob = match.group(0)
        if len(blob) > 8192:
            blob = blob[:8192]
        candidate = blob.replace("-", "+").replace("_", "/")
        padded = candidate + "=" * (-len(candidate) % 4)
        try:
            raw = base64.b64decode(padded, validate=False)
        except (binascii.Error, ValueError):
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if looks_like_text(decoded):
            out.append((decoded, blob))
    return out


def try_hex(text: str) -> List[Tuple[str, str]]:
    """Decode long hex runs (with optional ``0x`` prefix and separators)."""
    out: List[Tuple[str, str]] = []
    for match in _HEX_RE.finditer(text):
        blob = match.group(0)
        cleaned = re.sub(r"(?:0x)|[\s:,-]", "", blob)
        if len(cleaned) % 2:
            cleaned = cleaned[:-1]
        try:
            raw = bytes.fromhex(cleaned[:16384])
        except ValueError:
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if looks_like_text(decoded):
            out.append((decoded, blob))
    return out


def try_url(text: str) -> List[Tuple[str, str]]:
    """Percent-decode when the text actually contains escape sequences."""
    if len(_PERCENT_RE.findall(text)) < 2:
        return []
    try:
        decoded = unquote_plus(text)
    except (UnicodeDecodeError, ValueError):  # pragma: no cover - defensive
        return []
    if decoded != text and looks_like_text(decoded):
        return [(decoded, text[:256])]
    return []


def try_html_entities(text: str) -> List[Tuple[str, str]]:
    """Unescape HTML entities such as ``&#105;&#103;&#110;...``."""
    if len(_ENTITY_RE.findall(text)) < 3:
        return []
    decoded = html.unescape(text)
    if decoded != text and looks_like_text(decoded):
        return [(decoded, text[:256])]
    return []


def try_rot13(text: str) -> List[Tuple[str, str]]:
    """ROT13 is trivial for a model to read and still evades naive regexes."""
    if not re.search(r"[A-Za-z]{6,}", text):
        return []
    decoded = codecs.encode(text, "rot_13")
    # Only interesting if rotating produced recognisable instruction words.
    if re.search(r"(?i)\b(ignore|instruction|system|prompt|password|secret)\b", decoded):
        return [(decoded, text[:256])]
    return []


def try_gzip(text: str) -> List[Tuple[str, str]]:
    """Inflate base64-wrapped gzip/zlib payloads used to hide large prompts."""
    out: List[Tuple[str, str]] = []
    for match in _BASE64_RE.finditer(text):
        blob = match.group(0)[:16384]
        padded = blob.replace("-", "+").replace("_", "/")
        padded += "=" * (-len(padded) % 4)
        try:
            raw = base64.b64decode(padded, validate=False)
        except (binascii.Error, ValueError):
            continue
        for inflate in (_gunzip, _inflate):
            try:
                decoded = inflate(raw).decode("utf-8")
            except (OSError, zlib.error, UnicodeDecodeError, EOFError):
                continue
            if looks_like_text(decoded):
                out.append((decoded, blob))
                break
    return out


def _gunzip(raw: bytes) -> bytes:
    return gzip.decompress(raw)


def _inflate(raw: bytes) -> bytes:
    return zlib.decompress(raw)


#: Transform registry, ordered from most to least common in real payloads.
DECODERS: Dict[str, Callable[[str], List[Tuple[str, str]]]] = {
    "base64": try_base64,
    "url": try_url,
    "html_entity": try_html_entities,
    "hex": try_hex,
    "gzip": try_gzip,
    "rot13": try_rot13,
}


def decoded_variants(
    text: str,
    *,
    max_depth: int = MAX_DEPTH,
    max_variants: int = 12,
    enabled: Optional[List[str]] = None,
) -> List[DecodedVariant]:
    """Recover plaintexts hidden behind up to ``max_depth`` encoding layers.

    The cascade is breadth-first and deduplicated on the decoded text, so a
    payload reachable by several paths is only reported once (with the shortest
    chain).  The original ``text`` itself is *not* returned.

    Args:
        text: Raw text to de-obfuscate.
        max_depth: How many nested encodings to peel.
        max_variants: Safety cap on returned results.
        enabled: Optional subset of decoder names.

    Returns:
        Distinct decoded variants ordered by discovery depth.
    """
    if not text:
        return []
    names = [n for n in (enabled or list(DECODERS)) if n in DECODERS]
    seen = {text}
    results: List[DecodedVariant] = []
    frontier: List[Tuple[str, Tuple[str, ...]]] = [(text, ())]

    for _ in range(max(1, max_depth)):
        next_frontier: List[Tuple[str, Tuple[str, ...]]] = []
        for current, chain in frontier:
            for name in names:
                if name in chain:  # never apply the same transform twice
                    continue
                try:
                    decodes = DECODERS[name](current)
                except Exception:  # pragma: no cover - a decoder must never kill detection
                    continue
                for decoded, source in decodes:
                    if decoded in seen:
                        continue
                    seen.add(decoded)
                    variant = DecodedVariant(text=decoded, chain=chain + (name,), source=source[:120])
                    results.append(variant)
                    next_frontier.append((decoded, variant.chain))
                    if len(results) >= max_variants:
                        return results
        if not next_frontier:
            break
        frontier = next_frontier
    return results


def canonical_text(text: str) -> str:
    """NFKC + invisible-stripping form used as the primary detection surface."""
    return normalise_unicode(text or "")
