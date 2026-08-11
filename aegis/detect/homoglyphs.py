"""Confusable-character tables for homoglyph attack detection.

A homoglyph attack substitutes visually identical characters from another
script so that a regex looking for ``admin`` never fires on ``аdmin`` (Cyrillic
U+0430).  Models read the two identically; signature engines do not.

The tables here map confusables back to their ASCII skeleton, following the
same idea as the Unicode confusables data file but restricted to the scripts
actually used in attacks against agents: Cyrillic, Greek, Armenian, fullwidth
forms, Cherokee and mathematical alphanumerics.
"""

from __future__ import annotations

import unicodedata
from typing import Dict, List, Set, Tuple

__all__ = [
    "CONFUSABLES",
    "SCRIPT_RANGES",
    "skeleton",
    "detect_mixed_script",
    "confusable_characters",
    "script_of",
    "is_confusable",
    "LATIN_LOOKALIKE_SCRIPTS",
]


def _pairs(source: str, target: str) -> Dict[str, str]:
    """Zip two equal-length strings into a confusable -> ascii mapping."""
    return dict(zip(source, target))


#: Cyrillic letters that render as Latin ones in most fonts.
_CYRILLIC = _pairs(
    "\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0410\u0412\u0415\u041a\u041c\u041d"
    "\u041e\u0420\u0421\u0422\u0425\u0406\u0456\u0408\u0458\u04bb\u0455\u0405",
    "aeopcyxABEKMHOPCTXIiJjhss",
)

#: Greek letters commonly used to spoof Latin identifiers.
_GREEK = _pairs(
    "\u03b1\u03b2\u03b5\u03b7\u03b9\u03ba\u03bd\u03bf\u03c1\u03c3\u03c4\u03c5\u03c7"
    "\u0391\u0392\u0395\u0396\u0397\u0399\u039a\u039c\u039d\u039f\u03a1\u03a4\u03a5\u03a7",
    "aBenikvopotuxABEZHIKMNOPTYX",
)

#: Armenian and Cherokee lookalikes seen in domain-spoofing campaigns.
_OTHER_SCRIPTS = {
    "\u0570": "h", "\u0585": "o", "\u0581": "g", "\u057c": "n", "\u0578": "n",
    "\u13a0": "D", "\u13a1": "R", "\u13a2": "T", "\u13aa": "G", "\u13b3": "W",
    "\u13c0": "G", "\u13c2": "Z", "\u13ce": "4", "\u13d9": "V", "\u13de": "L",
    "\u0501": "d", "\u051b": "q", "\u0261": "g", "\u0269": "i", "\u026a": "I",
}

#: Fullwidth forms - NFKC already folds these, kept for pre-normalisation scans.
_FULLWIDTH = {chr(0xFF01 + i): chr(0x21 + i) for i in range(94)}

#: Mathematical alphanumeric symbols (bold/italic/script/monospace Latin).
_MATH_ALNUM: Dict[str, str] = {}
for _base, _ascii_start in (
    (0x1D400, ord("A")), (0x1D41A, ord("a")),   # bold
    (0x1D434, ord("A")), (0x1D44E, ord("a")),   # italic
    (0x1D5A0, ord("A")), (0x1D5BA, ord("a")),   # sans-serif
    (0x1D670, ord("A")), (0x1D68A, ord("a")),   # monospace
):
    for _offset in range(26):
        _MATH_ALNUM[chr(_base + _offset)] = chr(_ascii_start + _offset)

#: Punctuation and digit confusables used to disguise URLs and commands.
_PUNCT = {
    "\u2044": "/", "\u2215": "/", "\uff0f": "/", "\u29f8": "/",
    "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "-", "\u2212": "-",
    "\u201c": '"', "\u201d": '"', "\u2018": "'", "\u2019": "'", "\u02bc": "'",
    "\u3002": ".", "\uff0e": ".", "\u06d4": ".", "\u2024": ".", "\u0589": ":",
    "\uff1a": ":", "\uff1b": ";", "\uff08": "(", "\uff09": ")", "\uff5c": "|",
    "\u2028": "\n", "\u2029": "\n", "\u00a0": " ", "\u3000": " ",
}

#: Complete confusable -> ASCII skeleton mapping.
CONFUSABLES: Dict[str, str] = {**_CYRILLIC, **_GREEK, **_OTHER_SCRIPTS, **_FULLWIDTH, **_MATH_ALNUM, **_PUNCT}

_TRANSLATION = {ord(k): v for k, v in CONFUSABLES.items()}

#: Codepoint ranges per script, used for mixed-script analysis.
SCRIPT_RANGES: Tuple[Tuple[str, int, int], ...] = (
    ("latin", 0x0041, 0x024F),
    ("greek", 0x0370, 0x03FF),
    ("cyrillic", 0x0400, 0x04FF),
    ("armenian", 0x0530, 0x058F),
    ("hebrew", 0x0590, 0x05FF),
    ("arabic", 0x0600, 0x06FF),
    ("devanagari", 0x0900, 0x097F),
    ("cherokee", 0x13A0, 0x13FF),
    ("han", 0x4E00, 0x9FFF),
    ("hiragana", 0x3040, 0x309F),
    ("katakana", 0x30A0, 0x30FF),
    ("hangul", 0xAC00, 0xD7AF),
    ("fullwidth", 0xFF00, 0xFFEF),
    ("math_alnum", 0x1D400, 0x1D7FF),
)

#: Scripts whose presence alongside Latin is suspicious in an identifier.
LATIN_LOOKALIKE_SCRIPTS: Set[str] = {"cyrillic", "greek", "armenian", "cherokee", "math_alnum"}


def script_of(ch: str) -> str:
    """Return a coarse script name for one character."""
    code = ord(ch)
    for name, low, high in SCRIPT_RANGES:
        if low <= code <= high:
            return name
    if ch.isascii():
        return "ascii"
    return "other"


def is_confusable(ch: str) -> bool:
    """True when ``ch`` has an ASCII lookalike in :data:`CONFUSABLES`."""
    return ch in CONFUSABLES


def skeleton(text: str) -> str:
    """Fold confusables to their ASCII lookalikes.

    ``skeleton("аdmin")`` (Cyrillic а) returns ``"admin"``, letting downstream
    string comparisons and signature scans see the attacker's real intent.
    """
    if not text:
        return ""
    return text.translate(_TRANSLATION)


def confusable_characters(text: str, limit: int = 20) -> List[Tuple[int, str, str, str]]:
    """List the confusables present in ``text``.

    Returns:
        Up to ``limit`` tuples of ``(index, character, ascii_lookalike,
        unicode_name)`` - ready to render as finding evidence.
    """
    out: List[Tuple[int, str, str, str]] = []
    for index, ch in enumerate(text or ""):
        if ch in CONFUSABLES and not ch.isascii():
            try:
                name = unicodedata.name(ch)
            except ValueError:  # pragma: no cover - unnamed codepoint
                name = f"U+{ord(ch):04X}"
            out.append((index, ch, CONFUSABLES[ch], name))
            if len(out) >= limit:
                break
    return out


def detect_mixed_script(text: str, *, min_word_length: int = 3) -> List[Tuple[str, Set[str]]]:
    """Find whitespace-delimited words that mix Latin with a lookalike script.

    Chinese/Japanese text next to Latin is perfectly normal, so Han, Kana and
    Hangul never trigger this check; only scripts in
    :data:`LATIN_LOOKALIKE_SCRIPTS` do.

    Returns:
        ``(word, scripts)`` pairs for each suspicious word.
    """
    out: List[Tuple[str, Set[str]]] = []
    for word in (text or "").split():
        if len(word) < min_word_length:
            continue
        scripts = {script_of(ch) for ch in word if not ch.isspace() and ch.isalnum()}
        scripts.discard("other")
        has_latin = bool(scripts & {"ascii", "latin"})
        suspicious = scripts & LATIN_LOOKALIKE_SCRIPTS
        if has_latin and suspicious:
            out.append((word, scripts))
    return out
