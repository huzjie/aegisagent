"""Entropy and randomness statistics used to separate secrets from prose.

Credential regexes alone produce unacceptable false-positive rates: a
documentation snippet containing ``AKIAIOSFODNN7EXAMPLE`` looks exactly like a
live AWS key.  Combining a structural regex with a Shannon-entropy floor and a
few cheap "does this look like English/placeholder text" tests removes most of
that noise while keeping recall high.

All functions are pure and allocation-light so they can be called once per
regex hit without measurable cost.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

__all__ = [
    "shannon_entropy",
    "normalised_entropy",
    "base64_entropy",
    "hex_entropy",
    "charset_profile",
    "looks_random",
    "is_placeholder",
    "PLACEHOLDER_TOKENS",
    "ENTROPY_THRESHOLDS",
    "longest_run",
    "digit_ratio",
]

#: Minimum Shannon entropy (bits/char) per character class for a value to be
#: considered a real credential rather than an identifier or English word.
ENTROPY_THRESHOLDS: Dict[str, float] = {
    "base64": 4.0,
    "hex": 3.0,
    "alphanumeric": 3.5,
    "generic": 3.2,
}

#: Substrings that mark a value as documentation, not a live credential.
PLACEHOLDER_TOKENS: Tuple[str, ...] = (
    "example", "sample", "placeholder", "dummy", "changeme", "change-me",
    "your-", "yourkey", "your_key", "my-secret", "insert", "replace",
    "xxxxx", "aaaaa", "00000", "12345", "abcdef", "test-key", "testkey",
    "fake", "mock", "redacted", "removed", "hidden", "none", "null",
    "notarealkey", "dummykey", "sk-xxx", "<key>", "{{", "}}", "${",
    "--redacted--", "***", "…", "占位", "示例", "测试密钥",
)

#: Anything already masked by our own redaction pass.
REDACTION_MARKERS: Tuple[str, ...] = ("--REDACTED--", "***REDACTED***", "[REDACTED]", "<redacted>")

_B64_CHARS = re.compile(r"^[A-Za-z0-9+/=_-]+$")
_HEX_CHARS = re.compile(r"^[0-9a-fA-F]+$")
_WORDY = re.compile(r"(?i)\b(the|and|for|with|this|that|from|your|please|value|token is)\b")


def shannon_entropy(text: str) -> float:
    """Shannon entropy of ``text`` in bits per character.

    Returns ``0.0`` for empty input.  A random 32-char base64 string scores
    around 5.0; an English sentence around 4.0 but with a very different
    character profile; ``aaaaaaaa`` scores 0.0.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def normalised_entropy(text: str) -> float:
    """Entropy scaled to ``[0, 1]`` against the maximum for its alphabet size.

    Useful when comparing strings of very different lengths, where raw Shannon
    entropy is bounded by ``log2(len(text))`` rather than by randomness.
    """
    if len(text) < 2:
        return 0.0
    alphabet = len(set(text))
    ceiling = math.log2(min(alphabet, len(text)))
    return shannon_entropy(text) / ceiling if ceiling > 0 else 0.0


def base64_entropy(text: str) -> float:
    """Entropy of the base64-ish portion of ``text`` (separators removed)."""
    cleaned = re.sub(r"[^A-Za-z0-9+/=_-]", "", text or "")
    return shannon_entropy(cleaned)


def hex_entropy(text: str) -> float:
    """Entropy of the hexadecimal portion of ``text``."""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", text or "")
    return shannon_entropy(cleaned)


def charset_profile(text: str) -> str:
    """Name the dominant character class: ``hex`` / ``base64`` / ``alphanumeric`` / ``generic``."""
    stripped = (text or "").strip()
    if not stripped:
        return "generic"
    if _HEX_CHARS.match(stripped) and len(stripped) >= 16:
        return "hex"
    if _B64_CHARS.match(stripped):
        return "base64"
    if stripped.isalnum():
        return "alphanumeric"
    return "generic"


def digit_ratio(text: str) -> float:
    """Fraction of characters that are digits."""
    if not text:
        return 0.0
    return sum(1 for ch in text if ch.isdigit()) / len(text)


def longest_run(text: str) -> int:
    """Length of the longest run of one repeated character.

    Long runs (``AAAAAAAA``) indicate a redaction or placeholder rather than a
    real key even when the surrounding regex matched.
    """
    if not text:
        return 0
    best = run = 1
    for previous, current in zip(text, text[1:]):
        run = run + 1 if current == previous else 1
        best = max(best, run)
    return best


def is_placeholder(value: str) -> bool:
    """True when a credential-shaped string is obviously not a live secret."""
    if not value:
        return True
    low = value.lower()
    if any(marker.lower() in low for marker in REDACTION_MARKERS):
        return True
    if any(token in low for token in PLACEHOLDER_TOKENS):
        return True
    core = re.sub(r"^[a-z]{2,10}[-_]", "", low)
    if len(set(core)) <= 3:
        return True
    if longest_run(value) >= 6:
        return True
    return False


def looks_random(
    value: str,
    *,
    min_length: int = 16,
    threshold: Optional[float] = None,
    profile: Optional[str] = None,
) -> bool:
    """Decide whether ``value`` has the statistical shape of a real credential.

    Args:
        value: Candidate secret (already stripped of its ``sk-`` style prefix
            by the caller when the prefix is low-entropy boilerplate).
        min_length: Values shorter than this are never considered random.
        threshold: Override the entropy floor; defaults to the value in
            :data:`ENTROPY_THRESHOLDS` for the detected profile.
        profile: Force a character-class profile instead of detecting it.

    Returns:
        ``True`` when the value is long enough, non-placeholder, and its
        entropy clears the floor for its character class.
    """
    if not value or len(value) < min_length:
        return False
    if is_placeholder(value):
        return False
    if _WORDY.search(value):
        return False
    kind = profile or charset_profile(value)
    floor = threshold if threshold is not None else ENTROPY_THRESHOLDS.get(kind, ENTROPY_THRESHOLDS["generic"])
    entropy = shannon_entropy(value)
    if entropy < floor:
        return False
    # A key that is all digits is far more likely an id / timestamp.
    return not (digit_ratio(value) > 0.95 and kind != "hex")


def entropy_report(value: str) -> Dict[str, float | str | bool]:
    """Full diagnostic bundle - attached to findings for analyst triage."""
    return {
        "length": len(value or ""),
        "profile": charset_profile(value),
        "shannon": round(shannon_entropy(value), 3),
        "normalised": round(normalised_entropy(value), 3),
        "digit_ratio": round(digit_ratio(value), 3),
        "longest_run": longest_run(value),
        "placeholder": is_placeholder(value),
        "random": looks_random(value),
    }


def high_entropy_substrings(
    text: str,
    *,
    min_length: int = 24,
    threshold: float = 4.2,
    limit: int = 8,
) -> List[Tuple[str, float]]:
    """Find unlabelled high-entropy blobs (keys pasted without a known prefix).

    Splits on non-secret characters and evaluates each token independently.
    """
    out: List[Tuple[str, float]] = []
    for token in re.split(r"[^A-Za-z0-9+/=_\-\.]+", text or ""):
        if len(token) < min_length:
            continue
        if is_placeholder(token):
            continue
        entropy = shannon_entropy(token)
        if entropy >= threshold:
            out.append((token, round(entropy, 3)))
            if len(out) >= limit:
                break
    return out


def average_entropy(values: Iterable[str]) -> float:
    """Mean Shannon entropy across a collection - used for baseline drift."""
    items: Sequence[str] = [v for v in values if v]
    if not items:
        return 0.0
    return sum(shannon_entropy(v) for v in items) / len(items)
