"""Small, dependency-free helpers used across the codebase."""

from __future__ import annotations

import fnmatch
import ipaddress
import re
import threading
import time
import unicodedata
from collections import OrderedDict, deque
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Tuple, TypeVar
from urllib.parse import urlparse

T = TypeVar("T")

__all__ = [
    "glob_match",
    "any_glob_match",
    "normalise_unicode",
    "strip_invisible",
    "truncate",
    "flatten",
    "chunked",
    "coerce_bool",
    "human_bytes",
    "human_duration",
    "TokenBucket",
    "SlidingWindowCounter",
    "LRUCache",
    "Stopwatch",
    "retry",
    "host_matches_allowlist",
    "extract_urls",
    "jaccard",
    "levenshtein",
    "safe_get",
    "deep_redact_preview",
    "utc_iso",
]


ZERO_WIDTH = dict.fromkeys(
    [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E, 0x00AD, 0x200E, 0x200F, 0x202A,
     0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069]
)

URL_RE = re.compile(r"https?://[^\s\"'<>\)\]]+", re.IGNORECASE)


def utc_iso(ts: Optional[float] = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts if ts is not None else time.time()))


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #
def glob_match(value: str, pattern: str) -> bool:
    """Case-insensitive glob with support for ``**`` as a greedy wildcard."""
    if pattern in ("*", "**"):
        return True
    return fnmatch.fnmatch((value or "").lower(), pattern.lower().replace("**", "*"))


def any_glob_match(value: str, patterns: Iterable[str]) -> bool:
    return any(glob_match(value, p) for p in patterns or [])


def host_matches_allowlist(url_or_host: str, allowlist: Iterable[str]) -> bool:
    """Allowlist check supporting hostnames, ``*.suffix`` globs and CIDRs."""
    host = url_or_host
    if "://" in url_or_host:
        host = urlparse(url_or_host).hostname or ""
    host = (host or "").strip().lower()
    if not host:
        return False
    for entry in allowlist or []:
        entry = str(entry).strip().lower()
        if not entry:
            continue
        if "/" in entry:
            try:
                network = ipaddress.ip_network(entry, strict=False)
                if ipaddress.ip_address(host) in network:
                    return True
                continue
            except ValueError:
                pass
        if entry == host or glob_match(host, entry):
            return True
        if entry.startswith(".") and host.endswith(entry):
            return True
    return False


# --------------------------------------------------------------------------- #
# Text hygiene
# --------------------------------------------------------------------------- #
def normalise_unicode(text: str) -> str:
    """NFKC-normalise and drop invisible characters used to smuggle prompts."""
    if not text:
        return ""
    return unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH)


def strip_invisible(text: str) -> str:
    return (text or "").translate(ZERO_WIDTH)


def count_invisible(text: str) -> int:
    return sum(1 for ch in (text or "") if ord(ch) in ZERO_WIDTH)


def truncate(text: str, limit: int = 512, suffix: str = "…") -> str:
    text = text or ""
    return text if len(text) <= limit else text[: limit - len(suffix)] + suffix


def extract_urls(text: str) -> List[str]:
    return URL_RE.findall(text or "")


# --------------------------------------------------------------------------- #
# Collections
# --------------------------------------------------------------------------- #
def flatten(items: Iterable[Any]) -> List[Any]:
    out: List[Any] = []
    for item in items:
        if isinstance(item, (list, tuple, set)):
            out.extend(flatten(item))
        else:
            out.append(item)
    return out


def chunked(items: List[T], size: int) -> List[List[T]]:
    size = max(1, size)
    return [items[i: i + size] for i in range(0, len(items), size)]


def coerce_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on", "y", "enabled")


def safe_get(data: Any, path: str, default: Any = None) -> Any:
    cursor = data
    for part in path.split("."):
        if isinstance(cursor, dict):
            cursor = cursor.get(part)
        elif isinstance(cursor, (list, tuple)) and part.isdigit():
            idx = int(part)
            cursor = cursor[idx] if idx < len(cursor) else None
        else:
            cursor = getattr(cursor, part, None)
        if cursor is None:
            return default
    return cursor


def deep_redact_preview(data: Any, max_len: int = 160, depth: int = 0) -> Any:
    """Shorten long values so payload previews stay readable in the console."""
    if depth > 6:
        return "…"
    if isinstance(data, dict):
        return {k: deep_redact_preview(v, max_len, depth + 1) for k, v in list(data.items())[:40]}
    if isinstance(data, (list, tuple)):
        return [deep_redact_preview(v, max_len, depth + 1) for v in list(data)[:20]]
    if isinstance(data, str):
        return truncate(data, max_len)
    return data


# --------------------------------------------------------------------------- #
# Formatting
# --------------------------------------------------------------------------- #
def human_bytes(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0:
            return f"{num:.1f}{unit}" if unit != "B" else f"{int(num)}B"
        num /= 1024.0
    return f"{num:.1f}PB"


def human_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}m"
    if seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"


# --------------------------------------------------------------------------- #
# Similarity
# --------------------------------------------------------------------------- #
def jaccard(a: str, b: str) -> float:
    sa, sb = set((a or "").lower().split()), set((b or "").lower().split())
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def levenshtein(a: str, b: str, limit: int = 256) -> int:
    a, b = (a or "")[:limit], (b or "")[:limit]
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


# --------------------------------------------------------------------------- #
# Rate limiting & caching
# --------------------------------------------------------------------------- #
class TokenBucket:
    """Thread-safe token bucket used for per-agent / per-tool throttling."""

    def __init__(self, capacity: int = 60, refill_per_second: float = 1.0) -> None:
        self.capacity = max(1, capacity)
        self.refill_per_second = max(0.001, refill_per_second)
        self._tokens = float(self.capacity)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last
        self._last = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_per_second)

    def consume(self, amount: int = 1) -> bool:
        with self._lock:
            self._refill()
            if self._tokens >= amount:
                self._tokens -= amount
                return True
            return False

    def retry_after(self, amount: int = 1) -> float:
        with self._lock:
            self._refill()
            deficit = max(0.0, amount - self._tokens)
            return deficit / self.refill_per_second

    @property
    def available(self) -> int:
        with self._lock:
            self._refill()
            return int(self._tokens)


class SlidingWindowCounter:
    """Counts events inside a rolling time window (per key)."""

    def __init__(self, window_s: float = 60.0) -> None:
        self.window_s = window_s
        self._events: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, now: Optional[float] = None) -> int:
        now = now if now is not None else time.time()
        with self._lock:
            queue = self._events.setdefault(key, deque())
            queue.append(now)
            cutoff = now - self.window_s
            while queue and queue[0] < cutoff:
                queue.popleft()
            return len(queue)

    def count(self, key: str, now: Optional[float] = None) -> int:
        now = now if now is not None else time.time()
        with self._lock:
            queue = self._events.get(key)
            if not queue:
                return 0
            cutoff = now - self.window_s
            while queue and queue[0] < cutoff:
                queue.popleft()
            return len(queue)

    def reset(self, key: Optional[str] = None) -> None:
        with self._lock:
            if key is None:
                self._events.clear()
            else:
                self._events.pop(key, None)


class LRUCache:
    """Tiny thread-safe LRU with optional TTL."""

    def __init__(self, maxsize: int = 512, ttl_s: float = 0.0) -> None:
        self.maxsize = maxsize
        self.ttl_s = ttl_s
        self._data: "OrderedDict[str, Tuple[float, Any]]" = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                self.misses += 1
                return default
            ts, value = entry
            if self.ttl_s and (time.time() - ts) > self.ttl_s:
                self._data.pop(key, None)
                self.misses += 1
                return default
            self._data.move_to_end(key)
            self.hits += 1
            return value

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._data[key] = (time.time(), value)
            self._data.move_to_end(key)
            while len(self._data) > self.maxsize:
                self._data.popitem(last=False)

    def contains(self, key: str) -> bool:
        return self.get(key, _SENTINEL) is not _SENTINEL

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def stats(self) -> Dict[str, Any]:
        total = self.hits + self.misses
        return {
            "size": len(self._data),
            "maxsize": self.maxsize,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": round(self.hits / total, 4) if total else 0.0,
        }


_SENTINEL = object()


class Stopwatch:
    """Context manager returning elapsed milliseconds."""

    def __init__(self) -> None:
        self.start = 0.0
        self.elapsed_ms = 0.0

    def __enter__(self) -> "Stopwatch":
        self.start = time.perf_counter()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.elapsed_ms = (time.perf_counter() - self.start) * 1000.0


def retry(
    func: Callable[[], T],
    *,
    attempts: int = 3,
    delay_s: float = 0.25,
    backoff: float = 2.0,
    exceptions: Tuple[type, ...] = (Exception,),
) -> T:
    """Retry a callable with exponential backoff."""
    last: Optional[BaseException] = None
    wait = delay_s
    for _ in range(max(1, attempts)):
        try:
            return func()
        except exceptions as exc:  # noqa: PERF203
            last = exc
            time.sleep(wait)
            wait *= backoff
    raise last  # type: ignore[misc]
