"""Rate limiting middleware.

Enforces per-client or per-agent request rate limits using a token bucket
algorithm.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional

from aegis.core.utils import TokenBucket
from aegis.core.logging import get_logger
from .base import Middleware, RequestContext, ResponseContext

__all__ = ["RateLimitMiddleware"]

_log = get_logger(__name__)


class RateLimitMiddleware(Middleware):
    """Apply token bucket rate limiting to gateway requests.

    Args:
        capacity: maximum number of tokens in the bucket.
        refill_rate: tokens added per second.
        key_func: optional function to extract the rate limit key from the
            request context.  Defaults to using the client IP.
    """

    name = "rate_limit"

    def __init__(
        self,
        capacity: int = 60,
        refill_rate: float = 1.0,
        key_func: Optional[callable] = None,
    ) -> None:
        self._capacity = capacity
        self._refill_rate = refill_rate
        self._key_func = key_func or self._default_key
        self._buckets: Dict[str, TokenBucket] = {}
        self._lock = threading.Lock()
        self._rejected_count: int = 0

    def _default_key(self, context: RequestContext) -> str:
        return context.client_ip or "unknown"

    def process_request(self, context: RequestContext) -> RequestContext:
        """Check rate limit and block if exceeded."""
        key = self._key_func(context)
        bucket = self._get_bucket(key)
        if not bucket.consume():
            retry_after = bucket.retry_after()
            context.block(f"Rate limit exceeded for {key}, retry after {retry_after:.1f}s")
            self._rejected_count += 1
            _log.warning(
                "rate limit exceeded",
                fields={"key": key, "retry_after": retry_after},
            )
        return context

    def process_response(self, context: ResponseContext) -> ResponseContext:
        """Pass through - no response modification needed."""
        return context

    def _get_bucket(self, key: str) -> TokenBucket:
        with self._lock:
            if key not in self._buckets:
                self._buckets[key] = TokenBucket(
                    capacity=self._capacity,
                    refill_per_second=self._refill_rate,
                )
            return self._buckets[key]

    @property
    def rejected_count(self) -> int:
        """Number of requests rejected due to rate limiting."""
        return self._rejected_count

    def reset(self, key: Optional[str] = None) -> None:
        """Reset rate limit buckets for testing."""
        with self._lock:
            if key is None:
                self._buckets.clear()
            else:
                self._buckets.pop(key, None)
