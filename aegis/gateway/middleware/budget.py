"""Token budget enforcement middleware.

Tracks and enforces token usage budgets per client or tenant, blocking
requests that would exceed the configured limit.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional

from aegis.core.logging import get_logger
from .base import Middleware, RequestContext, ResponseContext

__all__ = ["BudgetMiddleware"]

_log = get_logger(__name__)


class BudgetMiddleware(Middleware):
    """Enforce token usage budgets for gateway clients.

    Args:
        max_tokens: maximum tokens allowed per period.
        period_s: budget period in seconds (default: 1 hour).
        key_func: optional function to extract the budget key from context.
    """

    name = "budget"

    def __init__(
        self,
        max_tokens: int = 1_000_000,
        period_s: float = 3600.0,
        key_func: Optional[callable] = None,
    ) -> None:
        self._max_tokens = max_tokens
        self._period_s = period_s
        self._key_func = key_func or self._default_key
        self._usage: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._rejected_count: int = 0

    def _default_key(self, context: RequestContext) -> str:
        return context.client_ip or "unknown"

    def process_request(self, context: RequestContext) -> RequestContext:
        """Check if budget is exceeded and block if so."""
        key = self._key_func(context)
        usage = self._get_usage(key)
        if usage["tokens"] >= self._max_tokens:
            context.block(f"Token budget exceeded for {key}")
            self._rejected_count += 1
            _log.warning("budget exceeded", fields={"key": key, "tokens": usage["tokens"]})
        return context

    def process_response(self, context: ResponseContext) -> ResponseContext:
        """Track token usage from response."""
        # Extract usage from response metadata
        usage_info = context.metadata.get("usage", {})
        if usage_info:
            # Would need request context to know which key to update
            # For now, this is a placeholder
            pass
        return context

    def record_usage(self, key: str, tokens: int) -> None:
        """Record token usage for a client."""
        with self._lock:
            usage = self._get_usage(key)
            usage["tokens"] += tokens
            usage["last_update"] = time.time()

    def _get_usage(self, key: str) -> Dict[str, Any]:
        """Get or create usage record for a key."""
        now = time.time()
        with self._lock:
            if key not in self._usage:
                self._usage[key] = {"tokens": 0, "last_update": now, "period_start": now}
            usage = self._usage[key]
            # Reset if period expired
            if now - usage["period_start"] > self._period_s:
                usage["tokens"] = 0
                usage["period_start"] = now
            return usage

    def get_usage(self, key: str) -> Dict[str, Any]:
        """Get current usage for a key."""
        return dict(self._get_usage(key))

    @property
    def rejected_count(self) -> int:
        """Number of requests rejected due to budget limits."""
        return self._rejected_count

    def reset(self, key: Optional[str] = None) -> None:
        """Reset usage tracking for testing."""
        with self._lock:
            if key is None:
                self._usage.clear()
            else:
                self._usage.pop(key, None)
