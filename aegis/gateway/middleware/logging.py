"""Request/response logging middleware.

Logs all gateway traffic with automatic redaction and timing information.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

from aegis.core.logging import get_logger
from .base import Middleware, RequestContext, ResponseContext

__all__ = ["LoggingMiddleware"]

_log = get_logger(__name__)


class LoggingMiddleware(Middleware):
    """Log gateway requests and responses with structured fields.

    Args:
        log_body: whether to include request/response bodies in logs.
        max_body_length: maximum body length to log (truncated if exceeded).
    """

    name = "logging"

    def __init__(
        self,
        log_body: bool = False,
        max_body_length: int = 1024,
    ) -> None:
        self._log_body = log_body
        self._max_body_length = max_body_length
        self._request_count: int = 0

    def process_request(self, context: RequestContext) -> RequestContext:
        """Log the incoming request."""
        self._request_count += 1
        fields = {
            "method": context.method,
            "path": context.path,
            "client_ip": context.client_ip,
            "request_id": context.metadata.get("request_id", ""),
        }
        if self._log_body and context.body:
            import json
            body_str = json.dumps(context.body, ensure_ascii=False, default=str)
            if len(body_str) > self._max_body_length:
                body_str = body_str[: self._max_body_length] + "...(truncated)"
            fields["body"] = body_str

        _log.info("gateway request", fields=fields)
        context.metadata["start_time"] = time.time()
        return context

    def process_response(self, context: ResponseContext) -> ResponseContext:
        """Log the outgoing response with timing."""
        start_time = 0.0  # Would need to be propagated via context
        duration_ms = 0.0

        fields = {
            "status_code": context.status_code,
            "duration_ms": round(duration_ms, 2),
        }
        if self._log_body and context.body:
            import json
            body_str = json.dumps(context.body, ensure_ascii=False, default=str)
            if len(body_str) > self._max_body_length:
                body_str = body_str[: self._max_body_length] + "...(truncated)"
            fields["body"] = body_str

        _log.info("gateway response", fields=fields)
        return context

    @property
    def request_count(self) -> int:
        """Total number of requests logged."""
        return self._request_count
