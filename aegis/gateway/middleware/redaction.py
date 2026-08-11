"""Secret redaction middleware.

Scans request and response bodies for sensitive data patterns and redacts them
before they are logged or forwarded.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Pattern

from aegis.core.logging import redact_text, redact_mapping, get_logger
from .base import Middleware, RequestContext, ResponseContext

__all__ = ["RedactionMiddleware"]

_log = get_logger(__name__)

# Additional patterns specific to gateway traffic
_GATEWAY_PATTERNS: List[tuple] = [
    (re.compile(r"(?i)Bearer\s+[A-Za-z0-9_\-\.]+"), "Bearer ***REDACTED***"),
    (re.compile(r"(?i)x-api-key:\s*\S+"), "x-api-key: ***REDACTED***"),
]


class RedactionMiddleware(Middleware):
    """Redact sensitive data from request and response bodies.

    This middleware applies the core redaction functions from
    :mod:`aegis.core.logging` plus gateway-specific patterns for API keys
    and bearer tokens.
    """

    name = "redaction"

    def __init__(self, extra_patterns: Optional[List[tuple]] = None) -> None:
        self._extra_patterns = extra_patterns or []

    def process_request(self, context: RequestContext) -> RequestContext:
        """Redact sensitive data from request body and headers."""
        # Redact headers
        for key in list(context.headers.keys()):
            if key.lower() in ("authorization", "x-api-key", "cookie"):
                context.headers[key] = "***REDACTED***"

        # Redact body
        if context.body:
            context.body = redact_mapping(context.body)

        return context

    def process_response(self, context: ResponseContext) -> ResponseContext:
        """Redact sensitive data from response body."""
        if context.body:
            context.body = redact_mapping(context.body)
        return context

    def _apply_patterns(self, text: str) -> str:
        """Apply all redaction patterns to text."""
        out = redact_text(text)
        for pattern, replacement in _GATEWAY_PATTERNS + self._extra_patterns:
            out = pattern.sub(replacement, out)
        return out
