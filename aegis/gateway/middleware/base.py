"""Abstract base class for gateway middleware.

Middleware components form a chain that processes requests and responses as
they flow through the gateway.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Optional

__all__ = ["Middleware", "RequestContext", "ResponseContext"]


class RequestContext:
    """Context object passed through the middleware chain for requests."""

    def __init__(
        self,
        method: str = "POST",
        path: str = "/",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Dict[str, Any]] = None,
        client_ip: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.method = method
        self.path = path
        self.headers = headers or {}
        self.body = body or {}
        self.client_ip = client_ip
        self.metadata = metadata or {}
        self.blocked = False
        self.block_reason = ""

    def block(self, reason: str) -> None:
        """Mark this request as blocked."""
        self.blocked = True
        self.block_reason = reason


class ResponseContext:
    """Context object passed through the middleware chain for responses."""

    def __init__(
        self,
        status_code: int = 200,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.status_code = status_code
        self.headers = headers or {}
        self.body = body or {}
        self.metadata = metadata or {}


class Middleware(ABC):
    """Interface for gateway middleware components.

    Subclasses implement :meth:`process_request` and :meth:`process_response`
    to inspect and modify traffic flowing through the gateway.
    """

    name: str = "base"

    @abstractmethod
    def process_request(self, context: RequestContext) -> RequestContext:
        """Process an outgoing request.

        Args:
            context: the request context.

        Returns:
            The (possibly modified) request context.
        """
        # pragma: no cover - interface

    @abstractmethod
    def process_response(self, context: ResponseContext) -> ResponseContext:
        """Process an incoming response.

        Args:
            context: the response context.

        Returns:
            The (possibly modified) response context.
        """
        # pragma: no cover - interface
