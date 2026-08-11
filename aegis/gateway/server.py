"""stdlib http.server based reverse proxy for the LLM gateway.

Provides a zero-dependency HTTP server that proxies requests to upstream LLM
providers while applying the gateway's security middleware and attestation
injection.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

from aegis.core.logging import get_logger
from .interceptor import GatewayInterceptor
from .router import UpstreamRouter, UpstreamConfig
from .middleware import (
    Middleware,
    RateLimitMiddleware,
    RedactionMiddleware,
    LoggingMiddleware,
)
from .middleware.base import RequestContext, ResponseContext

__all__ = ["run_gateway", "GatewayServer", "GatewayRequestHandler"]

_log = get_logger(__name__)


class GatewayRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the gateway proxy."""

    server: "GatewayServer"

    def do_POST(self) -> None:
        """Handle POST requests (LLM API calls)."""
        # Read request body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        try:
            request_data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")
            return

        # Build request context
        context = RequestContext(
            method="POST",
            path=self.path,
            headers=dict(self.headers),
            body=request_data,
            client_ip=self.client_address[0],
            metadata={"request_id": f"req_{int(time.time() * 1000)}"},
        )

        # Apply middleware chain
        for middleware in self.server.middlewares:
            context = middleware.process_request(context)
            if context.blocked:
                self.send_error(429, context.block_reason)
                return

        # Intercept request for CoreBreak detection
        messages = context.body.get("messages", [])
        intercept_result = self.server.interceptor.intercept_request(messages)
        if intercept_result.blocked:
            self.send_error(403, intercept_result.reason)
            return

        # Route to upstream
        model = context.body.get("model", "")
        upstream = self.server.router.route(model)
        if upstream is None:
            self.send_error(502, f"No upstream found for model: {model}")
            return

        # Forward request (simplified - in production would use urllib)
        response_body = self._forward_request(upstream, context)

        # Intercept response for attestation
        session_id = context.metadata.get("session_id", "")
        turn = context.metadata.get("turn", 0)
        response_result = self.server.interceptor.intercept_response(
            response_body,
            session_id=session_id,
            turn=turn,
            model=model,
            provider=upstream.name,
        )

        # Build response context
        response_context = ResponseContext(
            status_code=200,
            body=response_result.modified_response or response_body,
            metadata={"usage": response_result.completion.usage if response_result.completion else {}},
        )

        # Apply response middleware
        for middleware in self.server.middlewares:
            response_context = middleware.process_response(response_context)

        # Send response
        self.send_response(response_context.status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response_context.body).encode("utf-8"))

    def _forward_request(
        self, upstream: UpstreamConfig, context: RequestContext
    ) -> Dict[str, Any]:
        """Forward request to upstream provider.

        This is a simplified implementation.  In production, this would use
        urllib.request with proper timeout and retry logic.
        """
        # Placeholder - would make actual HTTP request
        return {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "Proxied response",
                },
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
        }

    def log_message(self, format: str, *args: Any) -> None:
        """Override to use structured logging."""
        _log.debug("gateway request", fields={"message": format % args})


class GatewayServer:
    """HTTP server for the LLM gateway.

    Args:
        host: bind address.
        port: bind port.
        router: upstream router configuration.
        interceptor: request/response interceptor.
        middlewares: list of middleware to apply.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        router: Optional[UpstreamRouter] = None,
        interceptor: Optional[GatewayInterceptor] = None,
        middlewares: Optional[List[Middleware]] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.router = router or UpstreamRouter()
        self.interceptor = interceptor or GatewayInterceptor()
        self.middlewares = middlewares or [
            LoggingMiddleware(),
            RedactionMiddleware(),
            RateLimitMiddleware(),
        ]
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the gateway server in a background thread."""
        self._server = HTTPServer((self.host, self.port), GatewayRequestHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        _log.info("gateway started", fields={"host": self.host, "port": self.port})

    def stop(self) -> None:
        """Stop the gateway server."""
        if self._server:
            self._server.shutdown()
            self._server = None
        if self._thread:
            self._thread.join(timeout=5.0)
            self._thread = None
        _log.info("gateway stopped")

    @property
    def is_running(self) -> bool:
        """Whether the server is currently running."""
        return self._server is not None and self._thread is not None and self._thread.is_alive()


def run_gateway(
    host: str = "127.0.0.1",
    port: int = 8080,
    settings: Any = None,
    upstreams: Optional[List[Dict[str, Any]]] = None,
) -> GatewayServer:
    """Create and start a gateway server.

    Args:
        host: bind address.
        port: bind port.
        settings: optional settings object.
        upstreams: list of upstream configurations.

    Returns:
        The running :class:`GatewayServer`.
    """
    router = UpstreamRouter()
    if upstreams:
        for config in upstreams:
            router.add_upstream(UpstreamConfig(**config))

    server = GatewayServer(
        host=host,
        port=port,
        router=router,
    )
    server.start()
    return server
