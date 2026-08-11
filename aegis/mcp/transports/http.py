"""HTTP transport: talk to a remote MCP server over JSON-RPC POST.

Used for servers that expose a single JSON-RPC endpoint (the common cloud
deployment).  The transport is intentionally minimal and defensive:

* only POST is used for requests; server-supplied redirects are never
  followed automatically,
* the response is validated through :mod:`aegis.mcp.protocol` before use,
* TLS is required for ``https://`` endpoints and the caller owns trust
  configuration via the standard ``SSLContext`` hook.

This transport is a network boundary: the proxy's security policy (pinning,
scanner, sanitizer) is what decides *whether* to forward, not this module.
"""

from __future__ import annotations

import json
import ssl
import urllib.request
from typing import Any, Dict, Optional

from ...core.errors import IntegrationError
from ...core.logging import get_logger
from ..protocol import JsonRpcRequest, McpErrorCode, McpError, TransportKind
from .base import TransportError, McpTransport

__all__ = ["HttpTransport"]

_LOG = get_logger("aegis.mcp.transport.http")

#: Per-request network timeout in seconds.
_DEFAULT_TIMEOUT_S = 30.0


class HttpTransport(McpTransport):
    """JSON-RPC over HTTPS/HTTP POST."""

    kind = TransportKind.HTTP

    def __init__(
        self,
        url: str,
        *,
        token: str = "",
        headers: Optional[Dict[str, str]] = None,
        timeout_s: float = _DEFAULT_TIMEOUT_S,
        ssl_context: Optional[ssl.SSLContext] = None,
        user_agent: str = "AegisAgent-MCP/1.0",
    ) -> None:
        """Create the transport.

        Args:
            url: Endpoint URL (``https://`` strongly recommended).
            token: Optional bearer token added to the ``Authorization`` header.
            headers: Additional static headers.
            timeout_s: Per-request timeout.
            ssl_context: Custom TLS context; defaults to the system store.
            user_agent: ``User-Agent`` header value.

        Raises:
            TransportError: ``url`` is empty or not HTTP(S).
        """
        super().__init__()
        if not url or not url.startswith(("http://", "https://")):
            raise TransportError("http transport requires an http(s) url")
        self._url = url
        self._token = token
        self._extra_headers = dict(headers or {})
        self._timeout = float(timeout_s)
        self._ssl = ssl_context
        self._user_agent = user_agent

    def connect(self) -> None:
        """Mark the transport open (no persistent connection is held)."""
        self._open = True

    def close(self) -> None:
        """Mark the transport closed."""
        self._open = False

    def send(self, request: JsonRpcRequest) -> "JsonRpcResponse":
        """POST the request and return the parsed JSON-RPC response.

        Args:
            request: The JSON-RPC request frame.

        Returns:
            The correlated response.

        Raises:
            TransportError: Network failure, non-2xx status, or malformed
                response.  A 401/403 surfaces as a :class:`McpError` carrying
                ``SERVER_UNTRUSTED`` so the proxy can quarantine the server.
        """
        if not self._open:
            raise TransportError("http transport is not connected")
        payload = json.dumps(request.to_dict()).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": self._user_agent,
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        headers.update(self._extra_headers)
        req = urllib.request.Request(self._url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout, context=self._ssl) as resp:  # noqa: S310
                status = resp.status
                raw = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise McpError(
                    "MCP server rejected credentials", code=McpErrorCode.SERVER_UNTRUSTED,
                    data={"status": exc.code},
                )
            raise TransportError(f"MCP server returned HTTP {exc.code}", cause=exc, transient=True)
        except (urllib.error.URLError, ssl.SSLError, OSError) as exc:
            raise TransportError(f"http transport request failed: {exc}", cause=exc, transient=True)
        except IntegrationError as exc:
            raise TransportError(str(exc), cause=exc)

        if status >= 400:
            raise TransportError(f"MCP server returned HTTP {status}")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise TransportError(f"invalid JSON from MCP server: {exc}")
        # SSE transports sometimes return a single ``data:`` line; unwrap it.
        if isinstance(parsed, dict) and "data" in parsed and not ("jsonrpc" in parsed or "result" in parsed or "error" in parsed):
            inner = parsed["data"]
            if isinstance(inner, str):
                try:
                    parsed = json.loads(inner)
                except json.JSONDecodeError:
                    pass
        return self._validate_response(parsed)
