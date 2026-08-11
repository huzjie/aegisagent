"""SSE transport: MCP over Server-Sent Events (POST out, GET stream back).

Some MCP servers use the classic HTTP+SSE topology: the client POSTs each
request to a message endpoint and reads responses from a long-lived SSE stream
on a separate URL.  This transport implements exactly that correlation:

* requests are POSTed with a client-generated id,
* a background reader parses the SSE ``data:`` lines into JSON-RPC responses,
* responses are matched to waiters by id, and unsolicited notifications are
  handed to the registered handler.

The reader runs in a daemon thread and is torn down on :meth:`close`.
"""

from __future__ import annotations

import json
import threading
import urllib.request
from typing import Any, Dict, Optional

from ...core.logging import get_logger
from ..protocol import (
    JsonRpcNotification,
    JsonRpcRequest,
    JsonRpcResponse,
    McpErrorCode,
    McpError,
    TransportKind,
)
from .base import TransportError, McpTransport

__all__ = ["SseTransport"]

_LOG = get_logger("aegis.mcp.transport.sse")

_DEFAULT_TIMEOUT_S = 30.0


class SseTransport(McpTransport):
    """MCP over HTTP POST + SSE response stream."""

    kind = TransportKind.SSE

    def __init__(
        self,
        post_url: str,
        sse_url: str,
        *,
        token: str = "",
        headers: Optional[Dict[str, str]] = None,
        timeout_s: float = _DEFAULT_TIMEOUT_S,
        ssl_context=None,
        user_agent: str = "AegisAgent-MCP/1.0",
    ) -> None:
        """Create the transport.

        Args:
            post_url: Endpoint that accepts JSON-RPC POSTs.
            sse_url: Endpoint that streams responses/notifications via SSE.
            token: Optional bearer token.
            headers: Additional static headers.
            timeout_s: Per-request timeout.
            ssl_context: Custom TLS context.
            user_agent: ``User-Agent`` header value.

        Raises:
            TransportError: Either URL is missing or not HTTP(S).
        """
        super().__init__()
        if not post_url.startswith(("http://", "https://")):
            raise TransportError("sse transport requires an http(s) post url")
        if not sse_url.startswith(("http://", "https://")):
            raise TransportError("sse transport requires an http(s) sse url")
        self._post_url = post_url
        self._sse_url = sse_url
        self._token = token
        self._extra_headers = dict(headers or {})
        self._timeout = float(timeout_s)
        self._ssl = ssl_context
        self._user_agent = user_agent
        self._pending: Dict[str, "_SsePending"] = {}
        self._lock = threading.Lock()
        self._reader: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def connect(self) -> None:
        """Open the SSE stream reader."""
        if self._open:
            return
        self._open = True
        self._stop.clear()
        self._reader = threading.Thread(target=self._pump_stream, name="mcp-sse-reader", daemon=True)
        self._reader.start()
        _LOG.info("sse transport connected", extra={"sse_url": self._sse_url})

    def close(self) -> None:
        """Stop the reader and mark the transport closed."""
        if not self._open:
            return
        self._open = False
        self._stop.set()
        if self._reader is not None:
            self._reader.join(timeout=self._timeout)
            self._reader = None
        _LOG.info("sse transport closed")

    # -- SSE reader ---------------------------------------------------------

    def _pump_stream(self) -> None:
        """Read the SSE stream, parsing ``data:`` frames and routing them."""
        headers = {
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
            "User-Agent": self._user_agent,
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        headers.update(self._extra_headers)
        req = urllib.request.Request(self._sse_url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout, context=self._ssl) as resp:  # noqa: S310
                for raw_line in resp:
                    if self._stop.is_set():
                        break
                    line = raw_line.decode("utf-8", "replace").rstrip("\n").rstrip("\r")
                    if not line.startswith("data:"):
                        continue
                    data = line[len("data:"):].strip()
                    if not data or data == "[DONE]":
                        continue
                    self._dispatch_sse(data)
        except Exception as exc:  # pragma: no cover - network teardown
            if not self._stop.is_set():
                _LOG.warning("sse stream reader ended", extra={"error": str(exc)})

    def _dispatch_sse(self, data: str) -> None:
        """Validate and route one SSE ``data:`` payload."""
        try:
            frame = json.loads(data)
        except json.JSONDecodeError:
            _LOG.warning("non-JSON SSE frame dropped", extra={"snippet": data[:80]})
            return
        if not isinstance(frame, dict):
            return
        if "method" in frame and "id" not in frame:
            note = JsonRpcNotification.from_dict(frame)
            self._emit_notification(note)
            return
        if "result" in frame or "error" in frame:
            response = self._validate_response(frame)
            with self._lock:
                pending = self._pending.pop(response.id, None)
            if pending is not None:
                pending.set(response)
            return
        _LOG.debug("unrouted SSE frame")

    # -- request/response ---------------------------------------------------

    def send(self, request: JsonRpcRequest) -> "JsonRpcResponse":
        """POST the request and wait for its response on the SSE stream.

        Args:
            request: The JSON-RPC request.

        Returns:
            The correlated response.

        Raises:
            TransportError: Not connected, or no response arrived in time.
        """
        if not self._open:
            raise TransportError("sse transport is not connected")
        import time

        event = threading.Event()
        promise: "_SsePending" = _SsePending(event)
        with self._lock:
            self._pending[request.id] = promise
        payload = json.dumps(request.to_dict()).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "AegisAgent-MCP/1.0",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        headers.update(self._extra_headers)
        req = urllib.request.Request(self._post_url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout, context=self._ssl) as _:  # noqa: S310
                pass
        except urllib.error.HTTPError as exc:
            with self._lock:
                self._pending.pop(request.id, None)
            if exc.code in (401, 403):
                raise McpError("MCP server rejected credentials", code=McpErrorCode.SERVER_UNTRUSTED, data={"status": exc.code})
            raise TransportError(f"MCP server returned HTTP {exc.code}", cause=exc, transient=True)
        except (urllib.error.URLError, OSError) as exc:
            with self._lock:
                self._pending.pop(request.id, None)
            raise TransportError(f"sse post failed: {exc}", cause=exc, transient=True)

        if not event.wait(timeout=self._timeout):
            with self._lock:
                self._pending.pop(request.id, None)
            raise TransportError(f"no SSE response within {self._timeout}s", transient=True)
        return promise.response


class _SsePending:
    """A minimal future for a single SSE-delivered response."""

    __slots__ = ("event", "response", "_lock")

    def __init__(self, event: threading.Event) -> None:
        self.event = event
        self.response: Optional[JsonRpcResponse] = None
        self._lock = threading.Lock()

    def set(self, response: "JsonRpcResponse") -> None:
        """Store the response and signal completion."""
        with self._lock:
            self.response = response
        self.event.set()
