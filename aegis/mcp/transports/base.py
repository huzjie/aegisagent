"""Transport abstraction for talking to MCP servers.

The proxy is **transport-agnostic**: whether a server is a local subprocess,
a remote HTTP endpoint or an SSE stream, the proxy only deals in
:class:`~aegis.mcp.protocol.JsonRpcRequest` / ``JsonRpcResponse`` frames.  Each
concrete transport in this package is responsible solely for moving those
frames and never for trust decisions.

Security note: every transport must treat the bytes it receives as untrusted.
Frames are validated through :mod:`aegis.mcp.protocol` before they reach the
proxy, and no transport may execute server-supplied code or follow redirects
to new hosts implicitly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional

from ..protocol import JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, McpError, TransportKind

__all__ = ["TransportError", "McpTransport", "NotificationHandler"]


class TransportError(Exception):
    """Raised when a transport cannot move frames to/from an MCP server."""

    def __init__(self, message: str = "", *, cause: Optional[BaseException] = None, transient: bool = False) -> None:
        super().__init__(message)
        self.cause = cause
        self.transient = transient


# A handler invoked for unsolicited notifications.
NotificationHandler = Callable[[JsonRpcNotification], None]


class McpTransport(ABC):
    """Base class every MCP transport implements."""

    #: The transport variant this class implements.
    kind: TransportKind = TransportKind.STDIO

    def __init__(self) -> None:
        self._open = False
        self._on_notification: Optional[NotificationHandler] = None

    @property
    def is_open(self) -> bool:
        """Whether the transport is currently connected."""
        return self._open

    def on_notification(self, handler: NotificationHandler) -> None:
        """Register a callback for unsolicited server notifications."""
        self._on_notification = handler

    def _emit_notification(self, note: JsonRpcNotification) -> None:
        """Dispatch a notification to the registered handler, if any."""
        if self._on_notification is not None:
            try:
                self._on_notification(note)
            except Exception:  # pragma: no cover - handler defect
                pass

    @abstractmethod
    def connect(self) -> None:
        """Establish the underlying connection (idempotent-safe)."""

    @abstractmethod
    def send(self, request: JsonRpcRequest) -> JsonRpcResponse:
        """Send a request and block for the correlated response.

        Args:
            request: The JSON-RPC request to transmit.

        Returns:
            The correlated response frame.

        Raises:
            TransportError: The frame could not be delivered or no response
                arrived within the transport's deadline.
        """

    @abstractmethod
    def close(self) -> None:
        """Tear down the connection and release resources."""

    # -- convenience helpers shared by subclasses ---------------------------

    @staticmethod
    def _validate_response(raw: Dict[str, Any]) -> JsonRpcResponse:
        """Parse and validate an inbound JSON-RPC response frame.

        Args:
            raw: Decoded JSON object from the wire.

        Returns:
            A parsed response.

        Raises:
            McpError: The frame is not a valid response.
        """
        try:
            return JsonRpcResponse.from_dict(raw)
        except McpError:
            raise
        except Exception as exc:  # malformed JSON structure
            raise McpError(f"invalid response frame: {exc}", code=McpErrorCode.INVALID_REQUEST)

    def __enter__(self) -> "McpTransport":
        """Context-manager entry; opens the transport."""
        self.connect()
        return self

    def __exit__(self, *exc: Any) -> None:
        """Context-manager exit; closes the transport."""
        self.close()
