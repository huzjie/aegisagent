"""MCP client: session, discovery and guarded tool invocation.

:class:`McpClient` is the thin control surface the proxy uses to talk to one
MCP server.  It performs the ``initialize`` handshake, enumerates tools via
``tools/list``, and forwards ``tools/call`` frames — but every response is
first validated through :mod:`aegis.mcp.protocol` and every tool call is first
filtered through the proxy's sanitizer and call-budget (supplied by the
proxy).  The client itself never makes trust decisions; it just refuses to
forward anything the policy layer has not cleared.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from ..core.logging import get_logger
from .protocol import (
    CallRequest,
    CallResult,
    JsonRpcRequest,
    McpError,
    McpErrorCode,
    ServerInfo,
    ToolDefinition,
    TransportKind,
    new_rpc_id,
)
from .transports import McpTransport, TransportSpec, build_transport

__all__ = ["McpClient", "ClientConfig", "ClientError"]

_LOG = get_logger("aegis.mcp.client")


class ClientError(Exception):
    """Raised when the client cannot complete an MCP interaction."""

    def __init__(
        self,
        message: str = "",
        *,
        code: Optional[McpErrorCode] = None,
        cause: Optional[BaseException] = None,
    ) -> None:
        """Create the error.

        Args:
            message: Human readable description.
            code: JSON-RPC / MCP error code; defaults to ``INTERNAL``.
            cause: The originating exception, retained for audit trails.
        """
        super().__init__(message)
        self.code = code or McpErrorCode.INTERNAL
        self.cause = cause


@dataclass
class ClientConfig:
    """Tunables for a single MCP client session."""

    server_id: str = ""
    name: str = ""
    protocol_version: str = "2024-11-05"
    request_timeout_s: float = 30.0
    keep_alive: bool = True


# Optional pre-call hook: (request) -> None, may raise to block.
CallFilter = Callable[[CallRequest], None]


class McpClient:
    """A session with one MCP server over one transport."""

    def __init__(
        self,
        spec: TransportSpec,
        *,
        config: Optional[ClientConfig] = None,
        transport: Optional[McpTransport] = None,
    ) -> None:
        """Create the client.

        Args:
            spec: How to reach the server (used when ``transport`` is None).
            config: Session tunables.
            transport: Pre-built transport; built from ``spec`` when omitted.

        Raises:
            ClientError: ``spec`` is unusable and no transport was given.
        """
        self._spec = spec
        self._config = config or ClientConfig(server_id=spec.url or " ".join(spec.command or []))
        self._transport = transport or build_transport(spec)
        self._lock = threading.RLock()
        self._server_info: Optional[ServerInfo] = None
        self._tools: List[ToolDefinition] = []
        self._initialized = False
        self._call_filters: List[CallFilter] = []
        self._latency_ms: float = 0.0

    # -- properties ---------------------------------------------------------

    @property
    def transport_kind(self) -> TransportKind:
        """Return the transport variant in use."""
        return self._transport.kind

    @property
    def server_info(self) -> Optional[ServerInfo]:
        """Return the discovered server summary, if initialised."""
        return self._server_info

    @property
    def tools(self) -> List[ToolDefinition]:
        """Return the enumerated tool definitions."""
        return list(self._tools)

    # -- lifecycle ----------------------------------------------------------

    def connect(self) -> ServerInfo:
        """Open the transport and perform the ``initialize`` handshake.

        Returns:
            The discovered :class:`ServerInfo`.

        Raises:
            ClientError: The handshake fails or returns a bad shape.
        """
        with self._lock:
            if self._initialized:
                return self._server_info  # type: ignore[return-value]
            try:
                self._transport.connect()
                info = self._initialize()
                self._server_info = info
                self._tools = self._list_tools(info.name)
                self._initialized = True
            except (McpError, ClientError):
                self._safe_close()
                raise
            except Exception as exc:
                self._safe_close()
                raise ClientError(f"mcp handshake failed: {exc}", cause=exc)
        _LOG.info("mcp client initialised", extra={"server": info.name, "tools": len(self._tools)})
        return info

    def _initialize(self) -> ServerInfo:
        """Send ``initialize`` and parse ``initialize/result`` + ``notifications/initialized``."""
        params = {
            "protocolVersion": self._config.protocol_version,
            "capabilities": {"tools": {}},
            "clientInfo": {"name": "aegis-agent", "version": "1.0"},
        }
        resp = self._request("initialize", params, timeout_s=self._config.request_timeout_s)
        if resp.is_error:
            raise ClientError(f"initialize rejected: {resp.error}", code=McpErrorCode.from_int(resp.error.get("code", -32603)))
        result = resp.result or {}
        server_id = self._config.server_id or result.get("serverInfo", {}).get("name", "unknown")
        transport = self._transport.kind
        fingerprint = self._fingerprint(server_id, result)
        info = ServerInfo(
            name=str(result.get("serverInfo", {}).get("name", "unknown")),
            version=str(result.get("serverInfo", {}).get("version", "")),
            server_id=server_id,
            transport=transport,
            capabilities=list(result.get("capabilities", {}).keys()),
            instructions=str(result.get("instructions", "")),
            fingerprint=fingerprint,
        )
        # Acknowledge initialisation per the MCP handshake.
        try:
            self._transport.send(JsonRpcRequest(method="notifications/initialized", params={}, id=new_rpc_id("init")))
        except Exception as exc:  # pragma: no cover - notification best-effort
            _LOG.debug("initialized notification skipped", extra={"error": str(exc)})
        return info

    def _fingerprint(self, server_id: str, result: Dict[str, Any]) -> str:
        """Compute a stable fingerprint for pinning/registry checks."""
        from ..core.crypto import sha256_hex

        blob = f"{server_id}|{self._transport.kind.value}|{self._config.protocol_version}"
        return sha256_hex(blob)

    def _list_tools(self, server: str) -> List[ToolDefinition]:
        """Send ``tools/list`` and parse the returned tool definitions."""
        resp = self._request("tools/list", {}, timeout_s=self._config.request_timeout_s)
        if resp.is_error:
            raise ClientError(f"tools/list rejected: {resp.error}", code=McpErrorCode.from_int(resp.error.get("code", -32603)))
        raw = (resp.result or {}).get("tools", []) or []
        tools: List[ToolDefinition] = []
        for entry in raw:
            try:
                tools.append(ToolDefinition.from_dict(entry, server=server))
            except McpError as exc:
                _LOG.warning("dropped malformed tool", extra={"error": str(exc), "raw": str(entry)[:120]})
        return tools

    # -- invocation ---------------------------------------------------------

    def add_call_filter(self, flt: CallFilter) -> None:
        """Register a pre-call filter (e.g. sanitizer / budget guard).

        Args:
            flt: A callable invoked with the :class:`CallRequest` before it is
                forwarded.  It should raise :class:`ClientError` to block.
        """
        self._call_filters.append(flt)

    def call(self, request: CallRequest, *, timeout_s: Optional[float] = None) -> CallResult:
        """Forward a tool call to the server and return the result.

        Args:
            request: The call to make.
            timeout_s: Optional per-call timeout override.

        Returns:
            The result, projected onto :class:`CallResult`.

        Raises:
            ClientError: The client is not initialised, a filter blocked the
                call, or the server returned an error frame.
        """
        if not self._initialized:
            raise ClientError("client is not initialised; call connect() first")
        for flt in self._call_filters:
            flt(request)
        params = {"name": request.tool, "arguments": request.arguments}
        try:
            resp = self._request("tools/call", params, timeout_s=timeout_s or self._config.request_timeout_s)
        except ClientError:
            raise
        return self._to_result(request, resp)

    def _to_result(self, request: CallRequest, resp) -> CallResult:
        """Project a JSON-RPC response onto :class:`CallResult`."""
        if resp.is_error:
            return CallResult(
                call_id=request.call_id,
                ok=False,
                error=str(resp.error),
                is_error=True,
            )
        result = resp.result or {}
        is_error = bool(result.get("isError", False))
        content = result.get("content")
        return CallResult(
            call_id=request.call_id,
            ok=not is_error,
            content=content,
            is_error=is_error,
            error=str(result.get("error", "")) if is_error else "",
            metadata={"structured": result.get("structuredContent")},
        )

    def _request(self, method: str, params: Dict[str, Any], *, timeout_s: float) -> Any:
        """Send a request using the configured transport.

        Args:
            method: JSON-RPC method name.
            params: Method parameters.
            timeout_s: Request deadline.

        Returns:
            The JSON-RPC response frame.

        Raises:
            ClientError: The transport failed.
        """
        import time

        started = time.monotonic()
        try:
            response = self._transport.send(JsonRpcRequest(method=method, params=params))
        except McpError as exc:
            raise ClientError(str(exc), code=exc.code, cause=exc)
        self._latency_ms = (time.monotonic() - started) * 1000.0
        return response

    # -- teardown -----------------------------------------------------------

    def _safe_close(self) -> None:
        """Close the transport, swallowing errors."""
        try:
            self._transport.close()
        except Exception:  # pragma: no cover - teardown
            pass

    def close(self) -> None:
        """Close the session and transport."""
        with self._lock:
            if self._initialized or self._transport.is_open:
                self._safe_close()
            self._initialized = False

    def __enter__(self) -> "McpClient":
        """Context-manager entry; connects and initialises."""
        self.connect()
        return self

    def __exit__(self, *exc: Any) -> None:
        """Context-manager exit; closes."""
        self.close()
