"""Transport registry and factory for MCP servers.

Keeps the concrete transport classes behind one import surface and provides a
single :func:`build_transport` entry that maps a transport *kind* plus a
connection descriptor onto a ready-to-use :class:`McpTransport`.  The proxy
layer constructs transports through this factory so that new transports can be
added without touching the proxy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional

from ...core.logging import get_logger
from ..protocol import TransportKind
from .base import McpTransport, TransportError

__all__ = [
    "McpTransport",
    "TransportError",
    "StdioTransport",
    "HttpTransport",
    "SseTransport",
    "TransportSpec",
    "build_transport",
    "TRANSPORT_KINDS",
]

_LOG = get_logger("aegis.mcp.transports")

from .base import McpTransport, TransportError  # noqa: E402
from .http import HttpTransport  # noqa: E402
from .sse import SseTransport  # noqa: E402
from .stdio import StdioTransport  # noqa: E402

#: Connection kinds the factory understands.
TRANSPORT_KINDS = ("stdio", "http", "sse")


@dataclass
class TransportSpec:
    """Declarative description of how to reach an MCP server."""

    kind: str
    command: List[str] = None  # type: ignore[assignment]
    url: str = ""
    post_url: str = ""
    sse_url: str = ""
    token: str = ""
    env: Dict[str, str] = None  # type: ignore[assignment]
    headers: Dict[str, str] = None  # type: ignore[assignment]
    timeout_s: float = 30.0
    allow_env: List[str] = None  # type: ignore[assignment]

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TransportSpec":
        """Parse a transport descriptor, tolerating missing fields."""
        raw = dict(data or {})
        kind = str(raw.get("kind", "")).lower()
        return cls(
            kind=kind,
            command=list(raw.get("command", []) or []),
            url=str(raw.get("url", "") or raw.get("endpoint", "")),
            post_url=str(raw.get("post_url", "") or raw.get("url", "")),
            sse_url=str(raw.get("sse_url", "") or raw.get("stream_url", "")),
            token=str(raw.get("token", "") or ""),
            env=dict(raw.get("env", {}) or {}),
            headers=dict(raw.get("headers", {}) or {}),
            timeout_s=float(raw.get("timeout_s", 30.0)),
            allow_env=list(raw.get("allow_env", []) or []),
        )


def build_transport(spec: TransportSpec) -> McpTransport:
    """Construct a transport instance from a spec.

    Args:
        spec: The declarative connection description.

    Returns:
        A concrete, *unopened* transport.  Callers must ``connect()`` it.

    Raises:
        TransportError: The kind is unknown or the descriptor is incomplete.
    """
    kind = TransportKind(spec.kind) if spec.kind in TRANSPORT_KINDS else None
    if kind is None:
        raise TransportError(f"unknown transport kind: {spec.kind}")
    if kind is TransportKind.STDIO:
        if not spec.command:
            raise TransportError("stdio transport requires a command")
        return StdioTransport(
            spec.command,
            env=spec.env,
            timeout_s=spec.timeout_s,
            allow_env=spec.allow_env,
        )
    if kind is TransportKind.HTTP:
        if not spec.url:
            raise TransportError("http transport requires a url")
        return HttpTransport(
            spec.url,
            token=spec.token,
            headers=spec.headers,
            timeout_s=spec.timeout_s,
        )
    # SSE
    if not spec.post_url or not spec.sse_url:
        raise TransportError("sse transport requires post_url and sse_url")
    return SseTransport(
        spec.post_url,
        spec.sse_url,
        token=spec.token,
        headers=spec.headers,
        timeout_s=spec.timeout_s,
    )
