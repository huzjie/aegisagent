"""Wire-level protocol types for the Model Context Protocol (MCP).

AegisAgent speaks MCP with downstream servers so it can inventory and guard
their tools, but it never trusts a server's self-description.  Every type here
is a plain, serialisable structure; trust decisions live in
:mod:`aegis.mcp.pinning`, :mod:`aegis.mcp.scanner` and
:mod:`aegis.mcp.registry_guard`.

The shapes deliberately track the JSON-RPC 2.0 envelope MCP uses over its
transports, so the proxy can forward, inspect and rewrite frames without
re-encoding semantics.
"""

from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from ..core.types import ToolCall, ToolResult

__all__ = [
    "McpError",
    "McpErrorCode",
    "TransportKind",
    "JsonRpcRequest",
    "JsonRpcResponse",
    "JsonRpcNotification",
    "ToolDefinition",
    "ToolParameter",
    "ToolAnnotations",
    "CallRequest",
    "CallResult",
    "CallId",
    "ServerInfo",
    "Capability",
    "new_rpc_id",
]

#: A JSON-RPC correlation id.  The spec permits string or integer; AegisAgent
#: always *emits* strings but must accept both when parsing a server reply.
CallId = Union[str, int]

# Stable per-process id counter for JSON-RPC correlation.
_ID_LOCK = threading.Lock()
_ID_GEN = itertools.count(1)


def new_rpc_id(prefix: str = "rpc") -> str:
    """Return a process-unique JSON-RPC identifier."""
    with _ID_LOCK:
        return f"{prefix}-{next(_ID_GEN)}"


class McpError(Exception):
    """Raised when an MCP frame or interaction is malformed / rejected."""

    def __init__(
        self,
        message: str = "",
        *,
        code: Optional["McpErrorCode"] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Create the error.

        Args:
            message: Human readable description of the violation.
            code: JSON-RPC / MCP error code; defaults to ``INTERNAL``.
            data: Structured context attached to the JSON-RPC error object.
        """
        super().__init__(message)
        self.code = code or McpErrorCode.INTERNAL
        self.data = data or {}


class McpErrorCode(int, Enum):
    """Standard JSON-RPC 2.0 error codes plus MCP-specific extensions."""

    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL = -32603
    # MCP / AegisAgent security extensions (server-range to avoid clashes).
    TOOL_BLOCKED = -32001
    TOOL_NOT_PINNED = -32002
    SERVER_UNTRUSTED = -32003
    RATE_LIMITED = -32004
    RESULT_REDACTED = -32005

    @classmethod
    def from_int(cls, value: int) -> "McpErrorCode":
        """Coerce a raw integer into the enum, falling back to INTERNAL."""
        try:
            return cls(value)
        except ValueError:
            return cls.INTERNAL


class TransportKind(str, Enum):
    """How an MCP server is reached."""

    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"
    INPROCESS = "inprocess"

    @property
    def is_remote(self) -> bool:
        """Whether the transport crosses a network boundary."""
        return self in (TransportKind.HTTP, TransportKind.SSE)


@dataclass
class JsonRpcRequest:
    """A JSON-RPC 2.0 request frame."""

    method: str
    params: Dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_rpc_id())
    jsonrpc: str = "2.0"

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a JSON-RPC envelope."""
        return {"jsonrpc": self.jsonrpc, "method": self.method, "params": self.params, "id": self.id}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "JsonRpcRequest":
        """Parse a JSON-RPC request, raising :class:`McpError` on bad shape."""
        if not isinstance(data, dict) or data.get("jsonrpc") != "2.0" or "method" not in data:
            raise McpError("not a valid JSON-RPC 2.0 request", code=McpErrorCode.INVALID_REQUEST)
        return cls(
            method=str(data["method"]),
            params=dict(data.get("params", {}) or {}),
            id=str(data.get("id", new_rpc_id())),
        )


@dataclass
class JsonRpcResponse:
    """A JSON-RPC 2.0 response frame."""

    id: str
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None
    jsonrpc: str = "2.0"

    @property
    def is_error(self) -> bool:
        """Whether the frame carries an error object."""
        return self.error is not None

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a JSON-RPC envelope."""
        body: Dict[str, Any] = {"jsonrpc": self.jsonrpc, "id": self.id}
        if self.error is not None:
            body["error"] = self.error
        else:
            body["result"] = self.result
        return body

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "JsonRpcResponse":
        """Parse a JSON-RPC response, raising :class:`McpError` on bad shape."""
        if not isinstance(data, dict) or data.get("jsonrpc") != "2.0":
            raise McpError("not a valid JSON-RPC 2.0 response", code=McpErrorCode.INVALID_REQUEST)
        return cls(
            id=str(data.get("id", new_rpc_id())),
            result=data.get("result"),
            error=data.get("error"),
        )


@dataclass
class JsonRpcNotification:
    """An unsolicited JSON-RPC notification (no id, no response)."""

    method: str
    params: Dict[str, Any] = field(default_factory=dict)
    jsonrpc: str = "2.0"

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a JSON-RPC envelope."""
        return {"jsonrpc": self.jsonrpc, "method": self.method, "params": self.params}


@dataclass
class ToolParameter:
    """A single declared tool parameter."""

    name: str
    type: str = "string"
    description: str = ""
    required: bool = False
    enum: List[str] = field(default_factory=list)
    default: Any = None
    schema: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to an MCP tool-schema parameter object."""
        out: Dict[str, Any] = {"name": self.name, "type": self.type}
        if self.description:
            out["description"] = self.description
        if self.required:
            out["required"] = True
        if self.enum:
            out["enum"] = list(self.enum)
        if self.default is not None:
            out["default"] = self.default
        if self.schema:
            out["schema"] = self.schema
        return out

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolParameter":
        """Parse a parameter object, tolerating missing fields."""
        return cls(
            name=str(data.get("name", "")),
            type=str(data.get("type", "string")),
            description=str(data.get("description", "")),
            required=bool(data.get("required", False)),
            enum=list(data.get("enum", []) or []),
            default=data.get("default"),
            schema=dict(data.get("schema", {}) or {}),
        )


@dataclass
class ToolAnnotations:
    """MCP tool annotations used to infer risk."""

    title: str = ""
    read_only_hint: bool = False
    destructive_hint: bool = False
    idempotent_hint: bool = False
    open_world_hint: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to an MCP annotations object."""
        return {
            "title": self.title,
            "readOnlyHint": self.read_only_hint,
            "destructiveHint": self.destructive_hint,
            "idempotentHint": self.idempotent_hint,
            "openWorldHint": self.open_world_hint,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolAnnotations":
        """Parse annotations, defaulting every hint to false."""
        if not isinstance(data, dict):
            return cls()
        return cls(
            title=str(data.get("title", "")),
            read_only_hint=bool(data.get("readOnlyHint", False)),
            destructive_hint=bool(data.get("destructiveHint", False)),
            idempotent_hint=bool(data.get("idempotentHint", False)),
            open_world_hint=bool(data.get("openWorldHint", False)),
        )


@dataclass
class ToolDefinition:
    """A tool as advertised by an MCP server."""

    name: str
    description: str = ""
    server: str = ""
    parameters: List[ToolParameter] = field(default_factory=list)
    annotations: ToolAnnotations = field(default_factory=ToolAnnotations)
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def qualified_name(self) -> str:
        """Return ``server::name`` so the proxy can namespace tools."""
        return f"{self.server}::{self.name}" if self.server else self.name

    @property
    def is_read_only(self) -> bool:
        """Whether the server claims the tool only reads."""
        return self.annotations.read_only_hint and not self.annotations.destructive_hint

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to an MCP ``tools/list`` entry."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": {
                "type": "object",
                "properties": {p.name: p.to_dict() for p in self.parameters},
            },
            "annotations": self.annotations.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], *, server: str = "") -> "ToolDefinition":
        """Parse a tool entry from ``tools/list``."""
        if not isinstance(data, dict):
            raise McpError("tool definition must be an object", code=McpErrorCode.INVALID_PARAMS)
        props = (data.get("inputSchema") or {}).get("properties", {}) or {}
        params = [ToolParameter.from_dict({"name": name, **(spec or {})}) for name, spec in props.items()]
        return cls(
            name=str(data.get("name", "")),
            description=str(data.get("description", "")),
            server=server,
            parameters=params,
            annotations=ToolAnnotations.from_dict(data.get("annotations", {}) or {}),
            raw=dict(data),
        )


@dataclass
class CallRequest:
    """A proxied tool invocation."""

    tool: str
    server: str = ""
    arguments: Dict[str, Any] = field(default_factory=dict)
    call_id: str = field(default_factory=lambda: new_rpc_id("call"))
    session_id: str = ""
    agent_id: str = ""
    tenant_id: str = "default"
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def qualified_name(self) -> str:
        """Return ``server::tool``."""
        return f"{self.server}::{self.tool}" if self.server else self.tool

    def to_tool_call(self) -> ToolCall:
        """Project this request onto the shared :class:`ToolCall` shape."""
        return ToolCall(
            id=self.call_id,
            session_id=self.session_id,
            agent_id=self.agent_id,
            tenant_id=self.tenant_id,
            tool=self.tool,
            server=self.server,
            arguments=self.arguments,
        )


@dataclass
class CallResult:
    """Outcome of a proxied tool invocation."""

    call_id: str
    ok: bool = True
    content: Any = None
    error: str = ""
    is_error: bool = False
    duration_ms: float = 0.0
    redacted: bool = False
    truncated: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_tool_result(self) -> ToolResult:
        """Project onto the shared :class:`ToolResult` shape."""
        return ToolResult(
            call_id=self.call_id,
            ok=self.ok,
            content=self.content,
            error=self.error,
            duration_ms=self.duration_ms,
            redacted=self.redacted,
            truncated=self.truncated,
        )


@dataclass
class ServerInfo:
    """Identity and capability summary discovered from a server."""

    name: str
    version: str = ""
    server_id: str = ""
    transport: TransportKind = TransportKind.STDIO
    capabilities: List[str] = field(default_factory=list)
    tools: List[ToolDefinition] = field(default_factory=list)
    instructions: str = ""
    fingerprint: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the server summary."""
        return {
            "name": self.name,
            "version": self.version,
            "server_id": self.server_id,
            "transport": self.transport.value,
            "capabilities": list(self.capabilities),
            "tools": [t.to_dict() for t in self.tools],
            "instructions": self.instructions,
            "fingerprint": self.fingerprint,
        }


@dataclass
class Capability:
    """A single negotiated feature flag."""

    name: str
    enabled: bool = True
    params: Dict[str, Any] = field(default_factory=dict)
