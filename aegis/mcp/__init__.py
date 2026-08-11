"""MCP (Model Context Protocol) security proxy layer.

Agents increasingly obtain their capabilities from MCP servers they did not
author and cannot audit.  The 2026-08 incidents showed three distinct failure
modes in that supply chain:

1. **Server swap** — a previously trusted server was replaced (or its binary
   updated) and kept the same name, so the agent kept calling it.  Countered by
   :mod:`aegis.mcp.pinning`, which fingerprints server identity + tool surface
   and refuses silently-changed servers.
2. **Tool shadowing / look-alike names** — a malicious server registers
   ``read_file`` or ``rеad_file`` (Cyrillic ``е``) and wins name resolution.
   Countered by :mod:`aegis.mcp.registry_guard` and the strict qualified-name
   resolution in :mod:`aegis.mcp.inventory`.
3. **Poisoned tool descriptions and results** — instructions smuggled into a
   tool description or a tool result hijack the agent.  Countered by
   :mod:`aegis.mcp.scanner` (static, at admission time) and
   :mod:`aegis.mcp.sanitizer` (dynamic, on every call and every result).

:class:`~aegis.mcp.proxy.McpProxy` is the single enforcement point that wires
all of the above together; nothing else in AegisAgent should talk to an MCP
server directly.

Typical use::

    from aegis.mcp import McpProxy, ProxyConfig, TransportSpec

    proxy = McpProxy(ProxyConfig())
    proxy.attach("files", TransportSpec(kind="stdio", command=["mcp-files"]))
    result = proxy.call(tool_call)

Every submodule is import-safe on both Windows and POSIX; platform-specific
process handling lives behind ``sys.platform`` branches inside
:mod:`aegis.mcp.transports.stdio`.
"""

from __future__ import annotations

from .client import ClientConfig, ClientError, McpClient
from .inventory import InventoryError, McpInventory, ServerEntry, ToolLookup
from .pinning import PinError, PinningPolicy, PinRecord, PinState, ServerPinner
from .protocol import (
    CallId,
    CallRequest,
    CallResult,
    Capability,
    JsonRpcNotification,
    JsonRpcRequest,
    JsonRpcResponse,
    McpError,
    McpErrorCode,
    ServerInfo,
    ToolAnnotations,
    ToolDefinition,
    ToolParameter,
    TransportKind,
    new_rpc_id,
)
from .proxy import McpProxy, ProxyConfig, ProxyStats, ToolObligations
from .registry_guard import (
    TRUSTED_PROVIDERS,
    GuardVerdict,
    RegistryGuard,
    RegistryGuardConfig,
    ShadowingReport,
)
from .sanitizer import (
    PROMPT_INJECTION_MARKERS,
    SECRET_KEY_HINTS,
    ArgumentSanitizer,
    SanitizeDecision,
    SanitizeResult,
    SanitizerConfig,
    looks_like_secret_value,
)
from .scanner import (
    ScannerConfig,
    ServerScanReport,
    ToolFinding,
    ToolRisk,
    ToolScanner,
    ToolScanReport,
)
from .transports import (
    TRANSPORT_KINDS,
    HttpTransport,
    McpTransport,
    SseTransport,
    StdioTransport,
    TransportError,
    TransportSpec,
    build_transport,
)

__all__ = [
    # proxy (the enforcement point)
    "McpProxy",
    "ProxyConfig",
    "ProxyStats",
    "ToolObligations",
    # client
    "McpClient",
    "ClientConfig",
    "ClientError",
    # protocol
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
    # transports
    "McpTransport",
    "TransportError",
    "StdioTransport",
    "HttpTransport",
    "SseTransport",
    "TransportSpec",
    "build_transport",
    "TRANSPORT_KINDS",
    # pinning
    "ServerPinner",
    "PinningPolicy",
    "PinRecord",
    "PinState",
    "PinError",
    # inventory
    "McpInventory",
    "ServerEntry",
    "ToolLookup",
    "InventoryError",
    # registry guard
    "RegistryGuard",
    "RegistryGuardConfig",
    "GuardVerdict",
    "ShadowingReport",
    "TRUSTED_PROVIDERS",
    # scanner
    "ToolScanner",
    "ScannerConfig",
    "ToolScanReport",
    "ServerScanReport",
    "ToolFinding",
    "ToolRisk",
    # sanitizer
    "ArgumentSanitizer",
    "SanitizerConfig",
    "SanitizeDecision",
    "SanitizeResult",
    "looks_like_secret_value",
    "SECRET_KEY_HINTS",
    "PROMPT_INJECTION_MARKERS",
]
