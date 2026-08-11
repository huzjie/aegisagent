"""Registry of connected MCP servers and their tool surfaces.

The inventory is the single source of truth the proxy consults to answer "what
tool is this, and which server owns it?".  Because multiple servers may each
advertise a tool called ``run`` or ``search``, every tool is namespaced as
``server::tool`` and shadowing is detected and flagged rather than silently
resolved in favour of whichever server registered first.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..core.errors import AegisError, ConflictError, NotFoundError
from ..core.logging import get_logger
from .protocol import ServerInfo, ToolDefinition

__all__ = ["ServerEntry", "McpInventory", "ToolLookup", "InventoryError"]

_LOG = get_logger("aegis.mcp.inventory")


class InventoryError(AegisError):
    """Raised on inventory consistency problems."""


@dataclass
class ServerEntry:
    """A registered MCP server and its advertised tools."""

    server_id: str
    name: str = ""
    spec: Dict[str, Any] = field(default_factory=dict)
    info: Optional[ServerInfo] = None
    tools: List[ToolDefinition] = field(default_factory=list)
    pinned: bool = False
    enabled: bool = True
    registered_at: float = 0.0
    last_seen: float = 0.0

    def qualified_tool(self, tool_name: str) -> str:
        """Return the ``server::tool`` namespace for a local tool name."""
        return f"{self.server_id}::{tool_name}"

    def find_tool(self, tool_name: str) -> Optional[ToolDefinition]:
        """Return the tool definition with ``tool_name`` if present."""
        for tool in self.tools:
            if tool.name == tool_name:
                return tool
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the entry (without the live transport)."""
        return {
            "server_id": self.server_id,
            "name": self.name,
            "spec": dict(self.spec),
            "tools": [t.name for t in self.tools],
            "pinned": self.pinned,
            "enabled": self.enabled,
            "transport": self.info.transport.value if self.info else "",
        }


@dataclass
class ToolLookup:
    """Resolution of a (possibly qualified) tool name to a server."""

    server_id: str
    tool: ToolDefinition

    @property
    def qualified_name(self) -> str:
        """Return ``server::tool``."""
        return f"{self.server_id}::{self.tool.name}"

    @property
    def server_name(self) -> str:
        """Return the owning server's display name."""
        return self.tool.server or self.server_id


class McpInventory:
    """In-memory registry of MCP servers and tools."""

    def __init__(self) -> None:
        self._servers: Dict[str, ServerEntry] = {}
        self._by_tool: Dict[str, str] = {}
        self._lock = threading.RLock()

    # -- registration -------------------------------------------------------

    def register(
        self,
        server_id: str,
        spec: Dict[str, Any],
        info: ServerInfo,
        *,
        pinned: bool = False,
        enabled: bool = True,
        registered_at: float = 0.0,
        last_seen: float = 0.0,
    ) -> ServerEntry:
        """Register or replace a server and index its tools.

        Args:
            server_id: Stable identifier.
            spec: The connection descriptor (serialisable).
            info: Discovered server info including tools.
            pinned: Whether the server passed pinning.
            enabled: Whether calls are currently allowed.
            registered_at: Epoch seconds of first registration.
            last_seen: Epoch seconds of last contact.

        Returns:
            The stored entry.

        Raises:
            ConflictError: A tool name collides *and* both servers are enabled
                (shadowing), which would make routing ambiguous.
        """
        with self._lock:
            entry = ServerEntry(
                server_id=server_id,
                name=info.name,
                spec=dict(spec),
                info=info,
                tools=list(info.tools),
                pinned=pinned,
                enabled=enabled,
                registered_at=registered_at or last_seen or 0.0,
                last_seen=last_seen or 0.0,
            )
            self._servers[server_id] = entry
            self._reindex_locked()
        return entry

    def _reindex_locked(self) -> None:
        """Rebuild the name→server map, detecting ambiguous shadowing."""
        self._by_tool.clear()
        for sid, entry in self._servers.items():
            if not entry.enabled:
                continue
            for tool in entry.tools:
                qn = entry.qualified_tool(tool.name)
                existing = self._by_tool.get(tool.name)
                if existing is not None and existing != qn:
                    _LOG.warning(
                        "tool name shadowing detected; qualify to disambiguate",
                        extra={"tool": tool.name, "a": existing, "b": qn},
                    )
                self._by_tool.setdefault(tool.name, qn)

    def unregister(self, server_id: str) -> bool:
        """Remove a server from the registry.

        Args:
            server_id: Identifier to remove.

        Returns:
            ``True`` if something was removed.
        """
        with self._lock:
            existed = self._servers.pop(server_id, None) is not None
            if existed:
                self._reindex_locked()
        return existed

    def set_enabled(self, server_id: str, enabled: bool) -> ServerEntry:
        """Enable or disable a server's tools.

        Args:
            server_id: Target server.
            enabled: New enabled state.

        Returns:
            The mutated entry.

        Raises:
            NotFoundError: Unknown server.
        """
        with self._lock:
            entry = self._servers.get(server_id)
            if entry is None:
                raise NotFoundError(f"unknown server: {server_id}", details={"server_id": server_id})
            entry.enabled = bool(enabled)
            self._reindex_locked()
        return entry

    # -- lookup -------------------------------------------------------------

    def resolve(self, name: str) -> ToolLookup:
        """Resolve a tool name (qualified or bare) to a server.

        Args:
            name: Either ``server::tool`` or ``tool``.  For bare names the
                first enabled server advertising it wins; shadowing is logged.

        Returns:
            A :class:`ToolLookup` with the owning server and tool definition.

        Raises:
            NotFoundError: No enabled server advertises the tool.
        """
        with self._lock:
            if "::" in name:
                sid, _, tool_name = name.partition("::")
                entry = self._servers.get(sid)
                if entry is None or not entry.enabled:
                    raise NotFoundError(f"unknown or disabled server: {sid}", details={"server_id": sid})
                tool = entry.find_tool(tool_name)
                if tool is None:
                    raise NotFoundError(
                        f"unknown tool {tool_name} on server {sid}",
                        details={"server_id": sid, "tool": tool_name},
                    )
                return ToolLookup(server_id=sid, tool=tool)
            qualified = self._by_tool.get(name)
            if qualified is None:
                raise NotFoundError(f"unknown tool: {name}", details={"tool": name})
            sid, _, tool_name = qualified.partition("::")
            entry = self._servers.get(sid)
            if entry is None or not entry.enabled:
                raise NotFoundError(f"tool {name} is on a disabled server", details={"tool": name})
            tool = entry.find_tool(tool_name)
            if tool is None:
                raise NotFoundError(f"unknown tool: {name}", details={"tool": name})
            return ToolLookup(server_id=sid, tool=tool)

    def server(self, server_id: str) -> ServerEntry:
        """Return a registered server entry.

        Args:
            server_id: Target server.

        Returns:
            The entry.

        Raises:
            NotFoundError: Unknown server.
        """
        with self._lock:
            entry = self._servers.get(server_id)
            if entry is None:
                raise NotFoundError(f"unknown server: {server_id}", details={"server_id": server_id})
            return entry

    def list_servers(self) -> List[ServerEntry]:
        """Return all registered server entries."""
        with self._lock:
            return list(self._servers.values())

    def list_tools(self) -> List[ToolDefinition]:
        """Return every tool across all enabled servers."""
        with self._lock:
            out: List[ToolDefinition] = []
            for entry in self._servers.values():
                if entry.enabled:
                    out.extend(entry.tools)
            return out

    def tool_names(self) -> List[str]:
        """Return every qualified tool name across enabled servers."""
        with self._lock:
            return [f"{sid}::{t.name}" for sid, entry in self._servers.items() if entry.enabled for t in entry.tools]
