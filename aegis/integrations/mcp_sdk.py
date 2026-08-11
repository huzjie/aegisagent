"""MCP (Model Context Protocol) integration for AegisAgent.

Provides a governed MCP server wrapper that applies AegisAgent policies
to tool calls.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aegis.core.types import ToolCall, ToolDescriptor
from aegis.core.logging import get_logger
from .common import IntegrationBase

__all__ = ["AegisMCPServer"]

_log = get_logger(__name__)


class AegisMCPServer(IntegrationBase):
    """MCP server wrapper for AegisAgent governance.

    Wraps MCP server to apply policy enforcement to tool calls.
    """

    def __init__(self, agent: Optional[Any] = None) -> None:
        """Initialize the server wrapper.

        Args:
            agent: Optional AegisAgent instance.
        """
        super().__init__(agent)
        self._tools: Dict[str, ToolDescriptor] = {}

    def register_tool(self, descriptor: ToolDescriptor) -> None:
        """Register a tool with the MCP server.

        Args:
            descriptor: Tool descriptor with metadata.
        """
        self._tools[descriptor.name] = descriptor
        _log.info("mcp tool registered", fields={"tool": descriptor.name})

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Execute a tool with governance.

        Args:
            tool_name: Name of the tool.
            arguments: Tool arguments.

        Returns:
            Tool execution result.

        Raises:
            RuntimeError: If tool is blocked by policy.
        """
        _log.info("mcp tool call", fields={"tool": tool_name})

        decision = self.agent.evaluate(tool_name, arguments)
        if not decision.allowed:
            raise RuntimeError(f"Tool {tool_name} blocked: {decision.reason}")

        return {"status": "success", "tool": tool_name}

    def list_tools(self) -> List[ToolDescriptor]:
        """List all registered tools.

        Returns:
            List of tool descriptors.
        """
        return list(self._tools.values())
