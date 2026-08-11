"""Smolagents integration for AegisAgent.

Provides a governed agent wrapper for the Smolagents framework.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from aegis.core.types import ToolCall
from aegis.core.logging import get_logger
from .common import IntegrationBase

__all__ = ["AegisSmolAgent"]

_log = get_logger(__name__)


class AegisSmolAgent(IntegrationBase):
    """Smolagents wrapper for AegisAgent governance.

    Wraps Smolagents to apply policy enforcement to tool calls.
    """

    def __init__(self, agent: Optional[Any] = None) -> None:
        """Initialize the agent wrapper.

        Args:
            agent: Optional AegisAgent instance.
        """
        super().__init__(agent)

    def execute_tool(self, tool_name: str, tool_input: Dict[str, Any]) -> Any:
        """Execute a tool with governance.

        Args:
            tool_name: Name of the tool.
            tool_input: Tool input arguments.

        Returns:
            Tool execution result.

        Raises:
            RuntimeError: If tool is blocked by policy.
        """
        _log.info("smolagents tool call", fields={"tool": tool_name})

        decision = self.agent.evaluate(tool_name, tool_input)
        if not decision.allowed:
            raise RuntimeError(f"Tool {tool_name} blocked: {decision.reason}")

        return {"status": "success", "tool": tool_name}
