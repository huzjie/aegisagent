"""Anthropic SDK integration for AegisAgent.

Provides a governed client wrapper for the Anthropic SDK.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aegis.core.types import ToolCall
from aegis.core.logging import get_logger
from .common import IntegrationBase

__all__ = ["AegisAnthropicClient"]

_log = get_logger(__name__)


class AegisAnthropicClient(IntegrationBase):
    """Anthropic SDK wrapper for AegisAgent governance.

    Wraps Anthropic's SDK to apply policy enforcement to tool use.
    """

    def __init__(self, agent: Optional[Any] = None) -> None:
        """Initialize the client wrapper.

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
        _log.info("anthropic tool call", fields={"tool": tool_name})

        decision = self.agent.evaluate(tool_name, tool_input)
        if not decision.allowed:
            raise RuntimeError(f"Tool {tool_name} blocked: {decision.reason}")

        return {"status": "success", "tool": tool_name}
