"""OpenAI Agents SDK integration for AegisAgent.

Provides a governed agent wrapper for OpenAI's Agents SDK.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aegis.core.types import ToolCall
from aegis.core.logging import get_logger
from .common import IntegrationBase

__all__ = ["AegisOpenAIAgent"]

_log = get_logger(__name__)


class AegisOpenAIAgent(IntegrationBase):
    """OpenAI Agents SDK wrapper for AegisAgent governance.

    Wraps OpenAI Agents SDK to apply policy enforcement to tool calls.
    """

    def __init__(self, agent: Optional[Any] = None) -> None:
        """Initialize the agent wrapper.

        Args:
            agent: Optional AegisAgent instance.
        """
        super().__init__(agent)
        self._tools: List[Dict[str, Any]] = []

    def add_tool(self, tool_spec: Dict[str, Any]) -> None:
        """Add a tool specification.

        Args:
            tool_spec: Tool specification with name, description, and parameters.
        """
        self._tools.append(tool_spec)
        _log.info("openai agent tool added", fields={"tool": tool_spec.get("name")})

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
        _log.info("openai agent tool call", fields={"tool": tool_name})

        decision = self.agent.evaluate(tool_name, arguments)
        if not decision.allowed:
            raise RuntimeError(f"Tool {tool_name} blocked: {decision.reason}")

        return {"status": "success", "tool": tool_name}
