"""CrewAI integration for AegisAgent.

Provides a governed tool wrapper for CrewAI agents.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from aegis.core.types import ToolCall
from aegis.core.logging import get_logger
from .common import IntegrationBase

__all__ = ["AegisCrewAITool"]

_log = get_logger(__name__)


class AegisCrewAITool(IntegrationBase):
    """CrewAI tool wrapper for AegisAgent governance.

    Wraps CrewAI tools to apply policy enforcement before execution.
    """

    def __init__(self, agent: Optional[Any] = None) -> None:
        """Initialize the tool wrapper.

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
        _log.info("crewai tool call", fields={"tool": tool_name})

        decision = self.agent.evaluate(tool_name, tool_input)
        if not decision.allowed:
            raise RuntimeError(f"Tool {tool_name} blocked: {decision.reason}")

        # In real implementation, would execute the actual tool
        return {"status": "success", "tool": tool_name}
