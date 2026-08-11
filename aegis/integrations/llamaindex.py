"""LlamaIndex integration for AegisAgent.

Provides event handlers that intercept LlamaIndex tool calls and apply
AegisAgent governance policies.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from aegis.core.types import ToolCall
from aegis.core.logging import get_logger
from .common import IntegrationBase

__all__ = ["AegisLlamaIndexHandler"]

_log = get_logger(__name__)


class AegisLlamaIndexHandler(IntegrationBase):
    """LlamaIndex event handler for AegisAgent governance.

    Integrates with LlamaIndex's event system to intercept tool invocations
    and apply policy enforcement.
    """

    def __init__(self, agent: Optional[Any] = None) -> None:
        """Initialize the handler.

        Args:
            agent: Optional AegisAgent instance.
        """
        super().__init__(agent)

    def on_tool_start(self, event: Dict[str, Any]) -> None:
        """Handle tool start event.

        Args:
            event: Event data containing tool information.
        """
        tool_name = event.get("tool_name", "unknown")
        tool_input = event.get("tool_input", {})
        _log.info("llamaindex tool start", fields={"tool": tool_name})

        tool_call = ToolCall(
            tool=tool_name,
            arguments=tool_input,
            session_id=event.get("session_id", ""),
        )

        decision = self.agent.evaluate(tool_name, tool_input)
        if not decision.allowed:
            _log.warning("llamaindex tool blocked", fields={"tool": tool_name})

    def on_tool_end(self, event: Dict[str, Any]) -> None:
        """Handle tool end event.

        Args:
            event: Event data containing tool output.
        """
        _log.info("llamaindex tool end", fields={"tool": event.get("tool_name")})
