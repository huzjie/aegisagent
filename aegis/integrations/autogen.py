"""AutoGen integration for AegisAgent.

Provides middleware that intercepts AutoGen tool calls and applies
AegisAgent governance policies.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from aegis.core.types import ToolCall
from aegis.core.logging import get_logger
from .common import IntegrationBase

__all__ = ["AegisAutoGenMiddleware"]

_log = get_logger(__name__)


class AegisAutoGenMiddleware(IntegrationBase):
    """AutoGen middleware for AegisAgent governance.

    Wraps AutoGen's tool execution to apply policy enforcement before
    tools are invoked.
    """

    def __init__(self, agent: Optional[Any] = None) -> None:
        """Initialize the middleware.

        Args:
            agent: Optional AegisAgent instance.
        """
        super().__init__(agent)

    def wrap_tool(self, tool_func: Callable, tool_name: str) -> Callable:
        """Wrap a tool function with governance.

        Args:
            tool_func: Original tool function.
            tool_name: Name of the tool.

        Returns:
            Wrapped function that applies governance.
        """
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            _log.info("autogen tool call", fields={"tool": tool_name})

            # Evaluate policy
            decision = self.agent.evaluate(tool_name, kwargs)
            if not decision.allowed:
                raise RuntimeError(f"Tool {tool_name} blocked by policy: {decision.reason}")

            return tool_func(*args, **kwargs)

        return wrapped
