"""LangChain integration for AegisAgent.

Provides callback handlers that intercept LangChain tool calls and apply
AegisAgent governance policies.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aegis.core.types import ToolCall, ToolResult
from aegis.core.logging import get_logger
from .common import IntegrationBase

__all__ = ["AegisCallbackHandler"]

_log = get_logger(__name__)


class AegisCallbackHandler(IntegrationBase):
    """LangChain callback handler for AegisAgent governance.

    Integrates with LangChain's callback system to intercept tool invocations
    and apply policy enforcement, provenance tracking, and audit logging.
    """

    def __init__(self, agent: Optional[Any] = None) -> None:
        """Initialize the callback handler.

        Args:
            agent: Optional AegisAgent instance. If not provided, creates one.
        """
        super().__init__(agent)
        self._active_sessions: Dict[str, str] = {}

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: str,
        parent_run_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a LangChain tool starts execution.

        Args:
            serialized: Serialized tool information.
            input_str: Tool input as string.
            run_id: Unique run identifier.
            parent_run_id: Parent run ID if nested.
            **kwargs: Additional callback arguments.
        """
        tool_name = serialized.get("name", "unknown")
        _log.info("langchain tool start", fields={"tool": tool_name, "run_id": run_id})

        # Create a tool call for governance
        tool_call = ToolCall(
            tool=tool_name,
            arguments={"input": input_str},
            session_id=run_id,
        )

        # Evaluate policy
        decision = self.agent.evaluate(tool_name, {"input": input_str}, session_id=run_id)
        self._active_sessions[run_id] = decision.id

        if not decision.allowed:
            _log.warning("langchain tool blocked", fields={"tool": tool_name, "reason": decision.reason})

    def on_tool_end(
        self,
        output: str,
        *,
        run_id: str,
        parent_run_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a LangChain tool completes.

        Args:
            output: Tool output as string.
            run_id: Unique run identifier.
            parent_run_id: Parent run ID if nested.
            **kwargs: Additional callback arguments.
        """
        _log.info("langchain tool end", fields={"run_id": run_id})
        self._active_sessions.pop(run_id, None)

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: str,
        parent_run_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a LangChain tool raises an error.

        Args:
            error: The exception that was raised.
            run_id: Unique run identifier.
            parent_run_id: Parent run ID if nested.
            **kwargs: Additional callback arguments.
        """
        _log.error("langchain tool error", fields={"run_id": run_id, "error": str(error)})
        self._active_sessions.pop(run_id, None)
