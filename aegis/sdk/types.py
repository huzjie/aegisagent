"""SDK type aliases and protocols.

Provides type hints for SDK users.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Protocol, runtime_checkable

from aegis.core.types import ToolCall, ToolResult, Decision

__all__ = ["ToolHandler", "DecisionCallback", "HookCallback"]


@runtime_checkable
class ToolHandler(Protocol):
    """Protocol for tool handler functions."""

    def __call__(self, **kwargs: Any) -> Any:
        """Execute the tool with given arguments."""
        ...


@runtime_checkable
class DecisionCallback(Protocol):
    """Protocol for decision callback functions."""

    def __call__(self, decision: Decision) -> None:
        """Handle a governance decision."""
        ...


@runtime_checkable
class HookCallback(Protocol):
    """Protocol for hook callback functions."""

    def __call__(self, tool_call: ToolCall, result: ToolResult) -> None:
        """Handle a hook event."""
        ...
