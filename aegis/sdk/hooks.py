"""Lifecycle hooks for SDK events.

Provides a registry for hook callbacks that are invoked at various points
in the tool execution lifecycle.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List

from aegis.core.types import ToolCall, ToolResult
from aegis.core.logging import get_logger

__all__ = ["HookRegistry", "pre_decision", "post_decision", "on_deny", "on_approve"]

_log = get_logger(__name__)


class HookRegistry:
    """Registry for lifecycle hook callbacks.

    Supports the following events:
    - pre_decision: called before policy evaluation
    - post_decision: called after policy evaluation
    - on_deny: called when a tool call is denied
    - on_approve: called when a tool call is approved
    """

    def __init__(self) -> None:
        self._hooks: Dict[str, List[Callable]] = {
            "pre_decision": [],
            "post_decision": [],
            "on_deny": [],
            "on_approve": [],
        }

    def register(self, event: str, callback: Callable) -> None:
        """Register a callback for an event.

        Args:
            event: event name.
            callback: callable to invoke.
        """
        if event not in self._hooks:
            _log.warning("unknown hook event", fields={"event": event})
            return
        self._hooks[event].append(callback)
        _log.info("hook registered", fields={"event": event})

    def run_pre_decision(self, tool_call: ToolCall) -> None:
        """Run pre-decision hooks."""
        for callback in self._hooks["pre_decision"]:
            try:
                callback(tool_call)
            except Exception as e:
                _log.exception("pre_decision hook failed", fields={"error": str(e)})

    def run_post_decision(self, tool_call: ToolCall, result: ToolResult) -> None:
        """Run post-decision hooks."""
        for callback in self._hooks["post_decision"]:
            try:
                callback(tool_call, result)
            except Exception as e:
                _log.exception("post_decision hook failed", fields={"error": str(e)})

    def run_on_deny(self, tool_call: ToolCall, reason: str) -> None:
        """Run on-deny hooks."""
        for callback in self._hooks["on_deny"]:
            try:
                callback(tool_call, reason)
            except Exception as e:
                _log.exception("on_deny hook failed", fields={"error": str(e)})

    def run_on_approve(self, tool_call: ToolCall) -> None:
        """Run on-approve hooks."""
        for callback in self._hooks["on_approve"]:
            try:
                callback(tool_call)
            except Exception as e:
                _log.exception("on_approve hook failed", fields={"error": str(e)})


def pre_decision(func: Callable) -> Callable:
    """Decorator to mark a function as a pre-decision hook.

    Args:
        func: callback function.

    Returns:
        The original function.

    Example:
        @pre_decision
        def log_tool_call(tool_call: ToolCall):
            print(f"Calling: {tool_call.tool}")
    """
    func._hook_event = "pre_decision"
    return func


def post_decision(func: Callable) -> Callable:
    """Decorator to mark a function as a post-decision hook.

    Args:
        func: callback function.

    Returns:
        The original function.

    Example:
        @post_decision
        def log_result(tool_call: ToolCall, result: ToolResult):
            print(f"Result: {result.ok}")
    """
    func._hook_event = "post_decision"
    return func


def on_deny(func: Callable) -> Callable:
    """Decorator to mark a function as an on-deny hook.

    Args:
        func: callback function.

    Returns:
        The original function.

    Example:
        @on_deny
        def alert_on_deny(tool_call: ToolCall, reason: str):
            send_alert(f"Tool denied: {reason}")
    """
    func._hook_event = "on_deny"
    return func


def on_approve(func: Callable) -> Callable:
    """Decorator to mark a function as an on-approve hook.

    Args:
        func: callback function.

    Returns:
        The original function.

    Example:
        @on_approve
        def log_approval(tool_call: ToolCall):
            print(f"Approved: {tool_call.tool}")
    """
    func._hook_event = "on_approve"
    return func
