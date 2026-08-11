"""Secure tool decorator and registry.

Provides decorators for marking functions as governed tools and configuring
their security requirements.
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Dict, List, Optional

from aegis.core.types import ToolDescriptor, ActionCategory

__all__ = ["SecureTool", "tool", "require_approval", "sandbox"]


class SecureTool:
    """Wrapper for tools with security metadata.

    Args:
        func: the tool function.
        name: tool name (defaults to function name).
        description: human-readable description.
        categories: list of action categories.
        requires_approval: whether tool requires human approval.
        sandbox_enabled: whether to execute in sandbox.
    """

    def __init__(
        self,
        func: Callable,
        name: str = "",
        description: str = "",
        categories: Optional[List[str]] = None,
        requires_approval: bool = False,
        sandbox_enabled: bool = False,
    ) -> None:
        self.func = func
        self.name = name or func.__name__
        self.description = description or func.__doc__ or ""
        self.categories = categories or []
        self.requires_approval = requires_approval
        self.sandbox_enabled = sandbox_enabled
        functools.update_wrapper(self, func)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Execute the tool function."""
        return self.func(*args, **kwargs)

    def to_descriptor(self) -> ToolDescriptor:
        """Convert to ToolDescriptor for policy evaluation."""
        return ToolDescriptor(
            name=self.name,
            description=self.description,
            categories=[ActionCategory(c) for c in self.categories],
            requires_approval=self.requires_approval,
        )


def tool(
    name: str = "",
    description: str = "",
    categories: Optional[List[str]] = None,
    requires_approval: bool = False,
    sandbox_enabled: bool = False,
) -> Callable:
    """Decorator to mark a function as a governed tool.

    Args:
        name: tool name (defaults to function name).
        description: human-readable description.
        categories: list of action categories.
        requires_approval: whether tool requires human approval.
        sandbox_enabled: whether to execute in sandbox.

    Returns:
        Decorator function.

    Example:
        @tool(name="send_email", categories=["communication"], requires_approval=True)
        def send_email(to: str, subject: str, body: str):
            ...
    """
    def decorator(func: Callable) -> SecureTool:
        return SecureTool(
            func=func,
            name=name,
            description=description,
            categories=categories,
            requires_approval=requires_approval,
            sandbox_enabled=sandbox_enabled,
        )
    return decorator


def require_approval(func: Callable) -> SecureTool:
    """Decorator to mark a tool as requiring human approval.

    Args:
        func: the tool function.

    Returns:
        SecureTool wrapper with requires_approval=True.

    Example:
        @require_approval
        def delete_data(record_id: str):
            ...
    """
    return SecureTool(func=func, requires_approval=True)


def sandbox(
    kind: str = "subprocess",
    timeout_s: float = 30.0,
    memory_mb: int = 512,
) -> Callable:
    """Decorator to mark a tool for sandboxed execution.

    Args:
        kind: sandbox type (subprocess, docker, firejail).
        timeout_s: execution timeout in seconds.
        memory_mb: memory limit in megabytes.

    Returns:
        Decorator function.

    Example:
        @sandbox(kind="docker", timeout_s=60)
        def execute_code(code: str):
            ...
    """
    def decorator(func: Callable) -> SecureTool:
        return SecureTool(
            func=func,
            sandbox_enabled=True,
        )
    return decorator
