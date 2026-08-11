"""AegisAgent Python SDK - User-facing interface.

Provides a simple, Pythonic API for integrating AegisAgent security governance
into agent applications.
"""

from __future__ import annotations

from .client import AegisAgent
from .executor import SecureExecutor
from .tool import SecureTool, tool, require_approval, sandbox
from .decorators import enforce, audit, trace
from .hooks import HookRegistry, pre_decision, post_decision, on_deny, on_approve
from .types import ToolHandler, DecisionCallback
from .exceptions import (
    AegisSDKError,
    ConfigurationError,
    ExecutionError,
    PolicyViolationError,
)

__all__ = [
    "AegisAgent",
    "SecureExecutor",
    "SecureTool",
    "tool",
    "require_approval",
    "sandbox",
    "enforce",
    "audit",
    "trace",
    "HookRegistry",
    "pre_decision",
    "post_decision",
    "on_deny",
    "on_approve",
    "ToolHandler",
    "DecisionCallback",
    "AegisSDKError",
    "ConfigurationError",
    "ExecutionError",
    "PolicyViolationError",
]
