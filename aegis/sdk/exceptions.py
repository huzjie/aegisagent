"""SDK-specific exceptions.

Provides user-friendly exception classes for SDK users.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

__all__ = [
    "AegisSDKError",
    "ConfigurationError",
    "ExecutionError",
    "PolicyViolationError",
]


class AegisSDKError(Exception):
    """Base exception for all SDK errors."""

    def __init__(self, message: str = "", details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ConfigurationError(AegisSDKError):
    """Raised when SDK configuration is invalid."""

    pass


class ExecutionError(AegisSDKError):
    """Raised when tool execution fails."""

    pass


class PolicyViolationError(AegisSDKError):
    """Raised when a tool call violates policy."""

    def __init__(
        self,
        message: str = "",
        policy_id: str = "",
        rule_id: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, details)
        self.policy_id = policy_id
        self.rule_id = rule_id
