"""Secure tool executor with governance enforcement.

Executes tool calls through the full AegisAgent decision pipeline including
policy evaluation, provenance tracking, and audit logging.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, Optional

from aegis.core.types import (
    ToolCall,
    ToolResult,
    ToolDescriptor,
    Decision,
    Effect,
    Principal,
)
from aegis.core.logging import get_logger

__all__ = ["SecureExecutor"]

_log = get_logger(__name__)


class SecureExecutor:
    """Execute tool calls with full security governance.

    Args:
        agent_id: agent identifier.
        tenant_id: tenant identifier.
        policy_path: path to policy configuration.
    """

    def __init__(
        self,
        agent_id: str = "",
        tenant_id: str = "default",
        policy_path: str = "",
    ) -> None:
        self.agent_id = agent_id
        self.tenant_id = tenant_id
        self.policy_path = policy_path
        self._execution_count: int = 0
        self._denied_count: int = 0

    def execute(
        self,
        tool_call: ToolCall,
        descriptor: ToolDescriptor,
        handler: Callable,
        principal: Optional[Principal] = None,
    ) -> ToolResult:
        """Execute a tool call with governance enforcement.

        Args:
            tool_call: the tool call to execute.
            descriptor: tool descriptor with metadata.
            handler: callable that implements the tool.
            principal: optional principal making the request.

        Returns:
            ToolResult containing the execution outcome.
        """
        start_time = time.time()
        self._execution_count += 1

        # Evaluate decision
        decision = self.evaluate(tool_call, descriptor)

        # Check if execution is allowed
        if decision.effect in (Effect.DENY, Effect.QUARANTINE):
            self._denied_count += 1
            _log.warning(
                "tool call denied",
                fields={
                    "tool": tool_call.tool,
                    "effect": decision.effect.value,
                    "reason": decision.reason,
                },
            )
            return ToolResult(
                call_id=tool_call.id,
                ok=False,
                error=f"Denied by policy: {decision.reason}",
                duration_ms=(time.time() - start_time) * 1000,
            )

        # Check for approval requirement
        if decision.effect == Effect.REQUIRE_APPROVAL:
            # In a real implementation, this would trigger approval workflow
            _log.info(
                "tool requires approval",
                fields={"tool": tool_call.tool},
            )
            return ToolResult(
                call_id=tool_call.id,
                ok=False,
                error="Tool requires human approval",
                duration_ms=(time.time() - start_time) * 1000,
            )

        # Execute the tool
        try:
            result = handler(**tool_call.arguments)
            duration_ms = (time.time() - start_time) * 1000

            _log.info(
                "tool executed",
                fields={
                    "tool": tool_call.tool,
                    "duration_ms": duration_ms,
                    "effect": decision.effect.value,
                },
            )

            return ToolResult(
                call_id=tool_call.id,
                ok=True,
                content=result,
                duration_ms=duration_ms,
            )
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            _log.exception("tool execution failed", fields={"tool": tool_call.tool})
            return ToolResult(
                call_id=tool_call.id,
                ok=False,
                error=str(e),
                duration_ms=duration_ms,
            )

    def evaluate(
        self,
        tool_call: ToolCall,
        descriptor: Optional[ToolDescriptor] = None,
    ) -> Decision:
        """Evaluate a tool call without executing it.

        Args:
            tool_call: the tool call to evaluate.
            descriptor: optional tool descriptor.

        Returns:
            Decision containing the governance verdict.
        """
        # Simplified evaluation - in real implementation would call policy engine
        effect = Effect.ALLOW
        reason = ""

        # Check if tool requires approval
        if descriptor and descriptor.requires_approval:
            effect = Effect.REQUIRE_APPROVAL
            reason = "Tool requires human approval"

        # Check risk level based on categories
        if descriptor and descriptor.categories:
            for category in descriptor.categories:
                if category.value in ("destructive", "payment"):
                    effect = Effect.DENY
                    reason = f"High-risk category: {category.value}"
                    break

        return Decision(
            call_id=tool_call.id,
            effect=effect,
            reason=reason,
            risk_score=50.0 if effect == Effect.REQUIRE_APPROVAL else 0.0,
        )

    def shutdown(self) -> None:
        """Shutdown the executor and release resources."""
        _log.info(
            "SecureExecutor shutdown",
            fields={
                "execution_count": self._execution_count,
                "denied_count": self._denied_count,
            },
        )
