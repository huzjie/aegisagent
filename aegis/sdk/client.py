"""Main SDK client for AegisAgent.

Provides the primary entry point for users to interact with the AegisAgent
security governance system.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Optional

from aegis.core.types import (
    ToolCall,
    ToolResult,
    ToolDescriptor,
    Decision,
    Effect,
    AgentIdentity,
    SessionRef,
    Principal,
)
from aegis.core.logging import get_logger
from .executor import SecureExecutor
from .hooks import HookRegistry

__all__ = ["AegisAgent"]

_log = get_logger(__name__)


class AegisAgent:
    """Main SDK client for AegisAgent security governance.

    Args:
        agent_id: unique identifier for this agent instance.
        tenant_id: tenant identifier for multi-tenancy.
        policy_path: path to policy configuration file or directory.
        enable_audit: whether to enable audit logging.
        enable_provenance: whether to enable provenance tracking.
    """

    def __init__(
        self,
        agent_id: str = "",
        tenant_id: str = "default",
        policy_path: str = "",
        enable_audit: bool = True,
        enable_provenance: bool = True,
    ) -> None:
        self.agent_id = agent_id or f"agent_{int(time.time())}"
        self.tenant_id = tenant_id
        self.policy_path = policy_path
        self.enable_audit = enable_audit
        self.enable_provenance = enable_provenance

        self._executor = SecureExecutor(
            agent_id=self.agent_id,
            tenant_id=self.tenant_id,
            policy_path=policy_path,
        )
        self._hooks = HookRegistry()
        self._tools: Dict[str, ToolDescriptor] = {}
        self._tool_handlers: Dict[str, Callable] = {}

        _log.info(
            "AegisAgent initialized",
            fields={
                "agent_id": self.agent_id,
                "tenant_id": self.tenant_id,
            },
        )

    def register_tool(
        self,
        name: str,
        handler: Callable,
        description: str = "",
        parameters: Optional[List[Dict[str, Any]]] = None,
        requires_approval: bool = False,
        sandbox_enabled: bool = False,
    ) -> None:
        """Register a tool with the agent.

        Args:
            name: unique tool name.
            handler: callable that implements the tool.
            description: human-readable description.
            parameters: list of parameter schemas.
            requires_approval: whether this tool requires human approval.
            sandbox_enabled: whether to execute in sandbox.
        """
        descriptor = ToolDescriptor(
            name=name,
            description=description,
            parameters=parameters or [],
            requires_approval=requires_approval,
        )
        self._tools[name] = descriptor
        self._tool_handlers[name] = handler
        _log.info("tool registered", fields={"tool": name})

    def execute_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        session_id: str = "",
        principal: Optional[Principal] = None,
    ) -> ToolResult:
        """Execute a tool with full security governance.

        Args:
            tool_name: name of the registered tool.
            arguments: tool arguments.
            session_id: session identifier.
            principal: optional principal (user/service) making the request.

        Returns:
            ToolResult containing the execution outcome.
        """
        if tool_name not in self._tools:
            return ToolResult(
                ok=False,
                error=f"Tool not found: {tool_name}",
                duration_ms=0.0,
            )

        descriptor = self._tools[tool_name]
        handler = self._tool_handlers[tool_name]

        # Create tool call
        tool_call = ToolCall(
            tool=tool_name,
            arguments=arguments,
            agent_id=self.agent_id,
            tenant_id=self.tenant_id,
            session_id=session_id,
        )

        # Execute hooks
        self._hooks.run_pre_decision(tool_call)

        # Execute with governance
        result = self._executor.execute(
            tool_call=tool_call,
            descriptor=descriptor,
            handler=handler,
            principal=principal,
        )

        # Execute post-decision hooks
        self._hooks.run_post_decision(tool_call, result)

        return result

    def evaluate(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        session_id: str = "",
    ) -> Decision:
        """Evaluate a tool call without executing it.

        Args:
            tool_name: name of the tool.
            arguments: tool arguments.
            session_id: session identifier.

        Returns:
            Decision containing the governance verdict.
        """
        tool_call = ToolCall(
            tool=tool_name,
            arguments=arguments,
            agent_id=self.agent_id,
            tenant_id=self.tenant_id,
            session_id=session_id,
        )

        descriptor = self._tools.get(tool_name)
        return self._executor.evaluate(tool_call, descriptor)

    def on(self, event: str, callback: Callable) -> None:
        """Register a hook callback.

        Args:
            event: event name (pre_decision, post_decision, on_deny, on_approve).
            callback: callable to invoke.
        """
        self._hooks.register(event, callback)

    def shutdown(self) -> None:
        """Shutdown the agent and release resources."""
        self._executor.shutdown()
        _log.info("AegisAgent shutdown complete")
