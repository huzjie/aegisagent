"""Shared fixtures and builders for the AegisAgent test suite.

These helpers construct the domain objects defined in :mod:`aegis.core.types`
without pulling in the heavier runtime wiring (sandbox, approval, etc.).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from aegis.core.types import (
    ActionCategory,
    AgentIdentity,
    EvaluationContext,
    ModelCompletion,
    ProvenanceRecord,
    ProvenanceStatus,
    RiskLevel,
    SessionRef,
    ToolCall,
)

TEST_SIGNING_KEY = "test-signing-key-not-for-production"


def make_completion(
    *,
    cid: str = "cmp1",
    sid: str = "ses1",
    agent_id: str = "agt1",
    tool: str = "shell.exec",
    args: Optional[Dict[str, Any]] = None,
    turn: int = 1,
) -> ModelCompletion:
    """Build a recorded model completion whose tool call uses ``{name, arguments}``.

    ``agent_id`` is accepted for convenience and stored on the parent session
    reference that the binder fixtures build; :class:`ModelCompletion` itself
    only carries ``session_id``.
    """
    return ModelCompletion(
        id=cid,
        session_id=sid,
        turn=turn,
        model="test-model",
        provider="test-provider",
        tool_calls=[{"name": tool, "arguments": args if args is not None else {"cmd": "echo hi"}}],
    )


def make_call(
    *,
    tool: str = "shell.exec",
    args: Optional[Dict[str, Any]] = None,
    sid: str = "ses1",
    agent_id: str = "agt1",
    tenant_id: str = "default",
    completion_id: Optional[str] = None,
    attestation: Optional[str] = None,
    source: str = "model",
    caller_ip: str = "",
) -> ToolCall:
    """Build a :class:`ToolCall`, splitting ``server::tool`` names automatically."""
    if "::" in tool:
        server, _, name = tool.partition("::")
    else:
        server, name = "local", tool
    return ToolCall(
        id="tc1",
        session_id=sid,
        agent_id=agent_id,
        tenant_id=tenant_id,
        tool=name,
        server=server,
        arguments=args if args is not None else {"cmd": "echo hi"},
        completion_id=completion_id,
        attestation=attestation,
        source=source,
        caller_ip=caller_ip,
    )


def make_ctx(
    call: ToolCall,
    *,
    risk: RiskLevel = RiskLevel.LOW,
    risk_score: float = 0.0,
    categories: Optional[List[ActionCategory]] = None,
    provenance: Optional[ProvenanceRecord] = None,
    findings: Optional[List[Any]] = None,
    environment: str = "production",
    now: Optional[float] = None,
) -> EvaluationContext:
    """Wrap a call in an evaluation context with sensible defaults."""
    return EvaluationContext(
        call=call,
        agent=AgentIdentity(id=call.agent_id, tenant_id=call.tenant_id),
        session=SessionRef(id=call.session_id, agent_id=call.agent_id),
        risk=risk,
        risk_score=risk_score,
        categories=categories or [],
        provenance=provenance,
        findings=findings or [],
        environment=environment,
        now=now if now is not None else 0.0,
    )


@pytest.fixture
def signing_key() -> str:
    return TEST_SIGNING_KEY
