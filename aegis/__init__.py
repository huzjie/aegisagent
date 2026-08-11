"""AegisAgent - runtime security gateway and privilege governance for AI agents.

Quick start::

    from aegis import Aegis

    aegis = Aegis.from_config("aegis.yaml")

    decision = aegis.evaluate_tool_call(
        session_id="ses_demo",
        tool="shell.exec",
        arguments={"command": "rm -rf /var/data"},
        completion_id="cmp_123",
        attestation=token,
    )

    if not decision.allowed:
        raise RuntimeError(decision.explain())

The package exposes the domain contract eagerly and everything else lazily so
importing ``aegis`` stays cheap even in short-lived CLI processes.
"""

from __future__ import annotations

from typing import Any

from .version import __version__, version_banner  # noqa: F401
from .core.types import (  # noqa: F401
    ActionCategory,
    AgentIdentity,
    Decision,
    Effect,
    Finding,
    ProvenanceStatus,
    RiskLevel,
    SessionRef,
    Severity,
    ToolCall,
    ToolDescriptor,
)
from .core.errors import AegisError, BlockedByPolicy, ForgedToolCallError  # noqa: F401

_LAZY = {
    "Aegis": ("aegis.runtime", "Aegis"),
    "Guard": ("aegis.runtime", "Guard"),
    "PolicyEngine": ("aegis.policy.engine", "PolicyEngine"),
    "ProvenanceVerifier": ("aegis.provenance.verifier", "ProvenanceVerifier"),
    "ProvenanceBinder": ("aegis.provenance.binder", "ProvenanceBinder"),
    "DetectorRegistry": ("aegis.detect.registry", "DetectorRegistry"),
    "SandboxRunner": ("aegis.sandbox.runner", "SandboxRunner"),
    "ApprovalQueue": ("aegis.approval.queue", "ApprovalQueue"),
    "AuditLedger": ("aegis.audit.ledger", "AuditLedger"),
    "RedTeamRunner": ("aegis.redteam.runner", "RedTeamRunner"),
    "McpProxy": ("aegis.mcp.proxy", "McpProxy"),
    "guard_tool": ("aegis.sdk.decorators", "guard_tool"),
}

__all__ = ["__version__", "version_banner", *sorted(_LAZY)] + [
    "ActionCategory",
    "AgentIdentity",
    "Decision",
    "Effect",
    "Finding",
    "ProvenanceStatus",
    "RiskLevel",
    "SessionRef",
    "Severity",
    "ToolCall",
    "ToolDescriptor",
    "AegisError",
    "BlockedByPolicy",
    "ForgedToolCallError",
]


def __getattr__(name: str) -> Any:  # PEP 562 lazy imports
    target = _LAZY.get(name)
    if target is None:
        raise AttributeError(f"module 'aegis' has no attribute '{name}'")
    module_name, attribute = target
    import importlib

    module = importlib.import_module(module_name)
    value = getattr(module, attribute)
    globals()[name] = value
    return value


def __dir__() -> list:
    return sorted(__all__)
