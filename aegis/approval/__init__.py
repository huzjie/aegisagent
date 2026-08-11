"""Human-in-the-loop approval layer for AegisAgent.

This package implements a *binding*, *quorum* and *single-use* approval system
built to defeat the approval-bypass pattern that hit three major agent
platforms in 2026-08: an attacker would get a benign action approved and then
redeem the approval for a malicious one, or simply replay a stale approval.

Public surface
--------------

:class:`ApprovalWorkflow`
    The coordinator.  Create tickets, cast votes, wait for verdicts, redeem
    receipts and invoke break-glass.
:class:`ApprovalTicket` / :class:`ApprovalReceipt`
    The server-side record and the signed, single-use redemption artefact.
:class:`ApprovalPolicy` / :class:`QuorumRule`
    Tenant configuration of risk thresholds, quorum and channels.
:class:`ApprovalQueue`
    Thread-safe pending registry with dedup, flood control and TTL reaping.
:class:`EscalationEngine` / :class:`BreakGlassManager` / :class:`StepUpRegistry`
    SLA escalation, audited emergency bypass, and second-factor verification.
"""

from __future__ import annotations

from .breakglass import BreakGlassGrant, BreakGlassManager, BreakGlassStats
from .escalation import EscalationEngine, EscalationEvent, EscalationPolicy, EscalationStats
from .models import (
    ApprovalChannel,
    ApprovalOutcome,
    ApprovalPolicy,
    ApprovalReceipt,
    ApprovalTicket,
    ApprovalVote,
    QuorumRule,
    VoteKind,
    compute_binding,
    preview_arguments,
)
from .queue import ApprovalQueue, QueueLimits, QueueStats
from .stepup import (
    ChallengeVerifier,
    HardwareKeyVerifier,
    StepUpChallenge,
    StepUpRegistry,
    StepUpResult,
    StepUpVerifier,
    TotpVerifier,
)
from .workflow import ApprovalConfig, ApprovalWorkflow, WorkflowHooks

__all__ = [
    # workflow
    "ApprovalWorkflow",
    "ApprovalConfig",
    "WorkflowHooks",
    # models
    "ApprovalTicket",
    "ApprovalReceipt",
    "ApprovalVote",
    "ApprovalOutcome",
    "ApprovalPolicy",
    "QuorumRule",
    "VoteKind",
    "ApprovalChannel",
    "compute_binding",
    "preview_arguments",
    # queue
    "ApprovalQueue",
    "QueueLimits",
    "QueueStats",
    # escalation
    "EscalationEngine",
    "EscalationPolicy",
    "EscalationEvent",
    "EscalationStats",
    # step-up
    "StepUpRegistry",
    "StepUpVerifier",
    "TotpVerifier",
    "ChallengeVerifier",
    "HardwareKeyVerifier",
    "StepUpChallenge",
    "StepUpResult",
    # break-glass
    "BreakGlassManager",
    "BreakGlassGrant",
    "BreakGlassStats",
]
