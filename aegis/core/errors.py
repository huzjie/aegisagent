"""Exception hierarchy for AegisAgent.

All errors carry a stable ``code`` so the API layer can map them onto HTTP
status codes and clients can branch on machine-readable identifiers rather than
message strings.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

__all__ = [
    "AegisError",
    "ConfigError",
    "ValidationError",
    "PolicyError",
    "PolicyCompileError",
    "ProvenanceError",
    "ForgedToolCallError",
    "ReplayAttackError",
    "DetectionError",
    "SandboxError",
    "SandboxTimeout",
    "SandboxEscapeDetected",
    "EgressBlocked",
    "ApprovalError",
    "ApprovalRejected",
    "ApprovalTimeout",
    "StepUpRequired",
    "AuthenticationError",
    "AuthorizationError",
    "RateLimited",
    "StorageError",
    "NotFoundError",
    "ConflictError",
    "IntegrationError",
    "UpstreamError",
    "BlockedByPolicy",
]


class AegisError(Exception):
    """Base class for every error raised by the platform."""

    code = "aegis_error"
    http_status = 500

    def __init__(
        self,
        message: str = "",
        *,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(message or self.__class__.__doc__ or self.code)
        self.message = message or (self.__class__.__doc__ or self.code).strip()
        self.details: Dict[str, Any] = details or {}
        self.cause = cause

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error": self.code,
            "message": self.message,
            "details": self.details,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"<{self.__class__.__name__} code={self.code} message={self.message!r}>"


# --------------------------------------------------------------------------- #
# Configuration & validation
# --------------------------------------------------------------------------- #
class ConfigError(AegisError):
    """Invalid or missing configuration."""

    code = "config_error"
    http_status = 500


class ValidationError(AegisError):
    """Input failed schema or semantic validation."""

    code = "validation_error"
    http_status = 422


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #
class PolicyError(AegisError):
    """Generic policy subsystem failure."""

    code = "policy_error"
    http_status = 500


class PolicyCompileError(PolicyError):
    """A policy bundle could not be compiled."""

    code = "policy_compile_error"
    http_status = 422


class BlockedByPolicy(AegisError):
    """The requested action was denied by policy."""

    code = "blocked_by_policy"
    http_status = 403

    def __init__(self, message: str = "", *, decision: Any = None, **kw: Any) -> None:
        super().__init__(message, **kw)
        self.decision = decision


# --------------------------------------------------------------------------- #
# Provenance (CoreBreak defence)
# --------------------------------------------------------------------------- #
class ProvenanceError(AegisError):
    """Tool-call provenance could not be established."""

    code = "provenance_error"
    http_status = 403


class ForgedToolCallError(ProvenanceError):
    """The tool call was not authorised by any recorded model completion."""

    code = "forged_tool_call"
    http_status = 403


class ReplayAttackError(ProvenanceError):
    """A previously used attestation nonce was presented again."""

    code = "replay_attack"
    http_status = 403


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #
class DetectionError(AegisError):
    """A detector failed while analysing content."""

    code = "detection_error"
    http_status = 500


# --------------------------------------------------------------------------- #
# Sandbox
# --------------------------------------------------------------------------- #
class SandboxError(AegisError):
    """Sandbox driver failure."""

    code = "sandbox_error"
    http_status = 500


class SandboxTimeout(SandboxError):
    """Sandboxed execution exceeded its wall-clock budget."""

    code = "sandbox_timeout"
    http_status = 504


class SandboxEscapeDetected(SandboxError):
    """Evidence that workload crossed the isolation boundary."""

    code = "sandbox_escape"
    http_status = 403


class EgressBlocked(SandboxError):
    """Outbound network destination is not on the allowlist."""

    code = "egress_blocked"
    http_status = 403


# --------------------------------------------------------------------------- #
# Approval
# --------------------------------------------------------------------------- #
class ApprovalError(AegisError):
    """Approval workflow failure."""

    code = "approval_error"
    http_status = 500


class ApprovalRejected(ApprovalError):
    """A human reviewer rejected the action."""

    code = "approval_rejected"
    http_status = 403


class ApprovalTimeout(ApprovalError):
    """No reviewer responded before the deadline."""

    code = "approval_timeout"
    http_status = 408


class StepUpRequired(ApprovalError):
    """Reviewer must re-authenticate with a stronger factor."""

    code = "step_up_required"
    http_status = 401


# --------------------------------------------------------------------------- #
# AuthN / AuthZ / limits
# --------------------------------------------------------------------------- #
class AuthenticationError(AegisError):
    """Missing or invalid credentials."""

    code = "authentication_error"
    http_status = 401


class AuthorizationError(AegisError):
    """Authenticated but not permitted."""

    code = "authorization_error"
    http_status = 403


class RateLimited(AegisError):
    """Too many requests."""

    code = "rate_limited"
    http_status = 429

    def __init__(self, message: str = "", *, retry_after: float = 1.0, **kw: Any) -> None:
        super().__init__(message, **kw)
        self.retry_after = retry_after
        self.details.setdefault("retry_after", retry_after)


# --------------------------------------------------------------------------- #
# Storage & integrations
# --------------------------------------------------------------------------- #
class StorageError(AegisError):
    """Persistence layer failure."""

    code = "storage_error"
    http_status = 500


class NotFoundError(AegisError):
    """Requested resource does not exist."""

    code = "not_found"
    http_status = 404


class ConflictError(AegisError):
    """Resource already exists or version conflict."""

    code = "conflict"
    http_status = 409


class IntegrationError(AegisError):
    """A third-party integration failed."""

    code = "integration_error"
    http_status = 502


class UpstreamError(AegisError):
    """Upstream model provider or MCP server failure."""

    code = "upstream_error"
    http_status = 502
