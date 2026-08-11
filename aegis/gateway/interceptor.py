"""Gateway request/response interceptor.

The :class:`GatewayInterceptor` is the core of the gateway's security posture.
It inspects outgoing LLM requests for CoreBreak attacks (injected tool_use
blocks) and records incoming completions to issue cryptographic attestations.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from aegis.core.types import ModelCompletion, new_id, utc_now
from aegis.core.crypto import Signer, NullSigner, canonical_json, sha256_hex
from aegis.core.logging import get_logger

__all__ = ["GatewayInterceptor", "InterceptorResult"]

_log = get_logger(__name__)

# Pattern to detect injected tool_use blocks in messages
_TOOL_USE_PATTERN = re.compile(r'"tool_use"|"tool_result"|tool_calls', re.IGNORECASE)


class InterceptorResult:
    """Outcome of intercepting a request or response."""

    def __init__(
        self,
        blocked: bool = False,
        reason: str = "",
        completion: Optional[ModelCompletion] = None,
        attestation: str = "",
        modified_response: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.blocked = blocked
        self.reason = reason
        self.completion = completion
        self.attestation = attestation
        self.modified_response = modified_response

    @property
    def allowed(self) -> bool:
        return not self.blocked


class GatewayInterceptor:
    """Inspect LLM traffic for CoreBreak attacks and issue attestations.

    The interceptor is called by the gateway server for every request/response
    pair.  It performs two security functions:

    1. **Request inspection**: detect and block requests that contain injected
       ``tool_use`` or ``tool_result`` blocks in the messages array — a
       CoreBreak attack vector (CVE-2026-18830).
    2. **Response recording**: extract model completions from responses, bind
       them to the session ledger, and issue a signed attestation that can be
       attached to subsequent tool calls.
    """

    def __init__(
        self,
        signer: Optional[Signer] = None,
        ledger: Any = None,
        binder: Any = None,
        settings: Any = None,
    ) -> None:
        self._signer = signer or NullSigner()
        self._ledger = ledger
        self._binder = binder
        self._settings = settings
        self._completion_count: int = 0
        self._blocked_count: int = 0

    def intercept_request(self, messages: List[Dict[str, Any]]) -> InterceptorResult:
        """Inspect outgoing request messages for CoreBreak injection.

        Returns:
            An :class:`InterceptorResult` indicating whether the request was
            blocked and why.
        """
        for message in messages:
            role = message.get("role", "")
            content = message.get("content")
            if content is None:
                continue
            # Check if content contains tool_use or tool_result blocks
            content_str = json.dumps(content, ensure_ascii=False) if not isinstance(content, str) else content
            if _TOOL_USE_PATTERN.search(content_str):
                self._blocked_count += 1
                _log.warning(
                    "corebreak injection detected",
                    fields={"role": role, "pattern": "tool_use/tool_result"},
                )
                return InterceptorResult(
                    blocked=True,
                    reason=f"CoreBreak attack: tool_use block detected in {role} message",
                )
        return InterceptorResult(blocked=False)

    def intercept_response(
        self,
        response: Dict[str, Any],
        session_id: str = "",
        turn: int = 0,
        model: str = "",
        provider: str = "",
    ) -> InterceptorResult:
        """Record a model completion and issue an attestation.

        Args:
            response: the LLM response dictionary (OpenAI-compatible format).
            session_id: the session identifier for provenance binding.
            turn: the conversation turn number.
            model: the model name (e.g. ``gpt-4o``).
            provider: the provider name (e.g. ``openai``).

        Returns:
            An :class:`InterceptorResult` containing the completion and
            attestation.
        """
        choices = response.get("choices", [])
        if not choices:
            return InterceptorResult(blocked=False)

        choice = choices[0]
        message = choice.get("message", {})
        content = message.get("content", "")
        tool_calls = message.get("tool_calls", [])
        finish_reason = choice.get("finish_reason", "stop")
        usage = response.get("usage", {})

        completion = ModelCompletion(
            id=new_id("cmp"),
            session_id=session_id,
            turn=turn,
            model=model,
            provider=provider,
            content=content or "",
            tool_calls=tool_calls or [],
            finish_reason=finish_reason,
            created_at=utc_now(),
            prompt_hash=sha256_hex(response.get("prompt", "")),
            response_hash=sha256_hex(json.dumps(response, sort_keys=True)),
            usage=usage,
        )

        # Record completion to session ledger if available
        if self._ledger is not None:
            try:
                self._ledger.record_completion(completion)
            except Exception:
                _log.exception("failed to record completion to ledger")

        # Issue attestation if binder is available
        attestation = ""
        if self._binder is not None and completion.tool_calls:
            try:
                attestation = self._binder.issue(
                    completion_id=completion.id,
                    tool=completion.tool_calls[0].get("function", {}).get("name", ""),
                    arguments=completion.tool_calls[0].get("function", {}).get("arguments", {}),
                )
            except Exception:
                _log.exception("failed to issue attestation")

        # Inject attestation into response if present
        modified_response = response
        if attestation:
            modified_response = dict(response)
            modified_response["aegis_attestation"] = attestation

        self._completion_count += 1
        return InterceptorResult(
            blocked=False,
            completion=completion,
            attestation=attestation,
            modified_response=modified_response,
        )

    @property
    def completion_count(self) -> int:
        """Number of completions recorded."""
        return self._completion_count

    @property
    def blocked_count(self) -> int:
        """Number of requests blocked due to CoreBreak detection."""
        return self._blocked_count
