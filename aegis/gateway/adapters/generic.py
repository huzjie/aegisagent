"""Generic fallback adapter.

Parses responses in OpenAI-compatible format.  Used when no specific adapter
matches the provider.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from aegis.core.types import ModelCompletion, new_id, utc_now
from aegis.core.crypto import sha256_hex
from .base import ProviderAdapter

__all__ = ["GenericAdapter"]


class GenericAdapter(ProviderAdapter):
    """Fallback adapter for OpenAI-compatible responses."""

    name = "generic"

    def parse_response(
        self,
        response: Dict[str, Any],
        session_id: str = "",
        turn: int = 0,
        model: str = "",
    ) -> Tuple[Optional[ModelCompletion], Dict[str, Any]]:
        # Try OpenAI format first
        choices = response.get("choices", [])
        if choices:
            choice = choices[0]
            message = choice.get("message", {})
            content = message.get("content", "") or ""
            tool_calls = message.get("tool_calls", []) or []
            finish_reason = choice.get("finish_reason", "stop")
            usage = response.get("usage", {})

            completion = ModelCompletion(
                id=new_id("cmp"),
                session_id=session_id,
                turn=turn,
                model=model or response.get("model", "unknown"),
                provider=response.get("provider", "generic"),
                content=content,
                tool_calls=tool_calls,
                finish_reason=finish_reason,
                created_at=utc_now(),
                response_hash=sha256_hex(json.dumps(response, sort_keys=True)),
                usage=usage,
            )
            return completion, {"usage": usage, "finish_reason": finish_reason}

        # Fallback: extract content from top-level keys
        content = response.get("content", "") or response.get("text", "") or ""
        if not content:
            return None, {}

        completion = ModelCompletion(
            id=new_id("cmp"),
            session_id=session_id,
            turn=turn,
            model=model or response.get("model", "unknown"),
            provider=response.get("provider", "generic"),
            content=content,
            tool_calls=[],
            finish_reason="stop",
            created_at=utc_now(),
            response_hash=sha256_hex(json.dumps(response, sort_keys=True)),
            usage={},
        )
        return completion, {}

    def extract_tool_calls(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        choices = response.get("choices", [])
        if not choices:
            return []
        message = choices[0].get("message", {})
        return message.get("tool_calls", []) or []

    def extract_usage(self, response: Dict[str, Any]) -> Dict[str, int]:
        usage = response.get("usage", {})
        return {
            "prompt_tokens": int(usage.get("prompt_tokens", 0)),
            "completion_tokens": int(usage.get("completion_tokens", 0)),
            "total_tokens": int(usage.get("total_tokens", 0)),
        }
