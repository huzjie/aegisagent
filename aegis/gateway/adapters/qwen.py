"""Qwen (Tongyi Qianwen) API adapter.

Parses responses from the Qwen DashScope API.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from aegis.core.types import ModelCompletion, new_id, utc_now
from aegis.core.crypto import sha256_hex
from .base import ProviderAdapter

__all__ = ["QwenAdapter"]


class QwenAdapter(ProviderAdapter):
    """Adapter for Qwen DashScope API responses."""

    name = "qwen"

    def parse_response(
        self,
        response: Dict[str, Any],
        session_id: str = "",
        turn: int = 0,
        model: str = "",
    ) -> Tuple[Optional[ModelCompletion], Dict[str, Any]]:
        output = response.get("output", {})
        if not output:
            return None, {}

        choices = output.get("choices", [])
        if not choices:
            return None, {}

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
            model=model or response.get("model", ""),
            provider="qwen",
            content=content,
            tool_calls=tool_calls,
            finish_reason=finish_reason,
            created_at=utc_now(),
            response_hash=sha256_hex(json.dumps(response, sort_keys=True)),
            usage=usage,
        )
        return completion, {"usage": usage, "finish_reason": finish_reason}

    def extract_tool_calls(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        output = response.get("output", {})
        if not output:
            return []
        choices = output.get("choices", [])
        if not choices:
            return []
        message = choices[0].get("message", {})
        return message.get("tool_calls", []) or []

    def extract_usage(self, response: Dict[str, Any]) -> Dict[str, int]:
        usage = response.get("usage", {})
        return {
            "input_tokens": int(usage.get("input_tokens", 0)),
            "output_tokens": int(usage.get("output_tokens", 0)),
            "total_tokens": int(usage.get("total_tokens", 0)),
        }
