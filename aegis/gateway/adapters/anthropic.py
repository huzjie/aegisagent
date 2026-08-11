"""Anthropic Messages API adapter.

Parses responses from the Anthropic Messages API.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from aegis.core.types import ModelCompletion, new_id, utc_now
from aegis.core.crypto import sha256_hex
from .base import ProviderAdapter

__all__ = ["AnthropicAdapter"]


class AnthropicAdapter(ProviderAdapter):
    """Adapter for Anthropic Messages API responses."""

    name = "anthropic"

    def parse_response(
        self,
        response: Dict[str, Any],
        session_id: str = "",
        turn: int = 0,
        model: str = "",
    ) -> Tuple[Optional[ModelCompletion], Dict[str, Any]]:
        content_blocks = response.get("content", [])
        if not content_blocks:
            return None, {}

        text_parts = []
        tool_calls = []
        for block in content_blocks:
            if block.get("type") == "text":
                text_parts.append(block.get("text", ""))
            elif block.get("type") == "tool_use":
                tool_calls.append({
                    "id": block.get("id", ""),
                    "type": "function",
                    "function": {
                        "name": block.get("name", ""),
                        "arguments": json.dumps(block.get("input", {})),
                    },
                })

        content = "\n".join(text_parts)
        stop_reason = response.get("stop_reason", "end_turn")
        usage = response.get("usage", {})

        completion = ModelCompletion(
            id=new_id("cmp"),
            session_id=session_id,
            turn=turn,
            model=model or response.get("model", ""),
            provider="anthropic",
            content=content,
            tool_calls=tool_calls,
            finish_reason=stop_reason,
            created_at=utc_now(),
            response_hash=sha256_hex(json.dumps(response, sort_keys=True)),
            usage=usage,
        )
        return completion, {"usage": usage, "stop_reason": stop_reason}

    def extract_tool_calls(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        content_blocks = response.get("content", [])
        return [
            {
                "id": block.get("id", ""),
                "type": "function",
                "function": {
                    "name": block.get("name", ""),
                    "arguments": json.dumps(block.get("input", {})),
                },
            }
            for block in content_blocks
            if block.get("type") == "tool_use"
        ]

    def extract_usage(self, response: Dict[str, Any]) -> Dict[str, int]:
        usage = response.get("usage", {})
        return {
            "input_tokens": int(usage.get("input_tokens", 0)),
            "output_tokens": int(usage.get("output_tokens", 0)),
        }
