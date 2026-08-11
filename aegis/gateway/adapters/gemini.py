"""Google Gemini API adapter.

Parses responses from the Gemini API.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from aegis.core.types import ModelCompletion, new_id, utc_now
from aegis.core.crypto import sha256_hex
from .base import ProviderAdapter

__all__ = ["GeminiAdapter"]


class GeminiAdapter(ProviderAdapter):
    """Adapter for Google Gemini API responses."""

    name = "gemini"

    def parse_response(
        self,
        response: Dict[str, Any],
        session_id: str = "",
        turn: int = 0,
        model: str = "",
    ) -> Tuple[Optional[ModelCompletion], Dict[str, Any]]:
        candidates = response.get("candidates", [])
        if not candidates:
            return None, {}

        candidate = candidates[0]
        content = candidate.get("content", {})
        parts = content.get("parts", [])

        text_parts = []
        tool_calls = []
        for part in parts:
            if "text" in part:
                text_parts.append(part["text"])
            elif "functionCall" in part:
                fc = part["functionCall"]
                tool_calls.append({
                    "id": new_id("tc"),
                    "type": "function",
                    "function": {
                        "name": fc.get("name", ""),
                        "arguments": json.dumps(fc.get("args", {})),
                    },
                })

        text = "\n".join(text_parts)
        finish_reason = candidate.get("finishReason", "STOP")
        usage_metadata = response.get("usageMetadata", {})

        completion = ModelCompletion(
            id=new_id("cmp"),
            session_id=session_id,
            turn=turn,
            model=model,
            provider="gemini",
            content=text,
            tool_calls=tool_calls,
            finish_reason=finish_reason,
            created_at=utc_now(),
            response_hash=sha256_hex(json.dumps(response, sort_keys=True)),
            usage=usage_metadata,
        )
        return completion, {"usage": usage_metadata, "finish_reason": finish_reason}

    def extract_tool_calls(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        candidates = response.get("candidates", [])
        if not candidates:
            return []
        parts = candidates[0].get("content", {}).get("parts", [])
        return [
            {
                "id": new_id("tc"),
                "type": "function",
                "function": {
                    "name": part["functionCall"].get("name", ""),
                    "arguments": json.dumps(part["functionCall"].get("args", {})),
                },
            }
            for part in parts
            if "functionCall" in part
        ]

    def extract_usage(self, response: Dict[str, Any]) -> Dict[str, int]:
        usage = response.get("usageMetadata", {})
        return {
            "prompt_tokens": int(usage.get("promptTokenCount", 0)),
            "completion_tokens": int(usage.get("candidatesTokenCount", 0)),
            "total_tokens": int(usage.get("totalTokenCount", 0)),
        }
