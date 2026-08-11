"""Ollama API adapter.

Parses responses from the Ollama local model server.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from aegis.core.types import ModelCompletion, new_id, utc_now
from aegis.core.crypto import sha256_hex
from .base import ProviderAdapter

__all__ = ["OllamaAdapter"]


class OllamaAdapter(ProviderAdapter):
    """Adapter for Ollama API responses."""

    name = "ollama"

    def parse_response(
        self,
        response: Dict[str, Any],
        session_id: str = "",
        turn: int = 0,
        model: str = "",
    ) -> Tuple[Optional[ModelCompletion], Dict[str, Any]]:
        content = response.get("message", {}).get("content", "") or ""
        if not content and not response.get("message"):
            return None, {}

        tool_calls = []
        if "tool_calls" in response.get("message", {}):
            for tc in response["message"]["tool_calls"]:
                function = tc.get("function", {})
                tool_calls.append({
                    "id": new_id("tc"),
                    "type": "function",
                    "function": {
                        "name": function.get("name", ""),
                        "arguments": json.dumps(function.get("arguments", {})),
                    },
                })

        done = response.get("done", True)
        finish_reason = "stop" if done else "incomplete"
        eval_count = response.get("eval_count", 0)
        prompt_eval_count = response.get("prompt_eval_count", 0)

        completion = ModelCompletion(
            id=new_id("cmp"),
            session_id=session_id,
            turn=turn,
            model=model or response.get("model", ""),
            provider="ollama",
            content=content,
            tool_calls=tool_calls,
            finish_reason=finish_reason,
            created_at=utc_now(),
            response_hash=sha256_hex(json.dumps(response, sort_keys=True)),
            usage={
                "prompt_tokens": int(prompt_eval_count),
                "completion_tokens": int(eval_count),
            },
        )
        return completion, {
            "done": done,
            "total_duration": response.get("total_duration", 0),
            "eval_count": eval_count,
        }

    def extract_tool_calls(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        message = response.get("message", {})
        if "tool_calls" not in message:
            return []
        return [
            {
                "id": new_id("tc"),
                "type": "function",
                "function": {
                    "name": tc.get("function", {}).get("name", ""),
                    "arguments": json.dumps(tc.get("function", {}).get("arguments", {})),
                },
            }
            for tc in message["tool_calls"]
        ]

    def extract_usage(self, response: Dict[str, Any]) -> Dict[str, int]:
        return {
            "prompt_tokens": int(response.get("prompt_eval_count", 0)),
            "completion_tokens": int(response.get("eval_count", 0)),
        }
