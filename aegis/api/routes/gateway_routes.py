from __future__ import annotations
"""LLM 网关路由。"""
import json
from typing import Any

from . import route


@route("POST", "/v1/gateway/chat/completions")
def chat_completions(handler: Any) -> None:
    """POST /v1/gateway/chat/completions — LLM 补全代理。"""
    body = _read_json(handler)
    if body is None:
        return
    # Mock 响应
    response = {
        "id": "chatcmpl-mock",
        "object": "chat.completion",
        "created": 1755000000,
        "model": body.get("model", "gpt-4"),
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "This is a mock response from AegisAgent gateway."},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 15, "total_tokens": 25},
    }
    _respond(handler, response)


def _read_json(handler: Any) -> dict | None:
    """读取请求 JSON。"""
    try:
        length = int(handler.headers.get("Content-Length", 0))
        raw = handler.rfile.read(length) if length > 0 else b"{}"
        return json.loads(raw.decode("utf-8"))
    except Exception:
        _respond(handler, {"error": {"code": "bad_request", "message": "invalid JSON"}}, 400)
        return None


def _respond(handler: Any, body: dict, status: int = 200) -> None:
    """发送 JSON 响应。"""
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)
