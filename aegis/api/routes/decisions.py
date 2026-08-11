from __future__ import annotations
"""决策评估路由。"""
import json
import time
import uuid
from typing import Any

from . import route


@route("POST", "/v1/decisions/evaluate")
def evaluate(handler: Any) -> None:
    """POST /v1/decisions/evaluate — 评估工具调用。"""
    body = _read_json(handler)
    if body is None:
        return
    tool = body.get("tool", "unknown")
    arguments = body.get("arguments", {})
    # Mock 决策：真实场景走 aegis.sdk.client.AegisAgent
    decision_id = str(uuid.uuid4())
    effect = "allow"
    if tool.startswith("dangerous.") or tool.startswith("shell.exec"):
        if "rm" in str(arguments) or "DROP" in str(arguments):
            effect = "deny"
    response = {
        "id": decision_id,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tool": tool,
        "effect": effect,
        "reason": "mock evaluation",
        "provenance": {"status": "verified"},
        "findings": [],
    }
    _respond(handler, response, 200)


@route("GET", "/v1/decisions/{id}")
def get_decision(handler: Any, id: str = "") -> None:
    """GET /v1/decisions/{id} — 查询决策详情。"""
    _respond(handler, {"id": id, "status": "not_found"}, 404)


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
