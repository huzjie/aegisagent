from __future__ import annotations
"""策略管理路由。"""
import json
from typing import Any

from . import route


@route("GET", "/v1/policy")
def get_policy(handler: Any) -> None:
    """GET /v1/policy — 获取当前策略。"""
    _respond(handler, {"policies": [], "default_effect": "monitor", "rules_count": 0})


@route("POST", "/v1/policy")
def update_policy(handler: Any) -> None:
    """POST /v1/policy — 更新策略。"""
    body = _read_json(handler)
    if body is None:
        return
    _respond(handler, {"status": "updated", "rules_count": len(body.get("rules", []))}, 201)


@route("POST", "/v1/policy/simulate")
def simulate_policy(handler: Any) -> None:
    """POST /v1/policy/simulate — 模拟策略决策。"""
    body = _read_json(handler)
    if body is None:
        return
    _respond(handler, {"tool": body.get("tool"), "effect": "allow", "matched_rules": [], "reason": "simulation"})


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
