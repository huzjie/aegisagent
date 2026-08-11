from __future__ import annotations
"""工具注册表路由。"""
import json
from typing import Any

from . import route


@route("GET", "/v1/tools")
def list_tools(handler: Any) -> None:
    """GET /v1/tools — 列出已注册工具。"""
    _respond(handler, {"tools": [], "total": 0})


@route("POST", "/v1/tools")
def register_tool(handler: Any) -> None:
    """POST /v1/tools — 注册工具。"""
    body = _read_json(handler)
    if body is None:
        return
    _respond(handler, {"status": "registered", "tool": body.get("name")}, 201)


@route("GET", "/v1/tools/{name}")
def get_tool(handler: Any, name: str = "") -> None:
    """GET /v1/tools/{name} — 查询工具详情。"""
    _respond(handler, {"name": name, "status": "not_found"}, 404)


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
