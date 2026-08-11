from __future__ import annotations
"""MCP 管理路由。"""
import json
from typing import Any

from . import route


@route("GET", "/v1/mcp/servers")
def list_servers(handler: Any) -> None:
    """GET /v1/mcp/servers — 列出 MCP 服务器。"""
    _respond(handler, {"servers": [], "total": 0})


@route("POST", "/v1/mcp/scan")
def scan_server(handler: Any) -> None:
    """POST /v1/mcp/scan — 安全扫描 MCP 服务器。"""
    body = _read_json(handler)
    if body is None:
        return
    _respond(handler, {"server": body.get("name"), "findings": [], "score": 100})


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
