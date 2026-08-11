from __future__ import annotations
"""审计日志路由。"""
import json
import time
from typing import Any

from . import route


@route("GET", "/v1/audit/events")
def list_events(handler: Any) -> None:
    """GET /v1/audit/events — 列出审计事件。"""
    events = [
        {"seq": i, "ts": "2026-08-11T00:00:00Z", "action": f"tool.call.{i}", "severity": "info"}
        for i in range(1, 11)
    ]
    _respond(handler, {"events": events, "total": len(events)})


@route("GET", "/v1/audit/stats")
def stats(handler: Any) -> None:
    """GET /v1/audit/stats — 审计统计。"""
    _respond(handler, {"total_events": 1024, "by_severity": {"info": 900, "warning": 100, "critical": 24}})


@route("GET", "/v1/audit/export")
def export_events(handler: Any) -> None:
    """GET /v1/audit/export — 导出审计日志。"""
    _respond(handler, {"message": "export endpoint (mock)", "format": "jsonl"})


def _respond(handler: Any, body: dict, status: int = 200) -> None:
    """发送 JSON 响应。"""
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)
