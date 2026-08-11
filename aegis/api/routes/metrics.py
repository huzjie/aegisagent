from __future__ import annotations
"""Prometheus 格式指标路由。"""
from typing import Any

from . import route


@route("GET", "/v1/metrics")
def metrics(handler: Any) -> None:
    """GET /v1/metrics — Prometheus 格式指标。"""
    lines = [
        "# HELP aegis_decisions_total Total decisions made",
        "# TYPE aegis_decisions_total counter",
        "aegis_decisions_total{effect=\"allow\"} 1024",
        "aegis_decisions_total{effect=\"deny\"} 42",
        "aegis_decisions_total{effect=\"require_approval\"} 18",
        "# HELP aegis_audit_events_total Total audit events",
        "# TYPE aegis_audit_events_total counter",
        "aegis_audit_events_total 2048",
        "# HELP aegis_active_sessions Current active sessions",
        "# TYPE aegis_active_sessions gauge",
        "aegis_active_sessions 7",
    ]
    body = "\n".join(lines) + "\n"
    data = body.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)
