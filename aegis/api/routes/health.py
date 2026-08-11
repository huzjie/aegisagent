from __future__ import annotations
"""健康检查路由。"""
import json

from aegis.version import __version__
from . import route


@route("GET", "/healthz")
def healthz(handler: "Any") -> None:
    """GET /healthz — 存活探针。"""
    _respond(handler, {"status": "ok"})


@route("GET", "/readyz")
def readyz(handler: "Any") -> None:
    """GET /readyz — 就绪探针。"""
    _respond(handler, {"status": "ready", "version": __version__})


@route("GET", "/version")
def version(handler: "Any") -> None:
    """GET /version — 版本信息。"""
    _respond(handler, {"version": __version__, "name": "AegisAgent"})


def _respond(handler: "Any", body: dict) -> None:
    """发送 JSON 响应。"""
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


from typing import Any
