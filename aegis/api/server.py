from __future__ import annotations
"""AegisAgent HTTP API 服务器。"""
import http.server
import json
import logging
import socketserver
from pathlib import Path
from typing import Any

from aegis.core.config import Settings
from .auth import AuthMiddleware
from .errors import ApiError, error_response
from .middleware import CorsMiddleware, RequestIdMiddleware, LoggingMiddleware, RateLimiter
# 导入全部路由模块以触发 @route 注册（顺序无关，装饰器执行即注册）
from . import routes as _routes  # noqa: F401
from .routes import health as _r_health  # noqa: F401
from .routes import decisions as _r_decisions  # noqa: F401
from .routes import audit_routes as _r_audit  # noqa: F401
from .routes import policy_routes as _r_policy  # noqa: F401
from .routes import tools_routes as _r_tools  # noqa: F401
from .routes import mcp_routes as _r_mcp  # noqa: F401
from .routes import gateway_routes as _r_gateway  # noqa: F401
from .routes import approvals as _r_approvals  # noqa: F401
from .routes import metrics as _r_metrics  # noqa: F401
from .routes import match

logger = logging.getLogger("aegis.api")


class AegisRequestHandler(http.server.BaseHTTPRequestHandler):
    """统一请求处理器。"""

    server_version = "AegisAgent/0.1"

    def do_GET(self) -> None:
        """处理 GET。"""
        self._handle("GET")

    def do_POST(self) -> None:
        """处理 POST。"""
        self._handle("POST")

    def do_PUT(self) -> None:
        """处理 PUT。"""
        self._handle("PUT")

    def do_DELETE(self) -> None:
        """处理 DELETE。"""
        self._handle("DELETE")

    def do_OPTIONS(self) -> None:
        """处理 OPTIONS (CORS preflight)。"""
        self.send_response(204)
        self.server.cors.apply(self)  # type: ignore[attr-defined]
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _handle(self, method: str) -> None:
        """统一处理流程。"""
        start = __import__("time").monotonic()
        request_id = self.server.request_id_mw.generate()  # type: ignore[attr-defined]
        # 静态文件
        if self.path.startswith("/static/") or self.path == "/" or self.path == "/index.html":
            self._serve_static()
            return
        handler, params = match(method, self.path)
        if handler is None:
            self._send_json({"error": {"code": "not_found", "message": f"{method} {self.path}"}}, 404)
            return
        # 认证
        try:
            headers = {k.lower(): v for k, v in self.headers.items()}
            self.server.auth.authenticate(headers)  # type: ignore[attr-defined]
        except ApiError as exc:
            error_response(self, exc)
            return
        # 限流
        client_ip = self.client_address[0]
        if not self.server.rate_limiter.check(client_ip):  # type: ignore[attr-defined]
            error_response(self, ApiError(429, "rate_limited", "too many requests"))
            return
        try:
            handler(self, **params)
        except ApiError as exc:
            error_response(self, exc)
        except Exception as exc:
            logger.exception("unhandled error")
            error_response(self, ApiError(500, "internal_error", str(exc)))
        duration_ms = (__import__("time").monotonic() - start) * 1000
        self.server.logging_mw.log_request(method, self.path, getattr(self, "_status", 200), duration_ms, request_id)  # type: ignore[attr-defined]

    def _serve_static(self) -> None:
        """服务前端静态文件。"""
        frontend_dir = Path(__file__).parent.parent / "frontend" / "static"
        path = self.path if self.path != "/" else "/index.html"
        file_path = frontend_dir / path.lstrip("/")
        if not file_path.exists() or not file_path.is_file():
            file_path = frontend_dir / "index.html"
        try:
            data = file_path.read_bytes()
            self.send_response(200)
            ct = "text/html" if file_path.suffix == ".html" else "application/octet-stream"
            self.send_header("Content-Type", f"{ct}; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.server.cors.apply(self)  # type: ignore[attr-defined]
            self.end_headers()
            self.wfile.write(data)
        except Exception:
            self._send_json({"error": {"code": "not_found", "message": "file not found"}}, 404)

    def _send_json(self, body: dict, status: int = 200) -> None:
        """发送 JSON。"""
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Request-Id", self.server.request_id_mw.generate())  # type: ignore[attr-defined]
        self.server.cors.apply(self)  # type: ignore[attr-defined]
        self.end_headers()
        self.wfile.write(data)
        self._status = status

    def log_message(self, format: str, *args: Any) -> None:
        """覆盖默认日志。"""
        logger.debug(format, *args)


class AegisApiServer(socketserver.TCPServer):
    """AegisAgent API 服务器。"""

    allow_reuse_address = True

    def __init__(self, settings: Settings, server_address: tuple[str, int], handler_class: type = AegisRequestHandler):
        super().__init__(server_address, handler_class)
        self.settings = settings
        self.auth = AuthMiddleware(api_key=settings.api_key, enabled=bool(settings.api_key))
        self.cors = CorsMiddleware()
        self.request_id_mw = RequestIdMiddleware()
        self.logging_mw = LoggingMiddleware()
        self.rate_limiter = RateLimiter()


def create_server(settings: Settings) -> AegisApiServer:
    """创建服务器实例。"""
    host = settings.server_host
    port = settings.server_port
    return AegisApiServer(settings, (host, port))
