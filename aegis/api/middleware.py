from __future__ import annotations
"""API 通用中间件：CORS / request-id / 日志 / 限流。"""
import time
import uuid
import logging
from typing import Any, Callable, Dict

logger = logging.getLogger("aegis.api.middleware")


class CorsMiddleware:
    """CORS 头部注入。"""

    def __init__(self, allow_origin: str = "*", allow_methods: str = "GET, POST, PUT, DELETE, OPTIONS", allow_headers: str = "Content-Type, Authorization, X-Api-Key"):
        self._origin = allow_origin
        self._methods = allow_methods
        self._headers = allow_headers

    def apply(self, handler: Any) -> None:
        """添加 CORS 头。"""
        handler.send_header("Access-Control-Allow-Origin", self._origin)
        handler.send_header("Access-Control-Allow-Methods", self._methods)
        handler.send_header("Access-Control-Allow-Headers", self._headers)


class RequestIdMiddleware:
    """为每个请求生成唯一 ID。"""

    HEADER = "X-Request-Id"

    def generate(self) -> str:
        """生成请求 ID。"""
        return str(uuid.uuid4())

    def apply(self, handler: Any, request_id: str) -> None:
        """注入 request-id 头。"""
        handler.send_header(self.HEADER, request_id)


class LoggingMiddleware:
    """请求日志。"""

    def log_request(self, method: str, path: str, status: int, duration_ms: float, request_id: str = "") -> None:
        """记录请求。"""
        logger.info("%s %s %d %.1fms [%s]", method, path, status, duration_ms, request_id[:8] if request_id else "-")


class RateLimiter:
    """简易令牌桶限流。"""

    def __init__(self, max_requests: int = 100, window_s: float = 60.0):
        self._max = max_requests
        self._window = window_s
        self._buckets: Dict[str, list] = {}

    def check(self, key: str) -> bool:
        """检查是否允许请求。"""
        now = time.monotonic()
        bucket = self._buckets.setdefault(key, [])
        # 清理过期
        cutoff = now - self._window
        bucket[:] = [t for t in bucket if t > cutoff]
        if len(bucket) >= self._max:
            return False
        bucket.append(now)
        return True

    def reset(self, key: str = "") -> None:
        """重置计数。"""
        if key:
            self._buckets.pop(key, None)
        else:
            self._buckets.clear()
