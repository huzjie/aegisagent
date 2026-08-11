from __future__ import annotations
"""API 统一错误类型与响应。"""
import json
from typing import Any


class ApiError(Exception):
    """API 异常。"""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message

    def to_dict(self) -> dict:
        """转为响应体。"""
        return {"error": {"code": self.code, "message": self.message}}


def error_response(handler: Any, exc: ApiError) -> None:
    """把 ApiError 写入响应。"""
    body = exc.to_dict()
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    handler.send_response(exc.status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)
    handler._status = exc.status
