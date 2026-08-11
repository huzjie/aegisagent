from __future__ import annotations
"""API 认证：Bearer token / API key。"""
import hmac
from typing import Any, Dict

from .errors import ApiError


class AuthMiddleware:
    """基于 API Key 的认证。"""

    def __init__(self, api_key: str = "", enabled: bool = True):
        self._api_key = api_key
        self._enabled = enabled

    def authenticate(self, headers: Dict[str, str]) -> None:
        """校验请求头认证信息。"""
        if not self._enabled or not self._api_key:
            return
        provided = self._extract_key(headers)
        if not provided:
            raise ApiError(401, "unauthorized", "missing api key")
        if not self._verify(provided, self._api_key):
            raise ApiError(401, "unauthorized", "invalid api key")

    @staticmethod
    def _extract_key(headers: Dict[str, str]) -> str:
        """从 Authorization 或 X-Api-Key 头提取 key。"""
        auth = headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        return headers.get("x-api-key", "").strip()

    @staticmethod
    def _verify(provided: str, expected: str) -> bool:
        """常数时间比较。"""
        return hmac.compare_digest(provided, expected)
