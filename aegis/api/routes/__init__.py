from __future__ import annotations
"""API 路由注册。"""
from typing import Any, Callable, Dict, List, Tuple

RouteHandler = Callable[..., None]
_ROUTE_TABLE: Dict[str, Dict[str, RouteHandler]] = {}


def route(method: str, pattern: str) -> Callable[[RouteHandler], RouteHandler]:
    """注册路由装饰器。"""
    def decorator(fn: RouteHandler) -> RouteHandler:
        _ROUTE_TABLE.setdefault(pattern, {})[method.upper()] = fn
        return fn
    return decorator


def match(method: str, path: str) -> Tuple[RouteHandler | None, Dict[str, str]]:
    """匹配路由，返回 (handler, path_params)。"""
    # 精确匹配
    if path in _ROUTE_TABLE and method.upper() in _ROUTE_TABLE[path]:
        return _ROUTE_TABLE[path][method.upper()], {}
    # 带参数匹配 /v1/decisions/{id}
    for pattern, methods in _ROUTE_TABLE.items():
        if method.upper() not in methods:
            continue
        params = _match_pattern(pattern, path)
        if params is not None:
            return methods[method.upper()], params
    return None, {}


def _match_pattern(pattern: str, path: str) -> Dict[str, str] | None:
    """简单路径参数匹配：{name} 捕获一段路径。"""
    pat_parts = pattern.strip("/").split("/")
    path_parts = path.strip("/").split("/")
    if len(pat_parts) != len(path_parts):
        return None
    params: Dict[str, str] = {}
    for pp, pathp in zip(pat_parts, path_parts):
        if pp.startswith("{") and pp.endswith("}"):
            params[pp[1:-1]] = pathp
        elif pp != pathp:
            return None
    return params


def all_routes() -> List[Tuple[str, str]]:
    """返回全部 (method, pattern)。"""
    result: List[Tuple[str, str]] = []
    for pattern, methods in _ROUTE_TABLE.items():
        for method in methods:
            result.append((method, pattern))
    return result
