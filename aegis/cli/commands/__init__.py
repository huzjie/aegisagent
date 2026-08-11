from __future__ import annotations
"""CLI 子命令注册表。"""
from typing import Callable, Dict
import argparse


CommandFunc = Callable[[argparse.Namespace], int]
_REGISTRY: Dict[str, CommandFunc] = {}


def register(name: str) -> Callable[[CommandFunc], CommandFunc]:
    """注册子命令装饰器。"""
    def decorator(fn: CommandFunc) -> CommandFunc:
        _REGISTRY[name] = fn
        return fn
    return decorator


def get(name: str) -> CommandFunc | None:
    """获取子命令处理函数。"""
    return _REGISTRY.get(name)


def all_commands() -> Dict[str, CommandFunc]:
    """返回所有已注册命令。"""
    return dict(_REGISTRY)
