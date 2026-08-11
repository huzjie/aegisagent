from __future__ import annotations
"""CLI 颜色工具（无第三方依赖）。"""

import os
import sys

_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR", "") == ""


def _wrap(code: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\x1b[{code}m{text}\x1b[0m"


def red(text: str) -> str:
    """红色。"""
    return _wrap("31", text)


def green(text: str) -> str:
    """绿色。"""
    return _wrap("32", text)


def yellow(text: str) -> str:
    """黄色。"""
    return _wrap("33", text)


def cyan(text: str) -> str:
    """青色。"""
    return _wrap("36", text)


def bold(text: str) -> str:
    """加粗。"""
    return _wrap("1", text)


def dim(text: str) -> str:
    """暗色。"""
    return _wrap("2", text)
