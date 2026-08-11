from __future__ import annotations
"""aegis check — 对单个 tool call 跑完整决策链。"""
import argparse
import json
import sys

from . import register
from ..colors import green, red, yellow, bold
from ..formatters import auto_format


@register("check")
def cmd_check(args: argparse.Namespace) -> int:
    """评估单个工具调用。"""
    payload = _read_input(args)
    if payload is None:
        return 1
    try:
        from aegis.core.config import load_settings
        settings = load_settings(getattr(args, "config", "config.yaml"))
    except Exception as exc:
        print(red(f"配置加载失败: {exc}"))
        return 1
    print(bold("🔍 评估工具调用..."))
    decision = {
        "effect": "deny" if payload.get("tool", "").startswith("dangerous.") else "allow",
        "reason": "mock decision — integrate aegis.sdk for real evaluation",
        "tool": payload.get("tool", "unknown"),
        "input": payload,
    }
    fmt = getattr(args, "format", "json")
    print(auto_format(decision, fmt))
    return 0


def _read_input(args: argparse.Namespace) -> dict | None:
    """从文件/stdin/参数读取 JSON。"""
    src = getattr(args, "input", None)
    if src and src != "-":
        try:
            with open(src, encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            print(red(f"读取失败: {exc}"))
            return None
    if not sys.stdin.isatty():
        return json.load(sys.stdin)
    raw = getattr(args, "json", None)
    if raw:
        return json.loads(raw)
    print(red("请提供 --input 文件、--json 字符串或 stdin"))
    return None
