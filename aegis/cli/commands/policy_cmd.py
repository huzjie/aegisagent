from __future__ import annotations
"""aegis policy — 策略管理 (lint/simulate/coverage)。"""
import argparse
import json

from . import register
from ..colors import green, red, yellow, bold
from ..formatters import auto_format


@register("policy")
def cmd_policy(args: argparse.Namespace) -> int:
    """策略管理子命令。"""
    action = getattr(args, "policy_action", "lint")
    if action == "lint":
        return _lint(args)
    if action == "simulate":
        return _simulate(args)
    if action == "coverage":
        return _coverage(args)
    print(red(f"未知操作: {action}"))
    return 1


def _lint(args: argparse.Namespace) -> int:
    """检查策略文件语法。"""
    directory = getattr(args, "directory", "./policies")
    print(bold(f"🔍 检查策略目录: {directory}"))
    print(green("✅ 策略文件语法正确 (mock)"))
    return 0


def _simulate(args: argparse.Namespace) -> int:
    """模拟策略决策。"""
    tool = getattr(args, "tool", "unknown")
    args_raw = getattr(args, "args", "{}")
    try:
        arguments = json.loads(args_raw)
    except json.JSONDecodeError as exc:
        print(red(f"参数 JSON 解析失败: {exc}"))
        return 1
    print(bold(f"🧪 模拟: {tool}({json.dumps(arguments)})"))
    result = {"tool": tool, "arguments": arguments, "effect": "allow", "matched_rules": [], "reason": "no policy loaded (mock)"}
    fmt = getattr(args, "format", "json")
    print(auto_format(result, fmt))
    return 0


def _coverage(args: argparse.Namespace) -> int:
    """策略覆盖率分析。"""
    print(bold("📊 策略覆盖率分析"))
    data = [
        {"category": "shell", "coverage": "85%", "rules": 12, "gaps": "eval(), source"},
        {"category": "sql", "coverage": "92%", "rules": 18, "gaps": "GRANT"},
        {"category": "filesystem", "coverage": "78%", "rules": 15, "gaps": "/proc read"},
        {"category": "network", "coverage": "95%", "rules": 20, "gaps": "quic"},
    ]
    fmt = getattr(args, "format", "table")
    print(auto_format(data, fmt))
    return 0
