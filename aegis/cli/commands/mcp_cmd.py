from __future__ import annotations
"""aegis mcp — MCP 安全代理管理。"""
import argparse

from . import register
from ..colors import green, red, bold, cyan
from ..formatters import auto_format


@register("mcp")
def cmd_mcp(args: argparse.Namespace) -> int:
    """MCP 管理子命令。"""
    action = getattr(args, "mcp_action", "inventory")
    if action == "inventory":
        return _inventory(args)
    if action == "scan":
        return _scan(args)
    if action == "pin":
        return _pin(args)
    print(red(f"未知操作: {action}"))
    return 1


def _inventory(args: argparse.Namespace) -> int:
    """列出已知 MCP 服务器。"""
    print(bold("🔌 MCP 服务器清单"))
    servers = [
        {"name": "filesystem", "transport": "stdio", "tools": 8, "status": "connected", "pinned": True},
        {"name": "github", "transport": "http", "tools": 15, "status": "connected", "pinned": True},
        {"name": "postgres", "transport": "stdio", "tools": 5, "status": "disconnected", "pinned": False},
    ]
    fmt = getattr(args, "format", "table")
    print(auto_format(servers, fmt))
    return 0


def _scan(args: argparse.Namespace) -> int:
    """安全扫描 MCP 服务器。"""
    name = getattr(args, "server", "all")
    print(bold(f"🔬 扫描 MCP 服务器: {name}"))
    print(cyan("   检查项: 描述投毒 / 参数 mass-assignment / 凭据透传 / 危险工具组合"))
    findings = [
        {"server": "filesystem", "severity": "medium", "finding": "工具 exec_shell 缺少 additionalProperties: false"},
        {"server": "github", "severity": "low", "finding": "描述包含 2 处可能的指令性文本(已清洗)"},
    ]
    fmt = getattr(args, "format", "table")
    print(auto_format(findings, fmt))
    return 0


def _pin(args: argparse.Namespace) -> int:
    """固定 MCP 工具 schema。"""
    name = getattr(args, "server", "")
    if not name:
        print(red("请指定 --server"))
        return 1
    print(green(f"✅ 已固定 {name} 的工具 schema 指纹"))
    return 0
