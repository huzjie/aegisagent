from __future__ import annotations
"""AegisAgent 命令行入口 ``python -m aegis``。"""
import argparse
import sys

from aegis.version import __version__
from . import commands as cmd_pkg


def build_parser() -> argparse.ArgumentParser:
    """构建参数解析器。"""
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="AegisAgent — AI Agent 运行时安全网关",
    )
    parser.add_argument("--version", action="version", version=f"aegis {__version__}")
    parser.add_argument("--config", default="config.yaml", help="配置文件路径")
    sub = parser.add_subparsers(dest="command", help="子命令")
    # init
    p_init = sub.add_parser("init", help="初始化工作目录")
    p_init.add_argument("directory", nargs="?", default=".", help="目标目录")
    # serve
    p_serve = sub.add_parser("serve", help="启动服务")
    p_serve.add_argument("--host", default=None)
    p_serve.add_argument("--port", type=int, default=None)
    # check
    p_check = sub.add_parser("check", help="评估工具调用")
    p_check.add_argument("--input", "-i", help="JSON 文件")
    p_check.add_argument("--json", "-j", help="JSON 字符串")
    p_check.add_argument("--format", choices=["json", "yaml", "table"], default="json")
    # audit
    p_audit = sub.add_parser("audit", help="审计日志")
    p_audit.add_argument("audit_action", nargs="?", choices=["list", "export", "verify"], default="list")
    p_audit.add_argument("--limit", type=int, default=20)
    p_audit.add_argument("--output", default="audit.jsonl")
    p_audit.add_argument("--format", choices=["json", "yaml", "table", "csv", "jsonl"], default="table")
    # policy
    p_pol = sub.add_parser("policy", help="策略管理")
    p_pol.add_argument("policy_action", nargs="?", choices=["lint", "simulate", "coverage"], default="lint")
    p_pol.add_argument("--directory", default="./policies")
    p_pol.add_argument("--tool", default="")
    p_pol.add_argument("--args", default="{}")
    p_pol.add_argument("--format", choices=["json", "yaml", "table"], default="table")
    # mcp
    p_mcp = sub.add_parser("mcp", help="MCP 管理")
    p_mcp.add_argument("mcp_action", nargs="?", choices=["inventory", "scan", "pin"], default="inventory")
    p_mcp.add_argument("--server", default="")
    p_mcp.add_argument("--format", choices=["json", "yaml", "table"], default="table")
    # simulate
    p_sim = sub.add_parser("simulate", help="批量回放")
    p_sim.add_argument("--input", required=True)
    p_sim.add_argument("--format", choices=["json", "yaml", "table"], default="table")
    # doctor
    sub.add_parser("doctor", help="环境诊断")
    # version
    sub.add_parser("version", help="显示版本")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI 主入口。"""
    # 确保所有命令模块被加载以触发 @register
    from .commands import init_cmd, serve, check, audit_cmd, policy_cmd, mcp_cmd, simulate_cmd, doctor_cmd, version_cmd  # noqa: F401
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    handler = cmd_pkg.get(args.command)
    if handler is None:
        print(f"未知命令: {args.command}")
        return 1
    try:
        return handler(args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"错误: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
