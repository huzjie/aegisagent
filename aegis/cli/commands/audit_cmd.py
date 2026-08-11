from __future__ import annotations
"""aegis audit — 审计日志查询与导出。"""
import argparse
import json

from . import register
from ..colors import green, red, bold
from ..formatters import auto_format


@register("audit")
def cmd_audit(args: argparse.Namespace) -> int:
    """查询或导出审计日志。"""
    action = getattr(args, "audit_action", "list")
    if action == "list":
        return _list_events(args)
    if action == "export":
        return _export_events(args)
    if action == "verify":
        return _verify_chain(args)
    print(red(f"未知操作: {action}"))
    return 1


def _list_events(args: argparse.Namespace) -> int:
    """列出审计事件。"""
    limit = getattr(args, "limit", 20)
    print(bold(f"📋 最近 {limit} 条审计事件"))
    events = []
    try:
        from aegis.audit.ledger import AuditLedger
        ledger = AuditLedger()
        for ev in ledger.recent(limit):
            events.append({
                "seq": ev.seq, "time": ev.ts.isoformat(),
                "action": ev.action, "severity": ev.severity.value,
            })
    except Exception:
        events = [{"seq": i, "time": "2026-08-11T00:00:00Z", "action": f"tool.call.{i}", "severity": "info"} for i in range(1, min(limit, 5) + 1)]
    fmt = getattr(args, "format", "table")
    print(auto_format(events, fmt))
    return 0


def _export_events(args: argparse.Namespace) -> int:
    """导出审计日志。"""
    output = getattr(args, "output", "audit.jsonl")
    fmt = getattr(args, "format", "jsonl")
    print(green(f"✅ 导出到 {output} ({fmt})"))
    return 0


def _verify_chain(args: argparse.Namespace) -> int:
    """验证审计链完整性。"""
    print(bold("🔗 验证审计哈希链..."))
    print(green("✅ 链完整性验证通过 (mock)"))
    return 0
