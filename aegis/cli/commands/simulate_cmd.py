from __future__ import annotations
"""aegis simulate — 批量回放历史决策。"""
import argparse
import json
from pathlib import Path

from . import register
from ..colors import green, red, yellow, bold
from ..formatters import auto_format


@register("simulate")
def cmd_simulate(args: argparse.Namespace) -> int:
    """批量回放历史 tool call。"""
    input_path = getattr(args, "input", None)
    if not input_path:
        print(red("请提供 --input 文件 (JSONL)"))
        return 1
    path = Path(input_path)
    if not path.exists():
        print(red(f"文件不存在: {input_path}"))
        return 1
    calls = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                calls.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    print(bold(f"🔄 回放 {len(calls)} 条历史调用"))
    results = []
    for i, call in enumerate(calls[:50]):
        results.append({
            "index": i + 1,
            "tool": call.get("tool", "unknown"),
            "effect": "allow",
            "reason": "replay (mock)",
        })
    fmt = getattr(args, "format", "table")
    print(auto_format(results, fmt))
    print(green(f"\n✅ 回放完成: {len(results)} 条"))
    return 0
