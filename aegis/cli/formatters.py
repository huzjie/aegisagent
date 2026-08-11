from __future__ import annotations
"""CLI 输出格式化：table / json / yaml / csv。"""
import csv
import io
import json
from typing import Any, Dict, List, Sequence

from .colors import bold, dim, cyan


def format_table(rows: Sequence[Dict[str, Any]], columns: Sequence[str] | None = None) -> str:
    """将字典列表格式化为对齐表格。"""
    if not rows:
        return dim("(no data)")
    cols = list(columns) if columns else list(rows[0].keys())
    widths: Dict[str, int] = {}
    for c in cols:
        widths[c] = max(len(str(c)), max((len(str(r.get(c, ""))) for r in rows), default=0))
    header = " | ".join(bold(str(c).ljust(widths[c])) for c in cols)
    sep = "-+-".join("-" * widths[c] for c in cols)
    lines = [header, sep]
    for r in rows:
        line = " | ".join(str(r.get(c, "")).ljust(widths[c]) for c in cols)
        lines.append(line)
    return "\n".join(lines)


def format_json(data: Any, indent: int = 2) -> str:
    """JSON 格式化。"""
    return json.dumps(data, indent=indent, ensure_ascii=False, default=str)


def format_yaml_like(data: Any, indent: int = 0) -> str:
    """简易 YAML-like 输出（不依赖 PyYAML）。"""
    prefix = "  " * indent
    if isinstance(data, dict):
        lines: List[str] = []
        for k, v in data.items():
            if isinstance(v, (dict, list)):
                lines.append(f"{prefix}{k}:")
                lines.append(format_yaml_like(v, indent + 1))
            else:
                lines.append(f"{prefix}{k}: {v}")
        return "\n".join(lines)
    if isinstance(data, list):
        lines = []
        for item in data:
            if isinstance(item, dict):
                lines.append(f"{prefix}-")
                lines.append(format_yaml_like(item, indent + 1))
            else:
                lines.append(f"{prefix}- {item}")
        return "\n".join(lines)
    return f"{prefix}{data}"


def format_csv(rows: Sequence[Dict[str, Any]], columns: Sequence[str] | None = None) -> str:
    """CSV 格式化。"""
    if not rows:
        return ""
    cols = list(columns) if columns else list(rows[0].keys())
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=cols)
    writer.writeheader()
    for r in rows:
        writer.writerow({c: r.get(c, "") for c in cols})
    return buf.getvalue()


def auto_format(data: Any, fmt: str = "table", columns: Sequence[str] | None = None) -> str:
    """根据 fmt 自动选择格式。"""
    if fmt == "json":
        return format_json(data)
    if fmt == "yaml":
        return format_yaml_like(data)
    if fmt == "csv":
        if isinstance(data, list):
            return format_csv(data, columns)
        return format_csv([data], columns)
    # table
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return format_table(data, columns)
    if isinstance(data, dict):
        return format_table([data], columns)
    return str(data)
