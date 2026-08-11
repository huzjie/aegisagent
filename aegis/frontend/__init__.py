from __future__ import annotations
"""Web 控制台静态文件服务。"""
from pathlib import Path

STATIC_DIR = Path(__file__).parent / "static"

def get_static_dir() -> Path:
    """返回静态文件目录。"""
    return STATIC_DIR
