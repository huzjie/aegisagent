from __future__ import annotations
"""aegis version — 打印版本信息。"""
import argparse

from aegis.version import __version__
from . import register


@register("version")
def cmd_version(args: argparse.Namespace) -> int:
    """打印版本。"""
    print(f"AegisAgent v{__version__}")
    return 0
