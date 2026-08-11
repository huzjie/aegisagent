from __future__ import annotations
"""aegis doctor — 环境诊断。"""
import argparse
import shutil
import subprocess
import sys

from . import register
from ..colors import green, red, yellow, bold, cyan


@register("doctor")
def cmd_doctor(args: argparse.Namespace) -> int:
    """诊断运行环境。"""
    print(bold("🩺 AegisAgent 环境诊断\n"))
    checks = []
    # Python 版本
    py_ok = sys.version_info >= (3, 10)
    checks.append(("Python >= 3.10", py_ok, f"{sys.version.split()[0]}"))
    # Docker
    docker = shutil.which("docker")
    checks.append(("Docker 可用", docker is not None, docker or "未安装"))
    # Firejail
    fj = shutil.which("firejail")
    checks.append(("Firejail 可用", fj is not None, fj or "未安装 (可选)"))
    # Git
    git = shutil.which("git")
    checks.append(("Git 可用", git is not None, git or "未安装"))
    # 配置文件
    from pathlib import Path
    cfg = Path("config.yaml")
    checks.append(("config.yaml 存在", cfg.exists(), str(cfg.resolve()) if cfg.exists() else "缺失"))
    # gh
    gh = shutil.which("gh")
    checks.append(("GitHub CLI", gh is not None, gh or "未安装 (可选)"))
    ok_count = 0
    for name, passed, detail in checks:
        icon = green("✔") if passed else yellow("⚠") if "可选" in detail else red("✘")
        print(f"  {icon} {name}: {cyan(detail)}")
        if passed:
            ok_count += 1
    print(f"\n  通过: {ok_count}/{len(checks)}")
    if ok_count == len(checks):
        print(green("\n✅ 环境检查全部通过"))
    else:
        print(yellow("\n⚠ 部分检查未通过，请参考文档修复"))
    return 0 if ok_count >= len(checks) - 1 else 1
