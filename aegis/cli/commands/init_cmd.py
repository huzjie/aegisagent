from __future__ import annotations
"""aegis init — 初始化项目结构。"""
import argparse
import os
from pathlib import Path

from . import register
from ..colors import green, cyan

_DEFAULT_CONFIG = """# AegisAgent 配置文件
# 详见 https://github.com/aegisagent/aegisagent/docs/deployment.md

version: "1.0"

server:
  host: "127.0.0.1"
  port: 8901
  api_key: "${AEGIS_API_KEY}"

provenance:
  require_attestation: true
  max_age_s: 300
  clock_skew_s: 5
  trusted_issuers: ["local"]

policy:
  default_effect: monitor
  fail_closed: true
  hot_reload: true
  directories:
    - "./policies"

sandbox:
  default_kind: subprocess
  timeout_s: 30
  memory_limit_mb: 512
  egress_allowlist: []

approval:
  auto_approve_below: low
  timeout_s: 300
  channels:
    - type: console

gateway:
  enabled: false
  port: 8910
  providers: {}

audit:
  backend: sqlite
  path: "./data/audit.db"

detection:
  detectors:
    prompt_injection: true
    secrets: true
    egress: true
    tool_poisoning: true
"""


@register("init")
def cmd_init(args: argparse.Namespace) -> int:
    """初始化 AegisAgent 工作目录。"""
    target = Path(getattr(args, "directory", "."))
    target.mkdir(parents=True, exist_ok=True)
    config_path = target / "config.yaml"
    if not config_path.exists():
        config_path.write_text(_DEFAULT_CONFIG, encoding="utf-8")
        print(green("✔ 创建 config.yaml"))
    else:
        print(cyan("⊘ config.yaml 已存在，跳过"))
    for sub in ("policies", "data", "logs", "certs"):
        d = target / sub
        d.mkdir(exist_ok=True)
        print(green(f"✔ 创建 {sub}/"))
    print(green("\n✅ AegisAgent 初始化完成"))
    print(f"   编辑 {config_path} 后运行: aegis serve")
    return 0
