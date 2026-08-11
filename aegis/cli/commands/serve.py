from __future__ import annotations
"""aegis serve — 启动 API 服务器与网关。"""
import argparse

from . import register
from ..colors import green, cyan, bold


@register("serve")
def cmd_serve(args: argparse.Namespace) -> int:
    """启动 AegisAgent 服务。"""
    from aegis.core.config import load_settings
    settings = load_settings(path=getattr(args, "config", "config.yaml"))
    host = getattr(args, "host", None) or settings.server_host
    port = getattr(args, "port", None) or settings.server_port
    print(bold(f"🛡️  AegisAgent 启动中..."))
    print(cyan(f"   API:   http://{host}:{port}"))
    print(cyan(f"   控制台: http://{host}:{port}/"))
    print(cyan(f"   健康:  http://{host}:{port}/healthz"))
    try:
        from aegis.api.server import create_server
        server = create_server(settings)
        server.serve_forever()
    except KeyboardInterrupt:
        print(green("\n✅ 已停止"))
    except Exception as exc:
        print(f"❌ 启动失败: {exc}")
        return 1
    return 0
