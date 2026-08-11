from __future__ import annotations
"""外层循环：反复重跑 push_api.main 直到成功（利用缓存断点续传）。"""
import subprocess
import sys
import time
import os

PY = sys.executable
SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "push_api.py")


def main() -> None:
    for attempt in range(1, 40):
        print(f"\n===== 第 {attempt} 次尝试 =====", flush=True)
        r = subprocess.run([PY, SCRIPT], capture_output=True, text=True, timeout=1200)
        out = (r.stdout + r.stderr)
        # 打印进度尾部
        lines = out.strip().splitlines()
        print("\n".join(lines[-8:]), flush=True)
        if r.returncode == 0 and "推送完成" in out:
            print("🎉 推送成功！", flush=True)
            return
        # 检查缓存进度
        try:
            import json
            cache = json.load(open(os.path.join(os.path.dirname(SCRIPT), ".push_cache.json")))
            print(f"  缓存进度: {len(cache)} 个 blob", flush=True)
        except Exception:
            pass
        time.sleep(3)
    print("❌ 多次尝试后仍失败", flush=True)


if __name__ == "__main__":
    main()
