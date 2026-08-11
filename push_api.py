from __future__ import annotations
"""通过 GitHub Git Data API 推送整个项目到远程仓库（绕过 git push 网络限制）。

用法: GH_TOKEN=xxx python push_api.py
"""
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

TOKEN = os.environ.get("GH_TOKEN", "")
REPO = "huzjie/aegisagent"
ROOT = Path(__file__).resolve().parent
SEED_COMMIT = "6c54ba3a7b03717aaf3d0096685e6e1e901d371e"  # 由 Contents API 建立的初始 commit
MAX_RETRY = 20
CACHE = ROOT / ".push_cache.json"
# gh 网络超时（秒）——短超时让 TLS 失败快速返回，靠重试推进
GH_TIMEOUT = int(os.environ.get("GH_API_TIMEOUT", "25"))


def gh(args: list[str], body: dict) -> dict:
    """调用 gh api 并返回 JSON，带网络重试。"""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tf:
        json.dump(body, tf)
        tmp = tf.name
    for attempt in range(1, MAX_RETRY + 1):
        try:
            r = subprocess.run(["gh", "api", *args, "--input", tmp],
                               capture_output=True, text=True, timeout=GH_TIMEOUT)
        except subprocess.TimeoutExpired:
            if attempt == MAX_RETRY:
                raise RuntimeError(f"gh api {' '.join(args)} timeout")
            time.sleep(min(2, 1 + attempt))
            continue
        if r.returncode == 0:
            return json.loads(r.stdout)
        err = r.stderr.lower()
        # 网络类错误重试（Go net/http 报错无 HTTP 状态码），业务错误直接抛
        net_keywords = ("timeout", "connect", "tls", "handshake", "network",
                        "connection", "eof", "temporary redirect", "load")
        if any(k in err for k in net_keywords):
            if attempt == MAX_RETRY:
                raise RuntimeError(f"gh api {' '.join(args)} failed: {r.stderr[:200]}")
            time.sleep(min(2, 1 + attempt))
            continue
        raise RuntimeError(f"gh api {' '.join(args)} failed: {r.stderr[:300]}")
    raise RuntimeError("unreachable")


def files_to_upload() -> list[str]:
    """收集要上传的（相对）文件路径。"""
    exclude_dirs = {".git", "__pycache__", ".pytest_cache"}
    exclude_suffix = {".pyc"}
    out = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        if any(part in exclude_dirs for part in path.parts):
            continue
        if path.suffix in exclude_suffix:
            continue
        out.append(path.relative_to(ROOT).as_posix())
    # 排除种子文件（仅用于初始化分支）
    return [p for p in out if p != ".aegis-seed"]


def main() -> None:
    if not TOKEN:
        print("GH_TOKEN 缺失", file=sys.stderr)
        return
    files = files_to_upload()
    print(f"共 {len(files)} 个文件")

    # 1. 逐个创建 blob（带缓存断点续传）
    sha_map: dict[str, str] = {}
    cache: dict[str, str] = {}
    if CACHE.exists():
        cache = json.loads(CACHE.read_text(encoding="utf-8"))
    for i, rel in enumerate(files, 1):
        if rel in cache:
            sha_map[rel] = cache[rel]
            continue
        content = base64.b64encode((ROOT / rel).read_bytes()).decode()
        resp = gh(["-X", "POST", f"repos/{REPO}/git/blobs"],
                  {"content": content, "encoding": "base64"})
        sha_map[rel] = resp["sha"]
        cache[rel] = resp["sha"]
        CACHE.write_text(json.dumps(cache), encoding="utf-8")
        if i % 50 == 0 or i == len(files):
            print(f"  blobs {i}/{len(files)}", flush=True)

    # 2. 构建 tree
    tree_items = [{"path": rel, "mode": "100644", "type": "blob", "sha": sha}
                  for rel, sha in sha_map.items()]
    tree_resp = gh(["-X", "POST", f"repos/{REPO}/git/trees"],
                   {"tree": tree_items})
    tree_sha = tree_resp["sha"]
    print(f"  tree={tree_sha}")

    # 3. 创建 commit
    author = {"name": "huzjie", "email": "huzjie@yonyou.com", "date": "2026-08-11T08:00:00Z"}
    commit_body = {
        "message": (
            "feat: AegisAgent v1.0.0 - runtime security gateway for AI agents\n\n"
            "Cryptographic tool-call provenance binding every tool call to a real model "
            "completion (CoreBreak defense: CVE-2026-18830/18236/64650/64651), policy "
            "engine, multi-detector detection layer, sandbox isolation, HITL approval, "
            "MCP security proxy, LLM gateway, tamper-evident audit, CLI, REST API and "
            "single-file web console."
        ),
        "tree": tree_sha,
        "parents": [SEED_COMMIT],
        "author": author,
        "committer": author,
    }
    commit_resp = gh(["-X", "POST", f"repos/{REPO}/git/commits"],
                     commit_body)
    commit_sha = commit_resp["sha"]
    print(f"  commit={commit_sha}")

    # 4. 更新 main ref
    try:
        gh(["-X", "POST", f"repos/{REPO}/git/refs"],
           {"ref": "refs/heads/main", "sha": commit_sha})
    except RuntimeError:
        # ref 已存在则更新
        gh(["-X", "PATCH", f"repos/{REPO}/git/refs/heads/main"],
           {"sha": commit_sha, "force": True})
    print(f"✅ 推送完成 commit={commit_sha} files={len(files)}")


if __name__ == "__main__":
    main()
