# AegisAgent — AI Agent Runtime Security Gateway

[![CI](https://github.com/huzjie/aegisagent/actions/workflows/ci.yml/badge.svg)](https://github.com/huzjie/aegisagent/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/badge/pypi-v1.0.0-green.svg)](https://pypi.org/project/aegisagent/)
[![CodeQL](https://github.com/huzjie/aegisagent/actions/workflows/codeql.yml/badge.svg)](https://github.com/huzjie/aegisagent/actions/workflows/codeql.yml)

> **AI Agent 运行时安全网关——密码学绑定每次工具调用到真实模型补全，零信任策略执行，沙箱隔离与人工审批一体化。**

---

## 背景：为什么需要 AegisAgent

2026 年 8 月，Cloud Security Alliance 披露了 **CoreBreak 漏洞族**，这一系列严重漏洞彻底打破了 AI Agent 生态的安全假设：

| CVE 编号 | 影响组件 | 风险描述 |
|---|---|---|
| **CVE-2026-18830** | LLM 工具调用链 | 模型补全结果可被中间人篡改，工具调用与 LLM 响应之间缺少密码学绑定 |
| **CVE-2026-18236** | MCP 协议层 | Model Context Protocol 缺少双向认证，恶意 MCP 服务器可注入任意工具结果 |
| **CVE-2026-64650** | 沙箱运行时 | 容器沙箱逃逸漏洞，Agent 工具执行环境可突破隔离边界 |
| **CVE-2026-64651** | 权限提升 | Agent 工具调用权限未被正确隔离，单点突破可导致全系统接管 |
| **CVE-2026-12537** | 策略绕过 | 基于字符串匹配的传统 guardrails 可被 prompt 注入轻易绕过 |

与此同时，**沙箱逃逸**攻击技术日趋成熟，Agent 在不受约束的情况下执行工具调用（shell 命令、文件操作、网络请求）已成为企业部署 AI Agent 的最大阻碍。

**AegisAgent 正是为此而生。**

---

## 核心能力

### 1. Provenance Attestation（来源证明）
每次工具调用都通过密码学签名绑定到产生它的 LLM 补全。不可伪造、不可重放、不可篡改。

### 2. 策略引擎（Policy Engine）
声明式 DSL 定义安全策略：基于角色、工具类型、参数模式、调用频率、数据敏感度的细粒度访问控制。

### 3. 检测层（Detection Layer）
实时检测 prompt 注入、工具调用异常、权限提升尝试、数据泄露模式。基于签名包持续更新的检测规则。

### 4. 沙箱隔离（Sandbox Isolation）
多层隔离策略：进程级 → 容器级 → gVisor/Firecracker microVM。每次工具调用在独立沙箱中执行。

### 5. 人工审批（HITL Approval）
高风险操作自动触发人工审批流程。支持 Slack/Teams/PagerDuty 通知，超时自动拒绝。

### 6. MCP 安全代理（MCP Security Proxy）
为 MCP 协议添加双向认证、调用审计、结果验证、速率限制。兼容 Anthropic MCP 规范。

### 7. LLM 网关（LLM Gateway）
统一的 LLM 调用入口，支持 OpenAI / Anthropic / 本地模型，自动添加安全头、路由策略、fallback 逻辑。

---

## 架构概览

```
┌─────────────────────────────────────────────────────────────────┐
│                      Agent Application                          │
│  (LangChain / AutoGen / CrewAI / Custom Agent)                 │
└───────────────────────┬─────────────────────────────────────────┘
                        │ tool_call(request)
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                     AegisAgent Gateway                           │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │  Provenance │  │   Policy     │  │   Detection Engine    │  │
│  │  Attestation│→ │   Engine     │→ │   (Signatures + ML)   │  │
│  └─────────────┘  └──────┬───────┘  └───────────┬───────────┘  │
│                          │                       │              │
│  ┌─────────────┐  ┌──────▼───────┐  ┌───────────▼───────────┐  │
│  │  Sandbox    │  │   HITL       │  │   Audit & Logging     │  │
│  │  Isolator   │  │   Approval   │  │   (Tamper-Evident)    │  │
│  └─────────────┘  └──────────────┘  └───────────────────────┘  │
└───────────────────────┬─────────────────────────────────────────┘
                        │ verified_tool_call
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│              MCP Servers / Tool Executors                        │
│  (authenticated, audited, sandboxed)                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## 快速开始

### 安装

```bash
# 基础安装（零依赖，仅标准库）
pip install aegisagent

# 完整安装（含 server、storage、crypto、providers）
pip install aegisagent[all]

# 开发安装
pip install aegisagent[all,dev]
```

### 初始化

```bash
# 生成默认配置
aegis init

# 启动网关服务
aegis serve --host 0.0.0.0 --port 8901

# 验证健康状态
curl http://localhost:8901/health
```

### 5 行代码集成

```python
from aegis import AegisClient

client = AegisClient(policy="default")
result = client.evaluate_and_execute(
    tool="shell.exec",
    args={"command": "ls -la"},
    provenance={"model": "gpt-4", "trace_id": "abc-123"}
)
print(result.status)  # "allowed" | "denied" | "needs_approval"
```

---

## CVE 防御映射

| 威胁 | AegisAgent 防御机制 | 状态 |
|---|---|---|
| CVE-2026-18830 (工具调用篡改) | Provenance Attestation — Ed25519 签名绑定每次调用 | ✅ 已防御 |
| CVE-2026-18236 (MCP 注入) | MCP Security Proxy — 双向 mTLS + 结果校验 | ✅ 已防御 |
| CVE-2026-64650 (沙箱逃逸) | 多层隔离 — gVisor/Firecracker + seccomp | ✅ 已防御 |
| CVE-2026-64651 (权限提升) | Policy Engine — 最小权限 + 动态权限降级 | ✅ 已防御 |
| CVE-2026-12537 (策略绕过) | Detection Layer — 语义分析 + 行为基线 + 签名包热更新 | ✅ 已防御 |

---

## 命令行参考

```bash
aegis init                    # 初始化配置目录
aegis serve [--port 8901]     # 启动网关服务
aegis policy validate         # 验证策略文件语法
aegis policy simulate         # 策略模拟 (what-if)
aegis detect scan             # 扫描当前检测规则
aegis sandbox exec <cmd>      # 在沙箱中执行命令
aegis audit export            # 导出审计日志
aegis redteam run <suite>     # 运行红队测试套件
aegis version                 # 显示版本信息
```

---

## 部署

### Docker

```bash
docker build -t aegisagent:latest .
docker run -p 8901:8901 -p 8902:8902 aegisagent:latest
```

### Docker Compose

```bash
docker compose up -d
```

### Kubernetes

```bash
kubectl apply -f deploy/k8s/
```

详见 [docs/deployment.md](docs/deployment.md)。

---

## 项目结构

```
aegisagent/
├── aegis/                  # 核心运行时库
│   ├── attestation/        # 来源证明模块
│   ├── policy/             # 策略引擎
│   ├── detect/             # 检测层
│   ├── sandbox/            # 沙箱隔离
│   ├── approval/           # 人工审批
│   ├── mcp/                # MCP 安全代理
│   ├── gateway/            # LLM 网关
│   ├── audit/              # 审计日志
│   ├── redteam/            # 红队测试
│   └── cli/                # 命令行工具
├── docs/                   # 文档
├── examples/               # 示例代码
├── tests/                  # 测试
├── deploy/                 # 部署配置
├── pyproject.toml
├── Dockerfile
├── docker-compose.yaml
└── Makefile
```

---

## 贡献

欢迎贡献！请阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 了解开发流程和代码规范。

发现安全漏洞？请通过 [SECURITY.md](SECURITY.md) 中的流程上报，不要在公开 Issue 中讨论。

---

## License

Apache License 2.0 — 详见 [LICENSE](LICENSE)。

Copyright 2026 AegisAgent Contributors.

---

<p align="center">
  <sub>Built with security-first principles for the AI Agent era.</sub>
</p>
