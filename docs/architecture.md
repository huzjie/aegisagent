# AegisAgent Architecture

## Overview

AegisAgent is designed as a **zero-trust runtime security gateway** that sits between AI agent applications and their tool execution environments. The architecture follows a layered approach where each request passes through multiple security checkpoints before reaching the target tool.

## Layered Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Application Layer                           │
│  Agent Framework (LangChain / AutoGen / CrewAI / Custom)        │
└───────────────────────┬─────────────────────────────────────────┘
                        │ tool_call(tool_name, args, context)
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Gateway Layer                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Request Validator & Router                   │  │
│  │  • Schema validation                                      │  │
│  │  • Authentication (API key, mTLS)                         │  │
│  │  • Rate limiting                                          │  │
│  └──────────────────────────────────────────────────────────┘  │
└───────────────────────┬─────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Security Decision Pipeline                      │
│                                                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐    │
│  │ Provenance  │───▶│   Policy    │───▶│   Detection     │    │
│  │ Attestation │    │   Engine    │    │   Engine        │    │
│  └─────────────┘    └──────┬──────┘    └────────┬────────┘    │
│                            │                     │              │
│                            ▼                     ▼              │
│                     ┌─────────────────────────────────────┐    │
│                     │      Decision Aggregator            │    │
│                     │  (ALLOW / DENY / NEEDS_APPROVAL)    │    │
│                     └─────────────────────────────────────┘    │
└───────────────────────┬─────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Execution Layer                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │   Sandbox    │  │   HITL       │  │   Tool Executor      │  │
│  │   Isolator   │  │   Approval   │  │   (MCP/HTTP/Local)   │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└───────────────────────┬─────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Audit Layer                                   │
│  Tamper-evident log with Merkle tree integrity verification      │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Provenance Attestation Engine

The Provenance Attestation Engine cryptographically binds every tool call to its originating LLM completion. This prevents:
- **Tool call tampering**: An attacker cannot modify tool arguments after the LLM generates them.
- **Replay attacks**: Each attestation token is single-use with a unique nonce.
- **Spoofed origins**: Only the authorized LLM provider can generate valid attestations.

**Implementation**:
- Uses Ed25519 signatures for performance and security.
- Attestation tokens include: `tool_name`, `args_hash`, `model_id`, `completion_id`, `timestamp`, `nonce`.
- Keys are rotated automatically every 24 hours.
- Wire protocol version: `ATTESTATION_VERSION = 1`.

### 2. Policy Engine

The Policy Engine evaluates declarative YAML policies to determine whether a tool call should be allowed.

**Policy Structure**:
```yaml
name: "restrict-shell-exec"
version: "1.0"
matchers:
  - tool_name: "shell.*"
conditions:
  - attribute: "caller.role"
    operator: "not_in"
    value: ["admin", "devops"]
effect: "deny"
reason: "Shell execution requires elevated privileges"
```

**Evaluation Flow**:
1. Load all policies matching the tool call.
2. Evaluate conditions in priority order.
3. First matching policy determines the effect.
4. If no policy matches, default to `allow` (configurable).

### 3. Detection Engine

The Detection Engine performs real-time analysis of tool calls to identify suspicious patterns.

**Detection Sources**:
- **Signature-based**: Known attack patterns (e.g., prompt injection payloads, CVE exploit signatures).
- **Behavioral**: Anomalies in call frequency, argument patterns, or data volume.
- **ML-based**: Trained models for zero-day detection (optional, requires `aegisagent[observability]`).

**Signature Pack**:
- Loaded from `aegis/detect/signatures/*.yaml`.
- Updated independently via `SIGNATURE_PACK_VERSION`.
- Can be hot-reloaded without restarting the server.

### 4. Sandbox Isolator

The Sandbox Isolator ensures that tool execution occurs in a controlled, isolated environment.

**Isolation Tiers**:
| Tier | Technology | Use Case |
|---|---|---|
| Process | subprocess + seccomp | Low-risk, trusted tools |
| Container | Docker / Podman | Standard isolation |
| microVM | gVisor / Firecracker | High-risk, untrusted code |

**Security Controls**:
- Network policies (allow/deny lists).
- Filesystem restrictions (read-only mounts, tmpfs).
- Resource limits (CPU, memory, execution time).
- No privileged capabilities by default.

### 5. HITL Approval

The HITL (Human-in-the-Loop) Approval component intercepts high-risk operations and requires explicit human authorization.

**Workflow**:
1. Tool call is flagged by policy or detection engine.
2. Approval request is sent to configured channels (Slack, Teams, PagerDuty, email).
3. Human reviewer approves or denies via web UI or channel response.
4. Timeout (default: 5 minutes) results in automatic denial.
5. Decision is recorded in audit log.

### 6. MCP Security Proxy

The MCP Security Proxy adds security controls to Model Context Protocol servers.

**Features**:
- Bidirectional mTLS authentication.
- Tool result verification (hash matching, schema validation).
- Rate limiting per client.
- Call auditing and anomaly detection.

### 7. Audit Log

The Audit Log provides a tamper-evident record of all security decisions.

**Implementation**:
- Append-only JSONL format.
- Each entry includes a hash of the previous entry (Merkle chain).
- Periodic snapshots with digital signatures.
- Export to SIEM systems via OpenTelemetry.

## Data Flow

### Successful Tool Call

```
1. Agent → Gateway: tool_call(request)
2. Gateway → Validator: schema check, auth
3. Validator → Provenance: verify attestation token
4. Provenance → Policy: evaluate policies
5. Policy → Detection: scan for threats
6. Detection → Decision: ALLOW
7. Decision → Sandbox: allocate isolated environment
8. Sandbox → Executor: run tool
9. Executor → Audit: log success
10. Audit → Agent: return result
```

### Denied Tool Call

```
1-6. (same as above)
7. Detection → Decision: DENY (policy violation)
8. Decision → Audit: log denial with reason
9. Audit → Agent: return error (403 Forbidden)
```

### Approval-Required Tool Call

```
1-6. (same as above)
7. Detection → Decision: NEEDS_APPROVAL
8. Decision → HITL: send approval request
9. HITL → (wait for human response)
10. Human → HITL: approve
11. HITL → Sandbox: proceed with execution
12-14. (same as successful flow)
```

## Configuration

AegisAgent is configured via YAML files in `.aegis/`:

```
.aegis/
├── config.yaml          # Global configuration
├── policy/              # Policy definitions
│   ├── default.yaml
│   └── custom/
├── signatures/          # Detection signatures
├── keys/                # Attestation signing keys
└── audit/               # Audit log storage
```

## Performance Considerations

- **Latency**: Typical evaluation takes <5ms per tool call.
- **Throughput**: Single instance handles ~10,000 evaluations/second.
- **Memory**: ~50MB base, +10MB per 1,000 loaded policies.
- **Horizontal scaling**: Stateless design allows multi-instance deployment behind a load balancer.

## Extensibility

AegisAgent supports plugins for:
- Custom policy matchers.
- Novel detection signatures.
- Alternative sandbox backends.
- Integration with external approval systems.

See [SDK Guide](sdk-guide.md) for details on extending AegisAgent.
