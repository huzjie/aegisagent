# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-11 "CoreBreak Response"

### Added
- **Provenance Attestation Engine**: Cryptographic binding (Ed25519) of every tool call to its originating LLM completion. Attestation tokens conform to wire protocol v1.
- **Policy Engine**: Declarative YAML-based policy DSL with matchers, conditions, and effects. Supports role-based, attribute-based, and risk-based access control for agent tool invocations.
- **Detection Layer**: Real-time detection of prompt injection, anomalous tool-call patterns, privilege escalation attempts, and data exfiltration. Signature pack version `2026.08.11`.
- **Sandbox Isolation**: Multi-tier isolation — process-level, container-level, and optional gVisor/Firecracker microVM backends. Per-call ephemeral sandboxes.
- **HITL Approval**: Human-in-the-loop approval workflow for high-risk operations. Integrates with Slack, Microsoft Teams, PagerDuty, and email. Configurable timeout with auto-deny.
- **MCP Security Proxy**: Bidirectional mTLS authentication for Model Context Protocol servers. Tool result verification, rate limiting, call auditing, and anomaly detection.
- **LLM Gateway**: Unified LLM invocation entry point supporting OpenAI, Anthropic, and local model providers. Automatic security header injection, request routing, fallback logic, and token budget enforcement.
- **Audit Log**: Tamper-evident append-only audit trail with Merkle tree integrity verification.
- **Red Team Harness**: Scenario-based red team testing framework with built-in scenario pack (`2026.08.11`). Simulates CoreBreak CVE exploit chains.
- **CLI**: `aegis` command-line tool — `init`, `serve`, `policy validate`, `policy simulate`, `detect scan`, `sandbox exec`, `audit export`, `redteam run`, `version`.
- **Python SDK**: `AegisClient` with `evaluate()`, `execute()`, and `evaluate_and_execute()` APIs.
- **FastAPI Server**: REST API on port 8901, WebSocket on port 8902 for real-time approval notifications.
- **Docker**: Multi-stage build producing <200MB runtime image with non-root user.
- **CI/CD**: GitHub Actions for linting (ruff), testing (pytest), security scanning (bandit), and CodeQL analysis.
- **CVE Defense Mappings**: Pre-configured policy and detection rules for CVE-2026-18830, CVE-2026-18236, CVE-2026-64650, CVE-2026-64651, CVE-2026-12537.

### Security
- Zero-trust architecture — no implicit trust for any tool call.
- All provenance tokens use Ed25519 signatures with automatic key rotation.
- Sandbox escape mitigation via seccomp profiles and AppArmor/SELinux enforcement.
