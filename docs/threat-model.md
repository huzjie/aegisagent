# AegisAgent Threat Model

## Introduction

This document provides a comprehensive threat model for AegisAgent, using the STRIDE methodology. It maps known vulnerabilities (CVEs) to AegisAgent's mitigation strategies and explains how the architecture addresses emerging threats in the AI Agent ecosystem.

## STRIDE Analysis

### 1. Spoofing

**Threat**: An attacker impersonates a legitimate agent, LLM provider, or MCP server to inject malicious tool calls.

**Mitigations**:
- **Provenance Attestation**: Every tool call must include a cryptographic attestation token signed by the authorized LLM provider. Tokens without valid Ed25519 signatures are rejected.
- **mTLS for MCP**: The MCP Security Proxy requires mutual TLS authentication for all MCP server connections.
- **API Key Authentication**: Gateway API endpoints require valid API keys with scoped permissions.
- **Identity Binding**: Attestation tokens bind the tool call to a specific `agent_id`, `model_id`, and `completion_id`.

**Residual Risk**: Low. Spoofing requires compromising the LLM provider's signing keys or the agent's API credentials.

### 2. Tampering

**Threat**: An attacker modifies tool call arguments, results, or policy configurations in transit or at rest.

**Mitigations**:
- **Tamper-Evident Audit Log**: All audit entries form a Merkle chain. Any modification breaks the chain and is detectable.
- **Attestation Integrity**: Attestation tokens include hashes of tool arguments. Modifications invalidate the signature.
- **Signed Policies**: Policy files are digitally signed. The Policy Engine verifies signatures on load.
- **TLS Everywhere**: All network communication uses TLS 1.3.
- **CVE-2026-18830 Defense**: Specifically addresses tool call tampering by cryptographically binding completions to calls.

**Residual Risk**: Low. Tampering is detectable and preventable through cryptographic mechanisms.

### 3. Repudiation

**Threat**: An actor denies performing a malicious action, claiming the tool call was legitimate or that they were not responsible.

**Mitigations**:
- **Comprehensive Audit Log**: Every tool call, policy evaluation, and security decision is logged with timestamps, actor identities, and decision reasons.
- **Non-Repudiation via Signatures**: Attestation tokens are signed by the LLM provider, proving the call originated from their system.
- **HITL Approval Records**: Human approval decisions are logged with the approver's identity and timestamp.
- **Immutable Logs**: Audit logs are append-only and can be exported to external SIEM systems for long-term retention.

**Residual Risk**: Minimal. All actions are cryptographically attributable.

### 4. Information Disclosure

**Threat**: Sensitive data (PII, credentials, proprietary information) is leaked through tool calls or logs.

**Mitigations**:
- **Detection Engine**: Scans tool arguments and results for sensitive data patterns (SSN, credit cards, API keys).
- **Policy Controls**: Policies can restrict which tools can access sensitive data based on caller role and context.
- **Sandbox Isolation**: Tool execution in isolated environments prevents data leakage to other processes.
- **Log Redaction**: Audit logs automatically redact sensitive fields (configurable).
- **CVE-2026-12537 Defense**: Addresses policy bypass techniques that could lead to unauthorized data access.

**Residual Risk**: Medium. Sophisticated exfiltration via encrypted channels or steganography may evade detection.

### 5. Denial of Service

**Threat**: An attacker overwhelms the gateway with malicious tool calls, causing service degradation or outage.

**Mitigations**:
- **Rate Limiting**: Configurable per-client rate limits prevent abuse.
- **Resource Limits**: Sandbox execution enforces CPU, memory, and time limits.
- **Circuit Breakers**: Repeated failures trigger automatic circuit breaking.
- **Horizontal Scaling**: Stateless design allows scaling across multiple instances.
- **DDoS Protection**: Recommended deployment behind a CDN/WAF (e.g., Cloudflare, AWS WAF).

**Residual Risk**: Medium. Large-scale DDoS requires infrastructure-level protection.

### 6. Elevation of Privilege

**Threat**: An attacker gains elevated privileges through tool execution, escaping the sandbox or accessing unauthorized resources.

**Mitigations**:
- **Least Privilege Policies**: Policies enforce minimal required permissions for each tool call.
- **Sandbox Escape Prevention**: Multi-tier isolation (process → container → microVM) with seccomp, AppArmor, and SELinux.
- **CVE-2026-64650 Defense**: Specifically addresses sandbox escape vulnerabilities.
- **CVE-2026-64651 Defense**: Prevents privilege escalation through tool call chains.
- **No Root Execution**: Docker images run as non-root user.
- **Capability Dropping**: Containers drop all unnecessary Linux capabilities.

**Residual Risk**: Low. Defense-in-depth approach makes privilege escalation extremely difficult.

## CVE Mapping

| CVE | Threat Category | AegisAgent Mitigation | Status |
|---|---|---|---|
| **CVE-2026-18830** | Tampering | Provenance Attestation — Ed25519 signatures bind tool calls to LLM completions | ✅ Mitigated |
| **CVE-2026-18236** | Spoofing / Tampering | MCP Security Proxy — mTLS + result verification + rate limiting | ✅ Mitigated |
| **CVE-2026-64650** | Elevation of Privilege | Sandbox Isolator — gVisor/Firecracker + seccomp + AppArmor | ✅ Mitigated |
| **CVE-2026-64651** | Elevation of Privilege | Policy Engine — least privilege + dynamic permission downgrade | ✅ Mitigated |
| **CVE-2026-12537** | Spoofing / Info Disclosure | Detection Engine — semantic analysis + behavioral baselines + signature hot-reload | ✅ Mitigated |

## Attack Scenarios

### Scenario 1: Prompt Injection → Tool Call Hijack

**Attack**: Attacker injects malicious instructions into a document processed by an LLM, causing the LLM to generate tool calls that exfiltrate data.

**AegisAgent Defense**:
1. Detection Engine identifies prompt injection pattern in LLM output.
2. Policy Engine blocks tool calls accessing sensitive files.
3. Sandbox Isolator restricts filesystem access.
4. Audit Log records the attempt for forensic analysis.

**Outcome**: Attack is detected and blocked at multiple layers.

### Scenario 2: Malicious MCP Server

**Attack**: Attacker compromises an MCP server and injects malicious tool results that trick the agent into executing harmful commands.

**AegisAgent Defense**:
1. MCP Security Proxy verifies tool result signatures.
2. Detection Engine flags anomalous result patterns.
3. Policy Engine requires approval for high-risk tools.
4. Sandbox Isolator executes tools in restricted environments.

**Outcome**: Malicious results are rejected before reaching the agent.

### Scenario 3: Sandbox Escape

**Attack**: Attacker exploits a vulnerability in a tool to escape the container and access the host system.

**AegisAgent Defense**:
1. Sandbox Isolator uses gVisor/Firecracker for kernel-level isolation.
2. Seccomp profiles restrict system calls.
3. AppArmor/SELinux policies prevent privilege escalation.
4. Detection Engine monitors for escape indicators.

**Outcome**: Escape attempt is contained; attacker cannot access host.

## Threat Intelligence Integration

AegisAgent integrates with threat intelligence feeds to stay ahead of emerging threats:

- **Signature Pack Updates**: `SIGNATURE_PACK_VERSION` is updated independently of the core platform.
- **Scenario Pack**: `SCENARIO_PACK_VERSION` includes new red team scenarios based on observed attacks.
- **CVE Monitoring**: Continuous monitoring of AI security research and CVE disclosures.

## Security Best Practices

### For Deployment

- Deploy behind a WAF/CDN for DDoS protection.
- Use mTLS for all internal communication.
- Rotate attestation signing keys every 24 hours (automatic).
- Enable audit log export to a SIEM system.
- Run regular red team tests using `aegis redteam run`.

### For Policy Configuration

- Start with restrictive policies and relax as needed.
- Use role-based access control (RBAC) for tool permissions.
- Enable HITL approval for high-risk tools (shell, database, file write).
- Regularly review and update policies.

### For Development

- Use the SDK in test mode during development.
- Run the detection engine in "log-only" mode to identify false positives.
- Participate in the bug bounty program for responsible disclosure.

## Compliance

AegisAgent assists with compliance requirements for:

- **SOC 2**: Tamper-evident audit logs, access controls, encryption.
- **ISO 27001**: Risk management, security controls, incident response.
- **GDPR**: Data protection, audit trails, right to erasure (via log redaction).
- **HIPAA**: Access controls, audit logs, encryption (with proper configuration).

## Continuous Improvement

AegisAgent follows a continuous improvement process for security:

1. **Monitor**: Track security incidents, CVEs, and research.
2. **Analyze**: Assess impact on AegisAgent deployments.
3. **Mitigate**: Develop and deploy updates (signature packs, policy packs).
4. **Verify**: Red team testing to validate mitigations.
5. **Disclose**: Transparent communication via security advisories.
