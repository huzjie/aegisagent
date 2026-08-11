# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ Yes |
| < 1.0 | ❌ No |

## Reporting a Vulnerability

AegisAgent takes security seriously. We appreciate responsible disclosure of security vulnerabilities.

### How to Report

**Email**: [security@aegisagent.dev](mailto:security@aegisagent.dev)

Please include:
- Description of the vulnerability
- Steps to reproduce or proof-of-concept
- Affected version(s)
- Potential impact assessment
- Suggested fix (if any)

### What to Expect

1. **Acknowledgment**: We will acknowledge receipt within 48 hours.
2. **Assessment**: Our security team will assess the report within 7 business days.
3. **Fix Development**: We will develop and test a fix.
4. **Coordinated Disclosure**: We will coordinate with you on a disclosure timeline (typically 90 days from acknowledgment).
5. **Credit**: With your permission, we will credit you in the security advisory.

### Guidelines

- **Do not** open a public GitHub issue for a security vulnerability.
- **Do not** exploit the vulnerability beyond what is needed for the proof-of-concept.
- **Do not** access or modify other users' data during testing.
- **Do** use isolated test environments for vulnerability reproduction.

### Scope

In-scope:
- AegisAgent core library (`aegis/`)
- AegisAgent CLI
- AegisAgent server/API
- Official Docker images
- Documentation that could lead to security issues

Out-of-scope:
- Third-party dependencies (report to the respective projects)
- Social engineering attacks against contributors
- Physical security

### PGP Key

For sensitive reports, encrypt your email using our PGP key:

```
Key ID: 0xAEGISAGENT-SECURITY
Fingerprint: (available on keyservers upon request)
```

## Security Architecture

AegisAgent follows defense-in-depth principles:

- **Zero Trust**: Every tool call is verified regardless of origin.
- **Provenance Attestation**: Cryptographic binding of tool calls to LLM completions.
- **Least Privilege**: Policy engine enforces minimal required permissions.
- **Sandbox Isolation**: Tool execution in isolated environments.
- **Tamper-Evident Audit**: Merkle tree-based audit log integrity.

## Security Updates

Security advisories are published on [GitHub Security Advisories](https://github.com/huzjie/aegisagent/security/advisories). Subscribe to watch for new advisories.

## CVE Coverage

AegisAgent provides active defense against:
- CVE-2026-18830 (Tool call tampering)
- CVE-2026-18236 (MCP protocol injection)
- CVE-2026-64650 (Sandbox escape)
- CVE-2026-64651 (Privilege escalation)
- CVE-2026-12537 (Policy bypass)

See [docs/threat-model.md](docs/threat-model.md) for detailed threat analysis.
