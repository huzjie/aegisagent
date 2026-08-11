# AegisAgent SDK Guide

The AegisAgent Python SDK provides a simple interface for integrating security controls into your AI agent applications.

## Installation

```bash
# Basic installation (zero dependencies)
pip install aegisagent

# With server support
pip install aegisagent[server]

# Full installation
pip install aegisagent[all]
```

## Quick Start

```python
from aegis import AegisClient

# Initialize client
client = AegisClient(policy="default")

# Evaluate and execute a tool call
result = client.evaluate_and_execute(
    tool="shell.exec",
    args={"command": "ls -la"},
    provenance={"model": "gpt-4", "trace_id": "abc-123"}
)

print(result.status)  # "allowed" | "denied" | "needs_approval"
```

## Core Concepts

### AegisClient

The `AegisClient` is the main entry point for the SDK.

```python
from aegis import AegisClient

client = AegisClient(
    policy="default",              # Policy profile name
    gateway_url="http://localhost:8901",  # Gateway URL (optional)
    timeout=30,                    # Request timeout in seconds
    retry_count=3                  # Number of retries
)
```

### Tool Evaluation

The `evaluate()` method checks if a tool call is allowed without executing it.

```python
result = client.evaluate(
    tool="database.query",
    args={"sql": "SELECT * FROM users"},
    context={
        "user_id": "user-123",
        "role": "analyst",
        "ip_address": "192.168.1.1"
    },
    provenance={
        "model": "gpt-4",
        "completion_id": "cmp-456"
    }
)

if result.allowed:
    print("Tool call is allowed")
else:
    print(f"Denied: {result.reason}")
```

### Tool Execution

The `execute()` method runs a tool call after evaluation.

```python
result = client.execute(
    tool="shell.exec",
    args={"command": "echo 'Hello, World!'"},
    sandbox={
        "backend": "container",    # "process", "container", "microvm"
        "timeout": 10,             # Execution timeout
        "network": False           # Network access
    }
)

print(f"Status: {result.status}")
print(f"Output: {result.output}")
```

### Evaluate and Execute

The `evaluate_and_execute()` method combines evaluation and execution.

```python
result = client.evaluate_and_execute(
    tool="http.request",
    args={
        "method": "GET",
        "url": "https://api.example.com/data"
    },
    provenance={"model": "claude-3", "trace_id": "xyz-789"},
    sandbox={"backend": "container"}
)
```

## Advanced Usage

### Custom Policies

Load custom policies from a file:

```python
client = AegisClient(policy="path/to/custom-policy.yaml")
```

Policy file format:

```yaml
name: "custom-policy"
version: "1.0"
rules:
  - match:
      tool_name: "shell.*"
    condition:
      attribute: "caller.role"
      operator: "in"
      value: ["admin", "devops"]
    effect: "allow"
  
  - match:
      tool_name: "database.*"
    condition:
      attribute: "args.sql"
      operator: "regex"
      pattern: "^(SELECT|INSERT)\\b"
    effect: "allow"
  
  - match:
      tool_name: ".*"
    effect: "deny"
    reason: "Default deny"
```

### Provenance Attestation

Generate and verify attestation tokens:

```python
from aegis.attestation import AttestationEngine

engine = AttestationEngine(signing_key="path/to/key.pem")

# Generate attestation
token = engine.attest(
    tool="shell.exec",
    args={"command": "ls"},
    model="gpt-4",
    completion_id="cmp-123"
)

# Verify attestation
is_valid = engine.verify(token)
```

### Detection Engine Integration

Manually invoke the detection engine:

```python
from aegis.detect import DetectionEngine

detector = DetectionEngine()

# Scan for threats
threats = detector.scan(
    tool="shell.exec",
    args={"command": "rm -rf /"},
    context={"user_id": "user-123"}
)

if threats:
    print(f"Detected {len(threats)} threats:")
    for threat in threats:
        print(f"  - {threat.type}: {threat.severity}")
```

### Sandbox Backends

Configure sandbox backends:

```python
from aegis.sandbox import SandboxFactory

# Process sandbox (fastest, least isolated)
sandbox = SandboxFactory.create("process", timeout=10)

# Container sandbox (Docker)
sandbox = SandboxFactory.create("container", image="python:3.12-slim")

# MicroVM sandbox (gVisor/Firecracker)
sandbox = SandboxFactory.create("microvm", memory="512m", cpus=1)

# Execute in sandbox
result = sandbox.execute("echo 'Hello from sandbox'")
```

### HITL Approval

Handle approval workflows:

```python
from aegis.approval import ApprovalManager

manager = ApprovalManager(
    channels=["slack", "email"],
    timeout=300  # 5 minutes
)

# Request approval
request = manager.request(
    tool="database.delete",
    args={"table": "users", "id": 123},
    reason="User requested account deletion",
    approvers=["admin@example.com"]
)

# Wait for approval
if request.wait_for_approval():
    print("Approved!")
    # Execute tool
else:
    print("Denied or timed out")
```

### MCP Security Proxy

Integrate with MCP servers:

```python
from aegis.mcp import MCPSecurityProxy

proxy = MCPSecurityProxy(
    server_url="https://mcp.example.com",
    client_cert="path/to/client.crt",
    client_key="path/to/client.key"
)

# Call MCP tool with security controls
result = proxy.call_tool(
    tool="search",
    args={"query": "sensitive data"}
)
```

### LLM Gateway

Route LLM calls through the gateway:

```python
from aegis.gateway import LLMGateway

gateway = LLMGateway(
    providers={
        "openai": {"api_key": "sk-..."},
        "anthropic": {"api_key": "sk-ant-..."}
    },
    routing="round-robin"  # or "priority", "failover"
)

# Generate completion
response = gateway.complete(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello"}],
    max_tokens=100
)
```

## Framework Integration

### LangChain

```python
from aegis.integrations.langchain import AegisCallbackHandler
from langchain.agents import initialize_agent

callback = AegisCallbackHandler(client=client)

agent = initialize_agent(
    tools=tools,
    callbacks=[callback]
)
```

### AutoGen

```python
from aegis.integrations.autogen import AegisMiddleware
import autogen

middleware = AegisMiddleware(client=client)

agent = autogen.AssistantAgent(
    name="assistant",
    middleware=middleware
)
```

## Error Handling

Handle SDK errors:

```python
from aegis.exceptions import (
    AegisError,
    PolicyViolationError,
    AttestationError,
    SandboxError
)

try:
    result = client.evaluate_and_execute(...)
except PolicyViolationError as e:
    print(f"Policy denied: {e.reason}")
except AttestationError as e:
    print(f"Attestation failed: {e}")
except SandboxError as e:
    print(f"Sandbox execution failed: {e}")
except AegisError as e:
    print(f"General error: {e}")
```

## Async Support

The SDK supports async/await:

```python
import asyncio
from aegis import AsyncAegisClient

async def main():
    client = AsyncAegisClient()
    result = await client.evaluate_and_execute(
        tool="shell.exec",
        args={"command": "ls"}
    )
    print(result.status)

asyncio.run(main())
```

## Testing

### Mock Client

Use the mock client for testing:

```python
from aegis.testing import MockAegisClient

mock_client = MockAegisClient()
mock_client.mock_evaluate(tool="shell.exec", allowed=True)

result = mock_client.evaluate(tool="shell.exec", args={})
assert result.allowed
```

### Test Utilities

```python
from aegis.testing import create_test_provenance, create_test_context

provenance = create_test_provenance(model="gpt-4")
context = create_test_context(role="admin")
```

## Best Practices

1. **Use environment variables** for configuration:
   ```python
   client = AegisClient(policy=os.getenv("AEGIS_POLICY", "default"))
   ```

2. **Enable caching** for repeated evaluations:
   ```python
   client = AegisClient(cache_enabled=True, cache_ttl=60)
   ```

3. **Log all security decisions** for auditing:
   ```python
   import logging
   logging.getLogger("aegis").setLevel(logging.INFO)
   ```

4. **Use type hints** for better IDE support:
   ```python
   from aegis.types import ToolCallResult
   result: ToolCallResult = client.evaluate(...)
   ```

5. **Handle timeouts** gracefully:
   ```python
   try:
       result = client.evaluate(timeout=5)
   except TimeoutError:
       # Fallback logic
   ```

## API Reference

See [API Reference](api-reference.md) for complete API documentation.
