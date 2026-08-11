# Contributing to AegisAgent

Thank you for your interest in contributing to AegisAgent. This document provides guidelines and information for contributors.

## Development Environment

### Prerequisites

- Python 3.10 or higher
- `pip` or `uv` for package management
- Git

### Setup

```bash
# Clone the repository
git clone https://github.com/huzjie/aegisagent.git
cd aegisagent

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate     # Windows

# Install with all dependencies
pip install -e ".[all,dev]"
```

## Code Style

AegisAgent uses the following tools for code quality:

| Tool | Purpose | Config |
|---|---|---|
| **ruff** | Linting & import sorting | `pyproject.toml` `[tool.ruff]` |
| **black** | Code formatting (line-length=110) | `pyproject.toml` `[tool.black]` |
| **mypy** | Static type checking | `pyproject.toml` `[tool.mypy]` |

### Before committing

```bash
ruff check aegis/
black --check aegis/
mypy aegis/
```

Or simply:

```bash
make lint
```

## Project Structure

```
aegis/                # Core library (stdlib-only, zero runtime deps)
├── attestation/      # Provenance attestation
├── policy/           # Policy engine + DSL
├── detect/           # Detection signatures
├── sandbox/          # Sandbox backends
├── approval/         # HITL approval flows
├── mcp/              # MCP security proxy
├── gateway/          # LLM gateway
├── audit/            # Tamper-evident audit log
├── redteam/          # Red team scenarios
└── cli/              # CLI entry point
tests/                # Mirror structure of aegis/
```

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`.
2. **Write tests** for any new functionality. AegisAgent targets >90% line coverage.
3. **Run the full test suite**: `make test`.
4. **Run lint checks**: `make lint`.
5. **Update documentation** if your change affects user-facing behavior.
6. **Submit a PR** using the pull request template. Fill in all sections.
7. A maintainer will review and may request changes. CI must pass before merge.

### Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(policy): add rate-limit matcher for tool call frequency
fix(attestation): handle expired signing keys gracefully
docs(sdk): add LangChain callback example
```

## Testing Requirements

- All new features must include unit tests.
- Security-sensitive changes must include integration tests.
- Run: `pytest tests/ -v --cov=aegis --cov-report=term-missing`
- Minimum coverage threshold: 90%

### Test Organization

```
tests/
├── unit/           # Fast, isolated tests
├── integration/    # Cross-module tests
├── e2e/            # End-to-end scenarios
└── redteam/        # Adversarial test cases
```

## Security Contributions

Security fixes are treated with higher priority. If your PR addresses a security issue:

1. Check [SECURITY.md](SECURITY.md) for responsible disclosure process.
2. Mark the PR with the `security` label.
3. Do not include exploit details in commit messages — link to the advisory instead.

## Getting Help

- Open a [GitHub Discussion](https://github.com/huzjie/aegisagent/discussions) for questions.
- Join the `#aegisagent` channel on the AI Security Discord.
- Tag `@aegisagent/maintainers` in your PR for faster review.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
