# Contributing to AgentShield

Thank you for your interest in contributing to AgentShield! This guide will help you get started.

## Development Setup

```bash
# 1. Fork and clone
git clone https://github.com/<your-username>/AgentShield.git
cd AgentShield

# 2. Install in dev mode
make install-dev

# 3. Set up pre-commit hooks
pre-commit install

# 4. Copy environment config
cp .env.example .env
```

## Branch Naming

| Prefix | Use |
|--------|-----|
| `feat/` | New features |
| `fix/` | Bug fixes |
| `chore/` | Maintenance, refactoring |
| `docs/` | Documentation only |

Example: `feat/add-autogen-support`

## Commit Format

```
<type>(scope): <short summary>

<optional body>
```

Types: `feat`, `fix`, `chore`, `docs`, `test`, `refactor`

Example:
```
feat(detection): add inter-agent injection detector
```

## PR Checklist

Before submitting a pull request, ensure:

- [ ] All tests pass: `make test`
- [ ] Linting passes: `make lint`
- [ ] Type checking passes: `make typecheck`
- [ ] New code has docstrings on all public methods
- [ ] New code has full type hints
- [ ] New tests added for new functionality
- [ ] No hardcoded secrets or API keys
- [ ] CHANGELOG.md updated (if user-facing change)

## Running Tests

```bash
# Unit + integration tests
make test

# With coverage report
make test-cov

# Specific test file
pytest tests/unit/test_config.py -v
```

## Code Style

We enforce consistent style with:

- **black** — code formatting (line length 88)
- **ruff** — linting (PEP8, import sorting, bugbear)
- **mypy** — strict type checking

```bash
# Format code
make format

# Check lint
make lint

# Check types
make typecheck
```

All three must pass before merging.

## Architecture

See [docs/architecture.md](docs/architecture.md) for the full system architecture.

## Questions?

Open an issue or start a discussion on GitHub.
