# Contributing to AgentShield

Thank you for your interest in contributing to AgentShield! This guide will help you get started.

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/agentshield.git
   cd agentshield
   ```
3. **Install** development dependencies:
   ```bash
   make install-dev
   ```
4. **Create a branch** for your changes:
   ```bash
   git checkout -b feat/your-feature-name
   ```

## Branch Naming

Use the following prefixes:

| Prefix   | Purpose                        |
| -------- | ------------------------------ |
| `feat/`  | New features                   |
| `fix/`   | Bug fixes                      |
| `chore/` | Maintenance and tooling        |
| `docs/`  | Documentation updates          |

## Commit Format

Follow the [Conventional Commits](https://www.conventionalcommits.org/) format:

```
type(scope): description
```

Examples:
- `feat(detection): add memory poisoning detector`
- `fix(interceptor): handle missing tool._run method`
- `docs(readme): update quickstart section`

## Code Style

All code must pass the following checks before a pull request is accepted:

```bash
make lint        # ruff + black --check
make typecheck   # mypy strict mode
make test        # pytest unit + integration
```

### Rules

- **Type hints** on all functions and methods
- **Docstrings** on all classes and public methods
- **Structured logging** via loguru (no bare `print()`)
- **Custom exceptions** (no bare `raise Exception(...)`)
- **No hardcoded secrets** — use environment variables
- **No TODO comments** in committed code

## Pull Request Checklist

Before submitting your PR, verify:

- [ ] All tests pass (`make test`)
- [ ] Linting passes (`make lint`)
- [ ] Type checking passes (`make typecheck`)
- [ ] Code follows the style guidelines
- [ ] Docstrings and type hints are complete
- [ ] CHANGELOG.md is updated (if applicable)

## Reporting Issues

Open an issue on GitHub with:
- Steps to reproduce
- Expected vs. actual behavior
- Python version and OS

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
