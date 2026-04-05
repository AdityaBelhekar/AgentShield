# Contributing

## Dev Environment Setup

```bash
git clone https://github.com/AdityaBelhekar/AgentShield
cd AgentShield
pip install -e ".[dev]"
cp .env.example .env
```

## Code Rules (13)

1. Target Python 3.11+ for all SDK changes.
2. Keep public import ergonomics stable (`from agentshield import shield`).
3. Preserve strict type safety (`mypy` strict is enabled for `agentshield/`).
4. Enforce formatting with Black (`line-length = 88`).
5. Enforce linting with Ruff before opening a PR.
6. Add docstrings for all new public classes/functions (Google style).
7. Do not bypass policy/detection evidence fields when raising security exceptions.
8. Keep adapter registry import order deterministic (LangChain -> LlamaIndex -> AutoGen -> Raw API).
9. Update `CHANGELOG.md` for user-visible behavior changes.
10. Use branch naming conventions: `feat/*`, `fix/*`, `chore/*`, `docs/*`.
11. Use commit format: `feat(phase-Nx): description - summary`.
12. Keep all tests under `/scratch/tests/` only and never commit scratch artifacts.
13. Never commit secrets or live credentials; use `.env.example` placeholders.

## Commit Format

Required style:

```text
feat(phase-Nx): description - summary
```

Example:

```text
feat(phase-12A): full MkDocs docs site - material theme and API reference
```

## Test Rule

- Test files must live in `/scratch/tests/`.
- Scratch test artifacts are local-only and should not be committed.

## Quality Commands

```bash
ruff check .
black --check .
mypy agentshield/
```

## PR Checklist

- [ ] `ruff check .` passes with zero errors.
- [ ] `black --check .` passes with zero formatting drift.
- [ ] `mypy agentshield/` passes in strict mode.
- [ ] New/changed behavior is covered by tests under `/scratch/tests/`.
- [ ] `CHANGELOG.md` updated for user-facing changes.
- [ ] New public APIs include docstrings and docs updates.