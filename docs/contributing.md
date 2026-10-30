# Contributing to AgentShield

## Setup

```bash
git clone https://github.com/AdityaBelhekar/AgentShield
cd AgentShield
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Checks

CI runs these on every push. Run them before opening a PR:

```bash
ruff check .
ruff format --check .
mypy agentshield
pytest
```

## Rules

- Tests live in `tests/` and are committed. Every behaviour change comes with a test that fails without it.
- Core dependencies are `pydantic` and `pyyaml` only. Anything else goes in an extra; `tests/test_package.py` enforces this.
- Enforcement fails closed: if the policy engine cannot decide, the answer is deny.
- Nothing on the tool-call path does network I/O or blocks on telemetry.
- Full type hints; `mypy --strict` must pass.
- Update `CHANGELOG.md` under `[Unreleased]`.

## Commit format

- `feat(scope): …` — new behaviour
- `fix(scope): …` — what was broken and how it is fixed
- `docs(scope): …`, `test(scope): …`, `refactor(scope): …`, `ci: …`, `build: …`

## Security issues

Do not open a public issue. See [SECURITY.md](https://github.com/AdityaBelhekar/AgentShield/blob/main/SECURITY.md).
