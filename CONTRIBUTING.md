# Contributing to AgentShield

## Dev Environment Setup

```bash
git clone https://github.com/AdityaBelhekar/AgentShield
cd AgentShield
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,redis,otel]"
```

Optional Redis for integration and event-stream validation:

```bash
docker run -p 6379:6379 redis:7
```

## Code Rules — Non-Negotiable

□ Full type hints on all functions and methods  
□ Google-style docstrings on all classes and public methods  
□ Loguru only — never print() or logging module  
□ Custom exceptions only — never raise Exception(...)  
□ No hardcoded values — all from AgentShieldConfig  
□ Zero TODO comments in committed code  
□ ruff check: zero errors  
□ black --check: zero errors  
□ mypy --strict: zero errors  
□ Tests in /scratch/tests/ only — never committed, always gitignored  
□ One clean commit per phase/feature  
□ emit() must never raise to the caller  
□ Canary token values never stored in events or logs

## Running Checks Locally

```bash
ruff check agentshield/
black --check agentshield/
mypy agentshield/ --strict
```

All three must pass before opening a PR.

## Commit Format

Use one of the following commit styles:

- feat(scope): short description — longer summary if needed
- fix(scope): what was broken and how it's fixed
- docs(scope): what was documented
- refactor(scope): what changed and why

Examples:

- feat(phase-3B): add PromptInjectionDetector — 3-layer pattern+semantic+canary
- fix(detection): prevent emit() from propagating RedisConnectionError
- docs(readme): add threat coverage table and badge row

## Submitting a PR

Checklist before opening:

□ ruff, black, mypy all pass  
□ No /scratch/tests/ files staged  
□ CHANGELOG.md updated under [Unreleased]  
□ Commit message follows format above  
□ No auto-push — PR requires review

## Reporting Issues

Use GitHub Issues.
For security vulnerabilities: email directly, do not open a public issue.

## What AgentShield Will Never Do

- Modify agent behavior (only observe and block)
- Store raw prompt content (always hashed)
- Store canary token values
- Silently swallow exceptions from user code
- Require internet connectivity to function
