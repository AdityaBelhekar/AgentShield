# Contributing to AgentShield

## Setup

git clone https://github.com/AdityaBelhekar/AgentShield
cd AgentShield
pip install -e ".[dev]"
cp .env.example .env

## Branch naming

feat/your-feature-name
fix/bug-description
chore/task-description
docs/what-you-documented

## Commit format

type(scope): description

Examples:
  feat(detection): add multilingual injection detector
  fix(emitter): handle Redis timeout on batch publish
  docs(policy): add YAML policy examples

## PR checklist

- [ ] make lint passes (zero errors)
- [ ] make typecheck passes (zero errors)
- [ ] Tests written for new code
- [ ] CHANGELOG.md updated
- [ ] Docstrings on all new public functions