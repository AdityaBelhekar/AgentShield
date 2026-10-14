# Changelog

All notable changes to AgentShield will be documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [0.1.0] — 2026-04-05

### Added
- `shield()` entry point — wrap any LangChain agent in one line
- **Prompt Injection Detector** — 3-layer detection (pattern + semantic + canary)
- **Goal Drift Detector** — cosine distance with rolling average baseline
- **Tool Chain Escalation Detector** — forbidden sequence detection
- **Memory Poison Detector** — z-score anomaly detection
- **Agent DNA Fingerprinting** — 13-feature behavioral baseline per agent
- **Canary Injection System** — honeypot tokens with immediate blocking
- **Prompt Provenance Tracking** — taint analysis for all content origins
- **Cryptographic Audit Trail** — SHA-256 hash-chained tamper-proof JSONL log
- **Cross-detector correlation engine** — escalation logic across 6 detectors
- **PolicyEvaluator** — YAML-configurable policy with 5 actions (BLOCK/ALERT/FLAG/LOG/ALLOW)
- Built-in policies: `no_exfiltration`, `strict`, `monitor_only`
- **Inter-Agent Trust Graph** — monitors cross-agent message injection
- **FastAPI backend** — REST + WebSocket event stream
- **React dashboard** — live agent graph, alert panel, forensic trace (Cytoscape.js)
- **Red Team CLI** — `agentshield attack` + `agentshield certify`
- **Adapters** — LangChain, LlamaIndex, AutoGen, raw OpenAI/Anthropic API
- **Observability** — OpenTelemetry export, Slack + PagerDuty webhooks, Grafana dashboard, SIEM export
- Full MkDocs documentation site at https://AdityaBelhekar.github.io/AgentShield
- GitHub Actions CI (lint, typecheck, build-check on every push)
- GitHub Actions publish workflow (PyPI release on version tag)

---

## [Unreleased]

### V2 (on the `v2` branch)

#### Removed
- The 0.1.x runtime: `shield()`, detectors, adapters, interceptors, canary, provenance, DNA, events, audit chain, policies, red-team CLI and certify. Replaced stage by stage per [V2_STAGES.md](V2_STAGES.md).
- `backend/`, `agentshield-desktop/`, top-level `cli/`, Dockerfiles, `docker-compose.yml`, `Makefile`, `.env.example`.
- Slack, PagerDuty, SIEM, Prometheus and OpenTelemetry exporters (OpenTelemetry returns in stage 15).
- Generated API reference pages for removed modules.

#### Changed
- Core dependencies are now `pydantic` and `pyyaml` only.
- Version is read from `agentshield/__init__.py`.
- Tests live in `tests/` and run in CI on Python 3.11–3.13; lint and format use ruff.

### 0.1.x (on `main`)


#### Changed
- README, QUICKSTART and the docs home page no longer claim protections 0.1.x does not provide; each now carries an "experimental, not a security boundary" notice.
- Package classifier changed from Beta to Alpha.

#### Removed
- `security_audit_report.md`: it credited a `SENSITIVITY_SCAN` mechanism that does not exist in the code, and its harness is not in the repository.

#### Fixed
- `publish.yml` was invalid YAML, so no release could run.
- `mypy --strict` failures caused by redis-py 8 no longer declaring `Redis` as generic.

#### Planned
- V2 redesign, staged in [V2_STAGES.md](V2_STAGES.md). Findings that motivate it: [AGENTSHIELD_V2_REPORT.md](AGENTSHIELD_V2_REPORT.md).
