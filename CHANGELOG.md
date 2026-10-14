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

### Changed
- README, QUICKSTART and the docs home page no longer claim protections 0.1.x does not provide; each now carries an "experimental, not a security boundary" notice.
- Package classifier changed from Beta to Alpha.

### Removed
- `security_audit_report.md`: it credited a `SENSITIVITY_SCAN` mechanism that does not exist in the code, and its harness is not in the repository.

### Fixed
- `publish.yml` was invalid YAML, so no release could run.
- `mypy --strict` failures caused by redis-py 8 no longer declaring `Redis` as generic.

### Planned
- V2 redesign, staged in [V2_STAGES.md](V2_STAGES.md). Findings that motivate it: [AGENTSHIELD_V2_REPORT.md](AGENTSHIELD_V2_REPORT.md).
