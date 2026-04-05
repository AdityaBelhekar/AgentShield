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

### Planned
- V1.1: ML models trained on HackAPrompt dataset (600k+ examples)
- ASIN (AgentShield Intelligence Network) — opt-in anonymized telemetry + monthly model updates
- Async-native runtime (arun() for all interceptors)
- LangGraph adapter
