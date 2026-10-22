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

#### Added
- Argument checks (stage 6): a tool's manifest can name an argument and set `deny_glob`, `sensitive_glob`, `allow_domains` or `deny_regex`. Violations deny the call before the tool runs. A `sensitive_glob` match does not deny — it adds `confidential` taint to the session after the call, for the flow rules to see.
- Secret egress scan (stage 6): arguments going to a tool labelled `external` are checked for credential-shaped values (AWS access keys, private-key headers, GitHub, Slack, Google, Stripe, OpenAI and Anthropic key formats). The denial names the credential type, never the value.
- `Shield.tool(name)` (stage 5): wraps a plain sync or async callable so every call is checked before it runs and recorded after. Arguments are bound to the function's parameter names, so a policy can match them. Denied calls raise `PolicyViolationError`; the callable's body never runs.
- Approvals for `ask` decisions (stage 5): `Shield(..., approval=handler)` receives the `ToolCall` and `Decision` and returns whether to allow that one call. The default raises `ApprovalRequired`; `terminal_approval` prompts on the terminal. An approval never changes the policy or clears session taint.
- `examples/exfil_demo.py`: a scripted agent that follows an instruction in a fetched page, reads a secret and tries to email it. It shows the call blocked before `send_email` runs, with no LLM or API key.
- `EnforcementEngine` (stage 4): `check(call)` evaluates every tool call in order — deny-list, unlabelled default, flow rules against session taint, then limits — and `record(call, result)` updates taint and counters. Fail-closed: an internal error returns `deny`. `monitor` mode reports the decision it would have enforced and returns `allow`. `Shield.engine` exposes it.
- `Shield.session(user=, task=)`: a sync/async context manager that scopes one agent run. The current session lives in a `ContextVar`, so concurrent threads and asyncio tasks are isolated while work spawned inside a session shares it (stage 2).
- Policy manifest (`agentshield.policy`, stage 3): YAML or dict validated into immutable models — per-tool `labels` and `deny`, `unlabelled_tools` default, `flows` (deny/ask on session taint × tool), `limits`. Exact tool-name matching. Built-ins `strict` and `monitor`, composable with `extends:`. `Policy.digest` is a SHA-256 of the effective policy, stable across processes. Unknown keys, labels, actions, undeclared flow tools and duplicate YAML keys are rejected with the offending field named.
- `Shield(policy)` / `Shield.from_policy(source)`; `Shield()` defaults to `strict`.
- Core types: `ToolCall`, `Decision`, `Verdict` (`allow` / `deny` / `ask`), `Label` (`untrusted` / `confidential` / `external`), `Session` (stage 2).

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
