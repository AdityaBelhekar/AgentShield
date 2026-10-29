# Changelog

All notable changes to AgentShield will be documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [Unreleased]

### Added
- `agentshield gateway --policy p.yaml -- <server command>`: a stdio MCP proxy that checks
  every `tools/call`. Denied and `ask` calls get a tool error and never reach the server;
  other messages pass through unchanged. Malformed lines, duplicate JSON keys and batches
  containing `tools/call` are refused rather than forwarded.

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

## [0.2.0] — 2026-10-24

0.2.0 is a ground-up rewrite. The detector stack, runtime wrapper and red-team CLI are gone;
in their place is a deterministic reference monitor for tool calls, a policy manifest, an
approval path and a tamper-evident audit log. Read the [README](README.md) for the guarantee
and, more importantly, for [what it does not protect against](README.md#what-this-does-not-protect-against).

### Added

- **AgentDojo benchmark** (stages 10–11): `agentshield bench` runs AgentDojo's banking suite
  (16 user tasks × 9 injection tasks) with every tool call through the engine. The default
  scripted mode needs no model or API key and executes the ground-truth user and injection
  calls — the worst case for the policy. `--model` runs a real AgentDojo pipeline and attack.
  The report carries the suite version, AgentDojo version, commit, date and every call's
  verdict; `--json`, `--markdown` and `--out` are available. Added the `[bench]` extra and a
  CI job that runs the full suite. On the banking policy the shielded configuration reaches
  0.0% attack success rate (from 100% unshielded), at 43.8% utility; the README table is
  reproducible at commit `11688c7`.
- **Untrusted-to-external flow** (stage 11): the first full benchmark left 14 of 144
  injections alive because two tasks read an injected file and then sent money or changed
  user info with no confidential data in the session. The banking policy now answers `ask`
  for any external sink once the session has untrusted data, with a regression test. This is
  a policy fix, not an engine change; the cost is two legitimate tasks that the label-level
  model cannot tell apart from the attack.
- **Rewritten README and quickstart** for the 0.2.0 API, including the benchmark table, the
  policy reference, the approval and audit paths, and a "what this does not protect against"
  section.
- Signed audit log (stage 9): `AuditLog` writes one JSON object per decision to an append-only, thread-safe JSONL file. Each record's SHA-256 covers the previous record's hash and every one of its own fields; Ed25519 checkpoints sign the head every N records. Reopening the file resumes the same chain, and appending to a signed log requires the same key. Arguments, task text and reasons are redacted before hashing. Pass it with `Shield.from_policy(..., audit=AuditLog(path, key=...))`; `Shield.close()` writes the final checkpoint. In `[audit]` extra.
- `agentshield audit verify <file>` (stage 9), shipped as a console script and as `python -m agentshield`, recomputes the chain and every checkpoint signature; `--json` prints the report. `agentshield audit keygen --out key.pem` creates an Ed25519 private key.
- Result labelling and spotlighting (stage 8): a string result from a tool labelled `untrusted` is wrapped in `<<UNTRUSTED_DATA:nonce>>` delimiters with a warning that it is data, not instructions, before it reaches the model. The nonce is random per result, so content cannot forge the closing delimiter. Applies to `shield.tool(...)` and to the LangChain middleware's `ToolMessage`.
- Canary leak check (stage 8): every session gets a random `agentshield-canary-…` marker. `shield.system_prompt(text)` appends the instruction that plants it, the engine denies any tool call whose arguments contain it (`rule="canary"`), and `shield.check_output(text)` raises `CanaryLeakError` if the final answer leaks it.
- LangChain / LangGraph middleware (stage 7): `shield.langchain()` returns agent middleware that routes every tool call through the engine using the framework's `wrap_tool_call` hook, sync and async. Pass it to `create_agent(..., middleware=[...])`; `invoke`, `stream`, `ainvoke` and `astream` are covered. Denied calls raise before the tool body runs. Lives behind the `[langchain]` extra.
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

### Removed
- The 0.1.x runtime: `shield()`, detectors, adapters, interceptors, canary, provenance, DNA, events, audit chain, policies, red-team CLI and certify. Replaced stage by stage per [V2_STAGES.md](V2_STAGES.md).
- `backend/`, `agentshield-desktop/`, top-level `cli/`, Dockerfiles, `docker-compose.yml`, `Makefile`, `.env.example`.
- Slack, PagerDuty, SIEM, Prometheus and OpenTelemetry exporters (OpenTelemetry returns in stage 15).
- Generated API reference pages for removed modules.

### Changed
- Core dependencies are now `pydantic` and `pyyaml` only.
- Version is read from `agentshield/__init__.py`; this release is `0.2.0`.
- Tests live in `tests/` and run in CI on Python 3.11–3.13; lint and format use ruff.

## [0.1.x] — never released


#### Changed
- README, QUICKSTART and the docs home page no longer claim protections 0.1.x does not provide; each now carries an "experimental, not a security boundary" notice.
- Package classifier changed from Beta to Alpha.

#### Removed
- `security_audit_report.md`: it credited a `SENSITIVITY_SCAN` mechanism that does not exist in the code, and its harness is not in the repository.

#### Fixed
- `publish.yml` was invalid YAML, so no release could run.
- `mypy --strict` failures caused by redis-py 8 no longer declaring `Redis` as generic.
