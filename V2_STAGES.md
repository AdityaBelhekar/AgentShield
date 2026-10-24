# AgentShield V2 — daily stages

One stage per day, 19 stages, three releases. Design rationale and the findings referenced as C1–C12 are in [AGENTSHIELD_V2_REPORT.md](AGENTSHIELD_V2_REPORT.md).

**Progress:** stages 0–11 done (2026-10-24). Next: stage 12.

**Rules**

- Stage 0 lands on `main`. Everything else lands on a `v2` branch until the 0.2.0 release.
- A stage is finished only when its **Done when** check passes in CI. If it doesn't, the next day finishes it; stages are never stacked.
- Every stage leaves at least one test behind. Each V1 finding gets a regression test in the stage that fixes it.
- Core stays dependency-light: anything beyond `pydantic` and `pyyaml` goes in an extra.

**Needs you** marks stages that can't finish without a decision, a credential or a publish action from you.

| # | Stage | Release |
|---|---|---|
| 0 | Honesty patch | — |
| 1 | Clean slate | |
| 2 | Types and sessions | |
| 3 | Policy manifest | |
| 4 | Enforcement engine | |
| 5 | Tool wrapper, approvals, end-to-end demo | |
| 6 | Argument checks and secret egress scan | |
| 7 | LangChain / LangGraph middleware | |
| 8 | Result labelling, spotlighting, canary leak check | |
| 9 | Signed audit log and verify CLI | |
| 10 | AgentDojo harness, one suite | |
| 11 | Measure, fix, publish numbers | |
| 12 | Release | **0.2.0** |
| 13 | MCP gateway (stdio) | |
| 14 | MCP hardening | |
| 15 | OpenTelemetry spans | |
| 16 | Flow-graph viewer | |
| 17 | Optional detector plugin | |
| 18 | Docs site, threat model, release | **0.3.0** |

---

## Stage 0 — Honesty patch (on `main`)

- **Build:** Remove from the README: "10 hard attacks. 0 breaches", "Every threat covered", "These don't exist anywhere else", the base64 row, the CLI commands that don't exist. Add an alpha / "not a security boundary" notice. Delete or caveat `security_audit_report.md`. Fix the code-fence indentation in `publish.yml`.
- **Done when:** `publish.yml` parses as YAML; README makes no claim the repo can't reproduce; CI is green.
- **Needs you:** decide whether to yank `agentshield-x 0.1.0` from PyPI or ship a `0.1.1` with the notice. Yanking is done from your PyPI account.

---

## Milestone A — the core works end to end in plain Python

### Stage 1 — Clean slate

- **Build:** Create the `v2` branch. Delete everything on the report's cut list plus the V1 runtime path (`runtime.py`, `detection/`, `adapters/`, `events/emitter.py`, `canary/`, `provenance/`, `cli/certify*`, attack library, Dockerfiles). Keep `exceptions.py`, `docs/`, CI. Cut `pyproject.toml` dependencies to `pydantic` and `pyyaml`. Move tests to `tests/`, point `testpaths` at it, run `pytest` and `ruff` in CI on 3.11–3.13.
- **Done when:** `pip install -e .` pulls no torch, redis or langchain; `import agentshield` adds under half a second on top of importing pydantic itself (pydantic's own import time varies several-fold between machines); CI runs a real `pytest` job.
- **Fixes:** C11, the packaging findings.

### Stage 2 — Types and sessions

- **Build:** `ToolCall`, `Decision` (`allow` / `deny` / `ask`), labels (`untrusted`, `confidential`, `external`), and `Session` held in a `contextvar` with its taint set and call counters. `Shield.session(user=, task=)` as a context manager, sync and async.
- **Done when:** a test runs two sessions concurrently in threads and in asyncio tasks and neither sees the other's taint or history.
- **Fixes:** C9.

### Stage 3 — Policy manifest

- **Build:** YAML → pydantic models: per-tool labels and `deny`, `unlabelled_tools` default, `flows`, `limits`. Exact tool-name matching only. A content hash of the loaded policy for later audit records. Two built-ins: `monitor` and `strict` (default-deny for unlabelled tools).
- **Done when:** valid policies load; a typo'd key, unknown label or unknown action is rejected with a message naming the bad field.
- **As built:** tools declare a single `labels:` list (`untrusted`, `confidential`, `external`) rather than the report's `source`/`sensitivity`/`sink` sketch; flows match on `session_has`, `tool_has` and `tool`; built-ins compose via `extends:`. Syntax reference: the docstring at the top of `agentshield/policy.py`.

### Stage 4 — Enforcement engine

- **Build:** `engine.check(call) -> Decision`, evaluated on **every** call in this order: deny-list, unlabelled default, flow rules against session taint, limits. `engine.record(call, result)` updates taint from the tool's labels. Any internal error returns `deny`.
- **Done when:** a seeded random-sequence test (a few thousand generated call sequences) never sees `allow` for a `deny: true` tool, and never sees `allow` for an `external` tool in a session holding both `untrusted` and `confidential`. Plus named regressions: denied tool blocked on its first call; `read_file → send_email` blocked.
- **Fixes:** C1, C2.

### Stage 5 — Tool wrapper, approvals, end-to-end demo

- **Build:** `shield.tool(name)` wrapper for plain sync and async callables: check before the call, record after. An approval handler for `ask` (default: raise `ApprovalRequired`; a terminal prompt handler is included). `examples/exfil_demo.py`: a scripted "model" that obeys an instruction hidden in a fetched page and tries to email a secret. No LLM or API key needed.
- **Done when:** the demo shows the email blocked, and a test asserts the `send_email` function body never ran.

### Stage 6 — Argument checks and secret egress scan

- **Build:** Per-tool argument rules: path deny-globs, URL domain allow-lists, regex denies. A secret scan on arguments going to `external` tools (known key prefixes and private-key headers). Reading a path matching a sensitive glob raises the session's `confidential` taint.
- **Done when:** tests cover `read_file("~/.ssh/id_rsa")` denied, `web_fetch` to a non-allow-listed host denied, and an AWS-style key in an outbound argument denied — while the same tools with benign arguments pass.
- **Fixes:** the "no detector looks at tool arguments" gap in C6.

---

## Milestone B — real agents and evidence → 0.2.0

### Stage 7 — LangChain / LangGraph middleware

- **Build:** `shield.langchain()` returning an agent middleware that routes every tool call through the engine, sync and async. Lives behind a `[langchain]` extra. Uses the framework's own tool-call hook, no attribute patching.
- **Done when:** with a real compiled LangGraph agent and a fake chat model: a denied tool never executes, an allowed tool returns its normal result, and the same holds when the agent is streamed.
- **Fixes:** C4, C5.
- **As built:** against `langchain` 1.4.7 / `langchain-core` 1.7.0, the hook is `AgentMiddleware.wrap_tool_call(request, handler)` with `awrap_tool_call` for async; the tests drive a real compiled graph with a scripted chat model for invoke, stream, ainvoke and astream.
- **Risk:** the middleware hook signature must be checked against the installed LangChain version on the day; may spill.

### Stage 8 — Result labelling, spotlighting, canary leak check

- **Build:** Results from `untrusted` tools are wrapped in explicit data delimiters before going back to the model. A random per-session marker for the system prompt, with a check that it never appears in outbound tool arguments or final output.
- **Done when:** tests show an untrusted result arrives delimited, and a tool call whose arguments contain the marker is denied.
- **Fixes:** the canary half of C3, done as a leak detector.
- **As built:** `shield.system_prompt(text)` appends the marker instruction; the engine denies a call whose arguments contain the marker even when unlabelled tools are allowed; `shield.check_output(text)` covers the final answer. Delimiters use a per-result nonce so fetched content cannot close the block early.

### Stage 9 — Signed audit log and verify CLI

- **Build:** Append-only JSONL of every decision. Each record's hash covers the previous hash and all of its own fields. Signed checkpoints. On restart, resume from the file's tail. Redact before hashing. `agentshield audit verify <file>` shipped in the wheel.
- **Done when:** three tests pass — a restart continues the same chain; deleting a record and re-hashing fails verification; verification still passes after 50,000 records.
- **Fixes:** C8.
- **As built:** records are canonical JSON with `seq`, timestamps, session/user/task, policy digest, redacted arguments, verdict, rule and reason. The header carries the Ed25519 public key and checkpoint interval; verification needs no private key. The whole file can still be rewritten by someone who replaces the header key too, so the public key should be anchored outside the file when that threat matters (external anchoring is out of scope for this release).

### Stage 10 — AgentDojo harness, one suite

- **Build:** An adapter that runs AgentDojo's agent with tool execution routed through the engine, and a policy manifest labelling every tool in the smallest suite. Runs shielded and unshielded.
- **Done when:** one command produces utility, utility-under-attack and attack-success-rate for both configurations on a small subset.
- **Needs you:** an LLM API key and a spending limit. Benchmark runs make many model calls.
- **Risk:** AgentDojo's pipeline API has to be learned on the day; may spill.
- **As built:** `agentshield/bench.py` subclasses AgentDojo's `FunctionsRuntime` so every tool call goes through the engine, and the scripted mode drives the real suite, environment and task checkers without a model. `agentshield bench` defaults to scripted mode; `--model` uses an AgentDojo pipeline and attack. `agentshield/policies/agentdojo-banking.yaml` labels all 11 tools. Approval defaults to deny because there is no human in the loop. The full banking suite is in CI, not only in the tests.

### Stage 11 — Measure, fix, publish numbers

- **Build:** Run the full suite from stage 10. Read every failure: missed attacks become policy or engine fixes with regression tests; blocked legitimate tasks become policy tuning. Add `agentshield bench` as the single entry point. Put the results table in the README with commit hash, model and date.
- **Done when:** the README table is reproducible from `agentshield bench` at that commit.
- **Fixes:** C10. This replaces the red-team suite and the certification badge.
- **As built:** the first full run left 14 of 144 injections alive: every `send_money` injection after `user_task_0` or `user_task_13` read a file, because the session had untrusted data but no confidential data, so the lethal-trifecta flow did not match. Added an `untrusted-to-external` flow (ask) with a regression test; that is the only policy change. The second run: utility 43.75% (7/16), utility-under-attack 43.75%, attack success rate 0%, 296 calls blocked and 296 approvals. The cost is two legitimate tasks (`user_task_0`, `user_task_13`), which the policy cannot distinguish from the attack. Numbers are scripted worst-case, not a model; `--model` is the real-model path and needs an API key. README table measured at `11688c7`.

### Stage 12 — Release 0.2.0

- **Build:** README and quickstart rewritten for the V2 API. Changelog. A short "what this does not protect against" section. Merge `v2` into `main`.
- **Done when:** a clean virtualenv can `pip install` the built wheel and run the stage 5 demo.
- **Needs you:** your go-ahead before the tag is pushed, since that publishes to PyPI.

---

## Milestone C — gateway, visibility, extras → 0.3.0

### Stage 13 — MCP gateway (stdio)

- **Build:** `agentshield gateway --policy p.yaml -- <server command>`: starts the downstream MCP server, proxies the protocol, and passes every `tools/call` through the engine. One session per client connection. Behind an `[mcp]` extra, built on the official MCP SDK.
- **Done when:** against a small fixture MCP server, a denied tool call returns an error to the client and the downstream tool is never invoked; allowed calls round-trip unchanged.
- **Risk:** largest unknown in the plan; may spill.

### Stage 14 — MCP hardening

- **Build:** A lockfile of tool-description hashes written on first sight; a changed description becomes `ask` or `deny`. A server allow-list. Draft manifest generation from a server's tool list, with its annotations as untrusted hints.
- **Done when:** a fixture server that changes a tool description between runs is caught.

### Stage 15 — OpenTelemetry spans

- **Build:** One span event per decision using the GenAI semantic conventions, behind an `[otel]` extra. Export is asynchronous; with the extra absent it is a no-op.
- **Done when:** a test with an in-memory exporter sees the decision attributes, and a test with a failing exporter shows tool calls are unaffected.
- **Fixes:** C7's "telemetry blocks the agent" class of problem.

### Stage 16 — Flow-graph viewer

- **Build:** `agentshield ui <audit.jsonl>` writes one self-contained HTML file showing a session as a graph: sources, the model, attempted tool calls, and blocked edges in red.
- **Done when:** the stage 5 demo's audit file renders with the blocked `send_email` edge visible.

### Stage 17 — Optional detector plugin

- **Build:** A detector interface whose output can only add taint or upgrade `allow` to `ask`. One classifier implementation that chunks long inputs and runs without torch, behind a `[classifier]` extra, with a time limit.
- **Done when:** a test proves a detector cannot turn a `deny` into an `allow`; an injection buried in a long document is flagged; classifier numbers on a public injection set and a benign set are added to `agentshield bench`.
- **Needs you:** pick the model on the day; licence and download terms differ between candidates.

### Stage 18 — Docs site, threat model, release 0.3.0

- **Build:** Docs site rewritten for V2. A threat model page stating what is and isn't in scope, with coverage mapped to the OWASP agentic list. `SECURITY.md` updated.
- **Done when:** the docs build has no page describing a removed feature, and the wheel installs and runs both demos from a clean virtualenv.
- **Needs you:** go-ahead before the tag is pushed.

---

## Deliberately left out

Add these only when someone asks for them: HTTP transport for the gateway, a second framework integration, value-level taint tracking, an LLM-judge detector, multi-agent identity, a hosted dashboard, external anchoring of audit checkpoints.
