[![PyPI](https://img.shields.io/pypi/v/agentshield-x?style=flat-square&color=black)](https://pypi.org/project/agentshield-x/)
[![Python](https://img.shields.io/badge/python-3.11%2B-black?style=flat-square)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-black?style=flat-square)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-live-black?style=flat-square)](https://AdityaBelhekar.github.io/AgentShield)

<br />

# AgentShield

**Runtime security for AI agents — experimental.**

> [!WARNING]
> **0.1.x is an experimental prototype. Do not use it as a security boundary.**
>
> An audit of 0.1.0 found that it does not block the attacks earlier versions of this README claimed it did. In particular, `read_file` → `send_email` exfiltration is **not blocked** under the `strict` or `no_exfiltration` policies, tools on the `strict` deny-list run on their first call, and LangGraph agents are not supported. Full findings, with reproductions: [AGENTSHIELD_V2_REPORT.md](AGENTSHIELD_V2_REPORT.md).
>
> A redesign (V2) is in progress: [V2_STAGES.md](V2_STAGES.md).

```python
from agentshield import shield

protected = shield(your_agent, policy="strict")
result = protected.run(user_input)
```

<br />

---

## What it is

AgentShield is a runtime security SDK for AI agents. It wraps an existing agent, observes LLM calls, tool calls and memory access, runs detectors over them, and raises an exception when the active policy decides to block.

It is not an agent. It is not a chatbot. It is meant to be a defensive layer — and 0.1.x does not yet deliver that reliably.

<br />

---

## Detectors in 0.1.x

| Threat | Approach | Status in 0.1.x |
| --- | --- | --- |
| Prompt injection | Substring signatures + embedding similarity | Blocks only under `strict`. Paraphrases, other languages and encodings get through; ordinary text is often flagged. |
| Goal drift | Cosine distance from the original task | Inactive through `shield()` — no original task is passed in. |
| Tool chain escalation | Tool-name sequence matching | Detected, but built-in policies downgrade it, so it is not blocked. |
| Memory poisoning | Pattern + z-score anomaly | Not evaluated in the audit. |
| Behavioral anomalies | Per-agent "DNA" baseline | Baseline is never established through `shield()`. |
| Inter-agent injection | Trust graph | Based on sender state, not message content. Not evaluated in the audit. |

<br />

---

## Install

```bash
pip install agentshield-x
```

The base install pulls in `sentence-transformers` (and therefore PyTorch).

> [!NOTE]
> 0.1.x publishes every event to Redis synchronously, with retries. **If no Redis server is reachable at `AGENTSHIELD_REDIS_URL` (default `redis://localhost:6379`), each event blocks for several seconds.** Run Redis locally when trying it out.

| Extra | When to use |
| --- | --- |
| `[redis]` | `hiredis` for faster Redis |
| `[otel]` | OpenTelemetry export |
| `[all]` | everything |

<br />

---

## Policies

```python
# Default. Records detections, never blocks.
protected = shield(agent, policy="monitor_only")
```

```python
# Intended to block exfiltration. In 0.1.x it does not — see the warning above.
protected = shield(agent, policy="no_exfiltration")
```

```python
# Most aggressive built-in. Blocks some prompt-injection strings; also blocks some ordinary requests.
protected = shield(agent, policy="strict")
```

```python
# Your own rules
protected = shield(agent, policy="./my_policy.yaml")
```

<br />

---

## Handling violations

```python
from agentshield import shield
from agentshield.exceptions import PolicyViolationError, PromptInjectionError

protected = shield(agent, policy="strict")

try:
    result = protected.run(user_input)
except PromptInjectionError as e:
    print(f"Injection blocked: {e}")
except PolicyViolationError as e:
    print(f"Policy violation: {e}")
```

<br />

---

## Integrations

Adapters exist for LangChain, LlamaIndex, AutoGen, and raw OpenAI / Anthropic clients. Framework detection is automatic; pass `framework=` to override.

Known limitations in 0.1.x:

- **LangGraph** agents are not detected, and forcing `framework="langchain"` does not intercept their tool calls.
- On LangChain agents that expose `.tools`, wrapping breaks `StructuredTool` calls on current `langchain-core`.
- Streaming output is not inspected.
- The OpenAI adapter only patches `chat.completions.create` and never sees tool execution.

<br />

---

## Experimental components

| Component | Status in 0.1.x |
| --- | --- |
| **Canary tokens** | Tokens are generated per session, but no adapter injects them into prompts, so they cannot trigger. |
| **Provenance tracking** | Content is tagged with a trust level, but no detector uses the tags. |
| **Audit trail** | SHA-256 hash chain. It is unkeyed, so it catches accidental corruption, not deliberate tampering. Kept in memory only unless `AGENTSHIELD_AUDIT_CHAIN_PATH` is set. |
| **Agent DNA fingerprinting** | See the detector table: the baseline is not established through `shield()`. |
| **Red-team CLI** | 30 payloads, of which 5 are run live; the other 25 are placeholders. |
| **Certify** | Produces a badge from a red-team report. Reflects only those 5 payloads. |

<br />

---

## Architecture

```
User Input
    │
    ▼
┌─────────────────────────────────────────────┐
│              AgentShield Runtime            │
│                                             │
│   LLM Hook ── Tool Hook ── Memory Hook      │
│                    │                        │
│            DetectionEngine                  │
│   ┌─────────────────────────────────────┐   │
│   │  Canary · DNA · Provenance          │   │
│   │  PromptInjectionDetector            │   │
│   │  GoalDriftDetector                  │   │
│   │  ToolChainDetector                  │   │
│   │  MemoryPoisonDetector               │   │
│   │  InterAgentMonitor                  │   │
│   └─────────────────────────────────────┘   │
│                    │                        │
│          Cross-Correlation Engine           │
│                    │                        │
│            PolicyEvaluator                  │
│                    │                        │
│         BLOCK · ALERT · FLAG · LOG          │
└─────────────────────────────────────────────┘
    │
    ▼
Agent continues — or PolicyViolationError raised
```

<br />

---

## Exception hierarchy

```
AgentShieldError
├── ConfigurationError
├── AdapterError
├── DetectionError
├── PolicyViolationError
│   ├── PromptInjectionError
│   ├── GoalDriftError
│   ├── MemoryPoisonError
│   ├── BehavioralAnomalyError
│   ├── InterAgentInjectionError
│   └── ToolCallBlockedError
│       └── PrivilegeEscalationError
├── CanaryError
├── DNAError
├── AuditChainError
└── ProvenanceError
```

<br />

---

## Red Team CLI

```bash
# List attack payloads
agentshield redteam list

# Run them against an agent factory (a callable returning a shielded agent)
agentshield redteam run myproject.agent:create_agent --policy strict --output report.json

# Turn a report into a certification badge
agentshield certify generate report.json --badge badge.svg
```

<br />

---

## Docs

[Documentation](https://AdityaBelhekar.github.io/AgentShield) · [Quickstart](./QUICKSTART.md) · [SDK Reference](./docs/sdk-reference.md) · [Contributing](./CONTRIBUTING.md) · [0.1.0 audit](./AGENTSHIELD_V2_REPORT.md)

<br />

---

MIT License · Built by [Aditya Belhekar](https://github.com/AdityaBelhekar)

AgentShield is and will always remain free and open-source.
