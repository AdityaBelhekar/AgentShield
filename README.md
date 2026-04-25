[![PyPI](https://img.shields.io/pypi/v/agentshield-x?style=flat-square&color=black)](https://pypi.org/project/agentshield-x/)
[![Python](https://img.shields.io/badge/python-3.11%2B-black?style=flat-square)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-black?style=flat-square)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-live-black?style=flat-square)](https://AdityaBelhekar.github.io/AgentShield)

<br />

# AgentShield

**The security primitive the agent ecosystem is missing.**

AI agents can search the web, run code, read files, call APIs, and talk to other agents.  
None of that is protected by default.  
AgentShield fixes that.

```python
from agentshield import shield

protected = shield(your_agent, policy="strict")
result = protected.run(user_input)
```

One line. Every threat covered.

<br />

---

## What it does

AgentShield is a runtime security SDK. It wraps your existing agent — whatever framework you use — and intercepts execution before unsafe behavior reaches your tools, memory, or external channels.

It is not an agent. It is not a chatbot. It is a defensive layer.

The problem it solves: agent frameworks were built for capability, not adversarial resilience. Prompt injection, goal drift, tool chain escalation — none of these have a standard defense. AgentShield is that standard.

<br />

---

## Threat coverage

| Threat | Detection | Default Action | Detector |
| --- | --- | --- | --- |
| Prompt Injection | Pattern + semantic + canary (3-layer) | BLOCK | `PromptInjectionDetector` |
| Goal Drift | Cosine distance + rolling average | ALERT | `GoalDriftDetector` |
| Tool Chain Escalation | Forbidden sequence detection | BLOCK | `ToolChainDetector` |
| Memory Poisoning | Z-score anomaly | ALERT | `MemoryPoisonDetector` |
| Behavioral Anomalies | Agent DNA fingerprinting | FLAG | `DNAAnomalyScorer` |
| Inter-Agent Injection | Provenance + trust graph | BLOCK | `InterAgentMonitor` |

<br />

---

## Proven in red team testing

10 hard attacks. 0 breaches.

Tested on a live LangGraph agent with tools: web search, code execution, file ops, shell commands.  
Attack suite: indirect injection, base64 obfuscation, multi-turn social engineering, memory poisoning, self-replication, chained droppers, combined attacks.

| Attack | Result |
| --- | --- |
| Indirect Prompt Injection | BLOCKED |
| Multi-Turn Social Engineering | PROTECTED |
| Base64 Encoded Payload | BLOCKED |
| Memory Poisoning via `.agentrc` | PROTECTED |
| Tool Chain Exfiltration | BLOCKED |
| Roleplay Jailbreak | BLOCKED |
| Self-Replication / Agent Backdoor | BLOCKED |
| Chained Dropper (2-stage) | PROTECTED |
| Prompt / System Leak | PROTECTED |
| Combined Everything Attack | BLOCKED |

Full report: [`security_audit_report.md`](./security_audit_report.md)

<br />

---

## Install

```bash
pip install agentshield-x
```

| Extra | When to use |
| --- | --- |
| `[redis]` | pub/sub + live dashboard |
| `[otel]` | OpenTelemetry export |
| `[all]` | full feature set |

<br />

---

## Policies

```python
# Observe only — zero risk, perfect for first run
protected = shield(agent, policy="monitor_only")
```

```python
# Block exfiltration, flag injection
protected = shield(agent, policy="no_exfiltration")
```

```python
# Maximum enforcement
protected = shield(agent, policy="strict")
```

```python
# Bring your own rules
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

Works with whatever you're already using.

```python
# LangChain
protected = shield(langchain_agent, policy="strict")

# LlamaIndex
protected = shield(llamaindex_agent, policy="strict")

# AutoGen
protected = shield(autogen_agent, policy="strict")

# OpenAI
protected = shield(openai_client, policy="strict")

# Anthropic
protected = shield(anthropic_client, policy="strict")
```

<br />

---

## Original research

These don't exist anywhere else.

**Agent DNA Fingerprinting** — builds a per-agent behavioral baseline from clean sessions. Flags statistically meaningful deviations in real time.

**Canary Injection** — plants cryptographic honeypot tokens in agent context. If they appear in output, instruction hijack is confirmed with near-zero ambiguity.

**Prompt Provenance Tracking** — tags every piece of context by trust origin (`TRUSTED` / `INTERNAL` / `EXTERNAL` / `UNTRUSTED`) before it reaches the model.

**Cryptographic Audit Trail** — SHA-256 hash-chains every security event into tamper-evident JSONL. Forensic-grade. Verifiable after the fact.

**Red Team CLI** — runs curated adversarial scenarios against live agents, emits structured security reports.

**AgentShield Certify** — converts red team outcomes into reproducible certification artifacts and badge output.

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
# List available attack scenarios
agentshield attack list

# Run a specific scenario against your agent
agentshield attack run --scenario prompt_injection --target my_agent.py

# Generate a certification report
agentshield certify --agent my_agent.py --policy strict
```

<br />

---

## Docs

[Full documentation](https://AdityaBelhekar.github.io/AgentShield) · [Quickstart](./QUICKSTART.md) · [SDK Reference](./docs/sdk-reference.md) · [Contributing](./CONTRIBUTING.md)

<br />

---

MIT License · Built by [Aditya Belhekar](https://github.com/AdityaBelhekar)

AgentShield is and will always remain free and open-source.
