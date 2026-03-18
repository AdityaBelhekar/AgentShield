# 🛡️ AgentShield

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)
![Version](https://img.shields.io/badge/version-0.1.0--alpha-orange.svg)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)

> **The security primitive the agent ecosystem is missing.**

AgentShield is a production-grade, open-source Python SDK that wraps
any AI agent and monitors its entire execution pipeline in real time —
detecting and blocking attacks without modifying your agent code.

## The Problem

AI agents are being deployed into production with almost no security
layer. They can be prompt injected, goal hijacked, have their memory
poisoned, or be manipulated into exfiltrating data through tool chains.
The ecosystem is building fast. Security is an afterthought.

## The Solution

```python
from agentshield import shield

# Your existing agent — zero changes
agent = create_your_langchain_agent()

# 4 lines. Fully protected.
protected = shield(agent, policy="no_exfiltration")
result = protected.run("Summarize this document")
```

## What AgentShield Defends Against

| Attack Vector         | Detection Method              | Action |
|-----------------------|-------------------------------|--------|
| Prompt Injection      | Pattern + semantic analysis   | Block  |
| Goal Drift            | Embedding cosine distance     | Block  |
| Tool Chain Escalation | Sequence pattern matching     | Block  |
| Memory Poisoning      | Statistical anomaly detection | Block  |
| Behavioral Anomalies  | DNA fingerprinting            | Flag   |
| Inter-Agent Injection | Provenance tracking           | Block  |

## What Makes AgentShield Different

**Prompt Provenance Tracking** — Every piece of text in the agent's
context is tagged with its origin. Tool output from an untrusted
URL gets extra scrutiny before reaching the LLM.

**Canary Injection** — Invisible honeypot tokens are silently embedded
in context. If the LLM echoes them back, an active manipulation
attempt is detected with near-zero false positives.

**Agent DNA Fingerprinting** — AgentShield learns what "normal"
looks like for YOUR agent over time. Behavioral deviations are
detected even without known attack signatures.

**Cryptographic Audit Trail** — Every event is hash-chained.
Tamper-evident logs suitable for compliance and incident response.

**Red Team CLI** — Attack your own agent before attackers do.
`agentshield redteam --agent ./my_agent.py`

## Quickstart

```bash
git clone https://github.com/AdityaBelhekar/AgentShield
cd AgentShield
cp .env.example .env  # add your API keys
make docker-up        # starts Redis + backend + frontend
```

Open http://localhost:5173 for the security console.

## Architecture

```text
┌─────────────────────────────────────────────────────────┐
│                    YOUR AGENT CODE                       │
│              (LangChain / AutoGen / CrewAI)              │
└──────────────────────┬──────────────────────────────────┘
                       │  shield()
┌──────────────────────▼──────────────────────────────────┐
│              AGENTSHIELD INTERCEPTOR LAYER               │
│         Tool hooks │ LLM hooks │ Memory hooks            │
└──────────────────────┬──────────────────────────────────┘
                       │  events
┌──────────────────────▼──────────────────────────────────┐
│               DETECTION ENGINE                           │
│  Injection │ Drift │ Chain │ Poison │ DNA │ Provenance   │
└──────────────────────┬──────────────────────────────────┘
                       │  threats
┌──────────────────────▼──────────────────────────────────┐
│           POLICY COMPILER + AUDIT CHAIN                  │
│         YAML rules │ Hash-chained tamper-proof logs      │
└──────────────────────┬──────────────────────────────────┘
                       │  Redis pub/sub
┌──────────────────────▼──────────────────────────────────┐
│           REACT SECURITY CONSOLE                         │
│    Live graph │ Threat alerts │ Forensic trace           │
└─────────────────────────────────────────────────────────┘
```

## Supported Frameworks

| Framework      | Status      |
|----------------|-------------|
| LangChain      | ✅ Phase 2  |
| LlamaIndex     | 🔜 Phase 10 |
| AutoGen        | 🔜 Phase 10 |
| CrewAI         | 🔜 Phase 10 |
| Raw OpenAI API | 🔜 Phase 10 |
| Anthropic API  | 🔜 Phase 10 |

## Contributing

See CONTRIBUTING.md

## Security

See SECURITY.md for how to report vulnerabilities.

## License

MIT — see LICENSE