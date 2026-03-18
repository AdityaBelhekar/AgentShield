<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0D1117,100:00D4FF&height=200&section=header&text=AgentShield&fontSize=80&fontColor=ffffff&fontAlignY=38&desc=The%20security%20primitive%20the%20agent%20ecosystem%20is%20missing&descAlignY=65&descSize=18" width="100%"/>

<br/>

[![License: MIT](https://img.shields.io/badge/License-MIT-00D4FF.svg?style=for-the-badge)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-00D4FF.svg?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Version](https://img.shields.io/badge/Version-0.1.0--alpha-FF3B3B.svg?style=for-the-badge)](CHANGELOG.md)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-00FF88.svg?style=for-the-badge)](CONTRIBUTING.md)
[![Stars](https://img.shields.io/github/stars/AdityaBelhekar/AgentShield?style=for-the-badge&color=FFB800)](https://github.com/AdityaBelhekar/AgentShield/stargazers)

<br/>

```python
from agentshield import shield

protected = shield(your_agent, policy="no_exfiltration")
protected.run("Summarize this document")  # ✓ Fully protected
```

<br/>

> Built by **[Aditya Belhekar](https://github.com/AdityaBelhekar)**

</div>

---

## The Problem

AI agents are being deployed into production with almost no security layer.

They can be **prompt injected**. Their goals can be **hijacked**. Their memory can be **poisoned**. They can be chained into **exfiltrating data** without the developer ever knowing.

The ecosystem is building agents faster than it is securing them.

**AgentShield fixes that.**

---

## What It Does

AgentShield is a **pip-installable Python SDK** that wraps any AI agent and monitors its entire execution pipeline in real time — detecting and blocking attacks **without touching your agent code**.

```
┌─────────────────────────────────────────────────────────────┐
│                      YOUR AGENT CODE                         │
│                (LangChain / AutoGen / CrewAI)                │
└──────────────────────────┬──────────────────────────────────┘
                           │  shield()
┌──────────────────────────▼──────────────────────────────────┐
│                INTERCEPTOR LAYER                             │
│          Tool hooks │ LLM hooks │ Memory hooks               │
└──────────────────────────┬──────────────────────────────────┘
                           │  events
┌──────────────────────────▼──────────────────────────────────┐
│                 DETECTION ENGINE                             │
│   Injection │ Drift │ Chain │ Poison │ DNA │ Provenance      │
└──────────────────────────┬──────────────────────────────────┘
                           │  threats
┌──────────────────────────▼──────────────────────────────────┐
│           POLICY COMPILER + CRYPTOGRAPHIC AUDIT              │
│         YAML rules │ Hash-chained tamper-proof logs          │
└──────────────────────────┬──────────────────────────────────┘
                           │  Redis pub/sub
┌──────────────────────────▼──────────────────────────────────┐
│               REACT SECURITY CONSOLE                         │
│       Live graph │ Threat alerts │ Forensic trace            │
└─────────────────────────────────────────────────────────────┘
```

---

## Attack Vectors Defended

| Attack | How It Works | How AgentShield Stops It |
|--------|-------------|--------------------------|
| 🔴 **Prompt Injection** | Malicious instructions hidden in tool output or user input | Pattern matching + semantic similarity + canary tokens |
| 🔴 **Goal Drift** | Agent slowly deviates from original task | Embedding cosine distance from original task |
| 🔴 **Tool Chain Escalation** | read_file → read_file → send_report = data exfiltration | Forbidden sequence detection |
| 🔴 **Memory Poisoning** | Corrupting agent memory across sessions | Statistical z-score anomaly detection |
| 🟡 **Behavioral Anomalies** | Anything that deviates from normal for YOUR agent | Agent DNA fingerprinting |
| 🔴 **Inter-Agent Injection** | Agent A manipulating Agent B via shared memory | Provenance tracking across agent boundaries |

---

## What Makes This Different

<table>
<tr>
<td width="50%">

### 🧬 Agent DNA Fingerprinting
AgentShield learns what "normal" looks like for **your specific agent** over time. Behavioral deviations are detected even without known attack signatures — no labeled training data required.

</td>
<td width="50%">

### 🕵️ Canary Injection
Invisible honeypot tokens are silently embedded in agent context. If the LLM echoes them back, an active manipulation is detected with **near-zero false positives**.

</td>
</tr>
<tr>
<td width="50%">

### 🔍 Prompt Provenance Tracking
Every piece of text entering the LLM context is tagged with its **origin and trust level**. Content from untrusted URLs gets extra scrutiny before reaching the model.

</td>
<td width="50%">

### 🔐 Cryptographic Audit Trail
Every event is hash-chained to the previous one. **Tamper-evident logs** suitable for compliance, incident response, and legal defensibility.

</td>
</tr>
<tr>
<td width="50%">

### ⚔️ Red Team CLI
Attack your own agent before attackers do.
`agentshield redteam --agent ./my_agent.py`
Generates a full security report with bypass findings.

</td>
<td width="50%">

### 🌐 Multi-Framework Support
LangChain today. LlamaIndex, AutoGen, CrewAI, raw OpenAI and Anthropic API coming in v0.5.

</td>
</tr>
</table>

---

## Quickstart

```bash
pip install agentshield
```

```python
from agentshield import shield
from agentshield.config import AgentShieldConfig

# Works with your existing agent — zero changes to agent code
agent = your_existing_langchain_agent()

# Wrap it
protected = shield(agent, policy="no_exfiltration")

# Run it — fully monitored and protected
result = protected.run("Summarize the quarterly report")
```

### Run the full stack locally

```bash
git clone https://github.com/AdityaBelhekar/AgentShield
cd AgentShield
cp .env.example .env        # add your API keys
make docker-up              # Redis + backend + frontend
```

Open **http://localhost:5173** — live security console.

---

## Built-in Policies

| Policy | What It Does |
|--------|-------------|
| `no_exfiltration` | Blocks all read → send tool chain patterns |
| `strict` | Everything in no_exfiltration + lower drift threshold |
| `monitor_only` | Detects everything, blocks nothing. Safe for production rollout. |

Or write your own in YAML:

```yaml
version: "2.0"
agent_id: "customer-support-bot"

capabilities:
  tools:
    allowed: ["search_kb", "lookup_order", "send_email"]
    denied: ["read_file", "execute_code"]

on_threat:
  PROMPT_INJECTION:
    action: BLOCK
    notify: ["slack:#security-alerts"]
  GOAL_DRIFT:
    high: BLOCK
    medium: ALERT
```

---

## Project Roadmap

```
✅ Phase 0   — Foundation & tooling
🔄 Phase 1   — Event system & data models
⬜ Phase 2   — Interceptor layer (LangChain)
⬜ Phase 3   — Core detection engine
⬜ Phase 4   — Advanced detection (DNA, Canary, Provenance)
⬜ Phase 5   — Policy compiler
⬜ Phase 6   — Backend API + Redis bridge
⬜ Phase 7   — React security console
⬜ Phase 8   — Cryptographic audit trail
⬜ Phase 9   — Red Team CLI
⬜ Phase 10  — Multi-framework adapters
⬜ Phase 11  — Observability & integrations
⬜ Phase 12  — Docs, PyPI release, GitHub Actions
```

---

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first.

```bash
git clone https://github.com/AdityaBelhekar/AgentShield
pip install -e ".[dev]"
make lint && make typecheck
```

---

## Security

Found a vulnerability? **Do not open a public issue.**  
Report privately → belhekaraditya96@gmail.com  
See [SECURITY.md](SECURITY.md) for full policy.

---

## License

MIT © [Aditya Belhekar](https://github.com/AdityaBelhekar)

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:00D4FF,100:0D1117&height=100&section=footer" width="100%"/>

**If this helped you secure your agents, drop a ⭐**

[GitHub](https://github.com/AdityaBelhekar/AgentShield) · [Report Bug](https://github.com/AdityaBelhekar/AgentShield/issues) · [Request Feature](https://github.com/AdityaBelhekar/AgentShield/issues)

</div>
