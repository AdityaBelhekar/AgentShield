# 🛡️ AgentShield

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-00D4FF.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.11+-00D4FF.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/Version-0.1.0-00D4FF.svg)](https://github.com/AdityaBelhekar/AgentShield/releases)
[![AMD ROCm](https://img.shields.io/badge/AMD-ROCm%20Accelerated-FF3B3B.svg)](https://rocm.amd.com/)
[![Build](https://img.shields.io/badge/Build-Passing-00FF88.svg)]()

**The only runtime that secures AI agents from the inside.**

*Real-time security monitoring, threat detection, and forensic audit trails —
wrapped around any LangChain, AutoGen, or CrewAI agent in 4 lines of code.*

[Quickstart](#quickstart) · [How It Works](#how-it-works) · [Attack Vectors](#what-it-defends-against) · [Architecture](#architecture) · [Docs](docs/quickstart.md)

</div>

---

## The Problem

AI agents today have tool access, memory, and full autonomy — but **zero security monitoring at the execution level**.

When an agent reads a malicious document, gets its goal hijacked, or chains tools in an unauthorized sequence — **nobody sees it happening**.

```
Agent reads malicious PDF
  → Hidden instructions override original task
    → Agent exfiltrates sensitive data via send_report
      → Nobody noticed. No alert. No log. No trace.
```

AgentShield fixes this.

---

## Quickstart

```bash
pip install agentshield
```

```python
from agentshield import shield

# Your existing agent — unchanged
agent = your_langchain_agent

# Wrap it in one line
secured = shield(agent, tools=tools, policy="no_exfiltration",
                 original_task="Summarize these documents")

# Run it — now fully protected
secured.run("Summarize these documents")  # ✓ Monitored
                                          # ✓ Threats blocked
                                          # ✓ Audit log generated
```

That's it. No changes to your agent code. No proxy. No API gateway.
AgentShield hooks directly into the execution internals.

---

## What It Defends Against

| # | Attack Vector | Description |
|---|--------------|-------------|
| 01 | **Indirect Prompt Injection** | Malicious instructions hidden inside documents, webpages, or retrieved data the agent processes |
| 02 | **Tool Poisoning** | Manipulating the agent into making unauthorized or malicious tool calls |
| 03 | **Goal Hijacking** | Gradually shifting the agent's objective away from its original task across multi-turn conversations |
| 04 | **Memory Poisoning** | Injecting false or malicious data into the agent's persistent memory or vector store |
| 05 | **Privilege Escalation** | Chaining permitted tools in unpermitted sequences to achieve unauthorized actions |
| 06 | **Inter-Agent Injection** | Compromising one agent in a multi-agent pipeline to hijack downstream agents |

---

## How It Works

```
1. Install SDK          pip install agentshield
        ↓
2. Wrap your agent      shield(agent, tools=tools, policy="no_exfiltration")
        ↓
3. Runtime hooks in     Intercepts every tool call, memory op, LLM I/O
        ↓
4. Detection engine     Analyzes for goal drift, injection, anomalies
        ↓
5. Threat response      Block + Alert + Audit log generated automatically
        ↓
6. Live console         Execution graph updates in real time via WebSocket
```

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│         Agent Framework Layer                    │
│         LangChain / AutoGen / CrewAI             │
└────────────────────┬────────────────────────────┘
                     │ hooks into
┌────────────────────▼────────────────────────────┐
│         AgentShield SDK                          │
│         Interceptors · Event Emitters ·          │
│         Policy Engine                            │
└────────────────────┬────────────────────────────┘
                     │ streams to
┌────────────────────▼────────────────────────────┐
│         Redis Event Bus                          │
│         Real-time pub/sub streaming              │
└────────────────────┬────────────────────────────┘
                     │ consumed by
┌────────────────────▼────────────────────────────┐
│         Detection Engine                         │
│         Intent Drift · Tool Anomaly ·            │
│         Embedding Analysis (AMD ROCm GPU)        │
└────────────────────┬────────────────────────────┘
                     │ outputs to
┌────────────────────▼────────────────────────────┐
│         FastAPI Backend → WebSocket              │
│         Streams events to React console          │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────┐
│         React Visual Console                     │
│         Cytoscape.js live graph ·                │
│         Forensic audit trail                     │
└─────────────────────────────────────────────────┘
```

---

## Features

| Feature | Description |
|---------|-------------|
| 🔍 **Tool Call Interception** | Every tool invocation validated in real time against policy |
| 🎯 **Goal Drift Detection** | Semantic similarity scoring across conversation turns |
| 🧠 **Memory Poisoning Detection** | Embedding-space anomaly detection on vector store writes |
| 💉 **Prompt Injection Detection** | Indirect injection detection in retrieved documents and data |
| ⛓️ **Tool Chain Anomaly** | Detects privilege escalation via unpermitted tool sequences |
| 🤝 **Inter-Agent Integrity** | Validates message authenticity in multi-agent pipelines |
| 📋 **Policy Compiler** | Plain-language YAML rules compiled to executable constraints |
| 📊 **Live Execution Graph** | Cytoscape.js visualization with real-time WebSocket updates |
| 🔬 **Forensic Audit Trail** | Complete execution replay with full attack chain reconstruction |
| ⚡ **GPU-Accelerated** | AMD ROCm parallel threat simulation — 10× faster than CPU |

---

## How AgentShield Compares

| Solution | Execution Layer | Framework Native | Real-Time Block | Forensic Trace | Agent-Aware |
|----------|:--------------:|:----------------:|:---------------:|:--------------:|:-----------:|
| Traditional SIEM | ❌ | ❌ | ❌ | Partial | ❌ |
| API Gateways | ❌ | ❌ | Partial | ❌ | ❌ |
| Prompt Filters | ❌ | ❌ | Partial | ❌ | ❌ |
| Protect AI / HiddenLayer | ❌ | ❌ | Partial | ❌ | ❌ |
| **AgentShield** ⭐ | ✅ | ✅ | ✅ | ✅ | ✅ |

> AgentShield is the only solution that operates natively **inside** agent execution — not around it.

---

## Full Setup

### Prerequisites
- Docker Desktop
- OpenAI API key (or compatible LLM)

### Run in 3 commands

```bash
git clone https://github.com/AdityaBelhekar/AgentShield.git
cd AgentShield
cp .env.example .env        # Add your OPENAI_API_KEY
make docker-up
```

Open **http://localhost:5173** — the live security console is running.

### Development Setup

```bash
pip install -e ".[dev]"
make lint
make typecheck
make test
```

---

## Policy Configuration

AgentShield ships with built-in policies:

```python
# Block data exfiltration patterns
secured = shield(agent, tools=tools, policy="no_exfiltration")

# Maximum security — blocks on lower thresholds
secured = shield(agent, tools=tools, policy="strict")

# Monitor only — log everything, block nothing
secured = shield(agent, tools=tools, policy="monitor_only")

# Custom YAML policy
secured = shield(agent, tools=tools, policy="./my_policy.yaml")
```

Custom policy example (`my_policy.yaml`):
```yaml
name: my_policy
version: "1.0"
rules:
  - id: no-exfil
    description: "Block read → send sequences"
    condition: "tool_sequence_matches(['read_file','send_report'])"
    action: block
    severity: high
```

---

## AMD ROCm GPU Acceleration

AgentShield automatically detects and uses AMD ROCm for:

- **Parallel Monte Carlo threat simulation** — simultaneously simulates thousands of attack scenarios in real time
- **Embedding-space anomaly detection** — GPU-accelerated sentence-transformer inference for memory poisoning detection
- **Behavioral baseline computation** — rolling statistical baselines impossible at CPU speed

```
CPU baseline:   ~40s per simulation
AMD GPU:         ~4s per simulation   (10× speedup)
```

AgentShield auto-detects the best available device:
`ROCm → CUDA → CPU` with no configuration required.

---

## Tech Stack

| Layer | Technologies |
|-------|-------------|
| **Agent Frameworks** | Python 3.11+, LangChain, AutoGen, CrewAI |
| **Backend & Streaming** | FastAPI, Redis Pub/Sub, WebSockets, Docker |
| **Detection & ML** | sentence-transformers, FAISS, PyTorch, scikit-learn |
| **Frontend** | React 18, TypeScript, Cytoscape.js, TailwindCSS |
| **GPU Acceleration** | AMD ROCm, HIP, PyTorch/ROCm, ONNX Runtime |

---

## Documentation

- [Quickstart Guide](docs/quickstart.md)
- [Architecture Overview](docs/architecture.md)
- [SDK Reference](docs/sdk-reference.md)
- [Attack Vectors](docs/attack-vectors.md)
- [Policy Guide](docs/policy-guide.md)

---

## Contributing

We welcome contributions! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

```bash
# Fork → Clone → Branch → PR
git checkout -b feat/your-feature
make lint && make typecheck && make test
# Open a PR
```

---

## License

MIT © [GroundTruth](https://github.com/AdityaBelhekar)

---

<div align="center">

*Built for AMD Slingshot Hackathon — Human Imagination Built With AI*

**"AI agents are becoming the nervous system of enterprise.**
**We make sure nothing hijacks that nervous system."**

</div>
