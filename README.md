<p align="center">
  <h1 align="center">🛡️ AgentShield</h1>
  <p align="center"><strong>The only runtime that secures AI agents from the inside.</strong></p>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/python-3.11%2B-brightgreen.svg" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/build-passing-brightgreen.svg" alt="Build">
  <img src="https://img.shields.io/badge/version-0.1.0-blue.svg" alt="Version">
</p>

---

AgentShield is a **real-time security runtime** for AI agents. It wraps your existing LangChain / AutoGen / CrewAI agent with invisible monitoring, threat detection, and policy enforcement — no agent code changes required.

> **Core Insight:** AI agents are powerful but vulnerable. Prompt injection, goal hijacking, tool chain escalation, and memory poisoning can turn any agent against its user. AgentShield detects and blocks these attacks in real time, from inside the agent's own execution loop.

## ⚡ 4-Line Integration

```python
from agentshield import shield

agent = shield(your_langchain_agent, tools=tools, policy="no_exfiltration")
result = agent.run("Summarize this document")  # Fully protected ✓
```

That's it. Your agent is now monitored, protected, and auditable.

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Your Agent (LangChain)                    │
├─────────────────────────────────────────────────────────────┤
│              AgentShield Runtime (pip SDK)                   │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐ │
│  │ Interceptors  │ │  Detection   │ │   Policy Engine      │ │
│  │ • LLM I/O    │ │  • Injection │ │   • YAML rules       │ │
│  │ • Tool calls │ │  • GoalDrift │ │   • Built-in presets │ │
│  │ • Memory ops │ │  • ToolChain │ │   • Custom policies  │ │
│  └──────┬───────┘ │  • MemPoison │ └──────────────────────┘ │
│         │         └──────┬───────┘                           │
│         └────────┬───────┘                                   │
│                  ▼                                           │
│         ┌────────────────┐                                   │
│         │  Event Emitter │──→ Redis PubSub + JSONL Audit Log │
│         └────────────────┘                                   │
├─────────────────────────────────────────────────────────────┤
│              FastAPI Backend (WebSocket bridge)              │
├─────────────────────────────────────────────────────────────┤
│           React Security Console (live dashboard)           │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Quickstart

```bash
# 1. Clone
git clone https://github.com/AdityaBelhekar/AgentShield.git
cd AgentShield

# 2. Configure
cp .env.example .env
# Edit .env → add your OPENAI_API_KEY

# 3. Launch
docker-compose up --build -d

# 4. Open the live security console
open http://localhost:5173
```

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Prompt Injection Detection** | Pattern + semantic similarity detection of injection attacks |
| 🎯 **Goal Drift Monitoring** | Embedding-based drift scoring against the original task |
| ⛓ **Tool Chain Analysis** | Forbidden sequence detection (e.g., read → exfiltrate) |
| 🧠 **Memory Poisoning Detection** | Z-score anomaly detection on memory write embeddings |
| 📊 **Live Security Console** | Real-time Cytoscape.js execution graph + threat alerts |
| 📋 **Forensic Audit Logging** | Full JSONL audit trail of every event |
| 🛑 **Policy Engine** | YAML-defined or built-in security policies |
| 🔌 **Framework Agnostic** | LangChain today, AutoGen + CrewAI coming soon |

## 🔬 How It Works

1. **Wrap** — `shield()` attaches invisible interceptors to your agent
2. **Intercept** — Every LLM call, tool invocation, and memory op is captured
3. **Analyze** — The detection engine scores each event against 5 threat models
4. **Enforce** — Policy rules block dangerous actions in real time
5. **Visualize** — Events stream to the live console via WebSocket

## 🧪 Development

```bash
# Install in dev mode
make install-dev

# Run tests
make test

# Lint + format
make lint
make format

# Type check
make typecheck
```

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, branch naming, commit format, and PR checklist.

## 📄 License

MIT — see [LICENSE](LICENSE).

---

<p align="center">
  <strong>Built by Team GroundTruth for AMD Slingshot Hackathon</strong><br>
  <em>Human Imagination Built With AI</em>
</p>
