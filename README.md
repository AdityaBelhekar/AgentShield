# 🛡️ AgentShield

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-0.1.0-green.svg)](CHANGELOG.md)

> **The only runtime that secures AI agents from the inside.**

AgentShield is an open-source Python SDK that wraps any LangChain, AutoGen, or CrewAI agent and monitors its entire execution pipeline in real time — detecting and blocking attacks without modifying your agent code.

## Quickstart

```bash
pip install agentshield
```

```python
from agentshield import shield

agent = shield(your_agent, policy="no_exfiltration")
agent.run("Summarize this document")  # Fully protected ✓
```

## What It Defends Against

| Attack Vector              | Description                                    | Detection Method              |
| -------------------------- | ---------------------------------------------- | ----------------------------- |
| 🎯 Prompt Injection       | Malicious instructions hidden in input data    | Pattern + semantic similarity |
| 🔀 Goal Drift / Hijacking | Agent subtly steered away from original task   | Cosine distance tracking      |
| 🧪 Tool Poisoning         | Compromised tool returns manipulated data      | Output anomaly analysis       |
| ⛓️ Tool Chain Escalation  | Read → Read → Exfiltrate sequences             | Forbidden sequence matching   |
| 🧠 Memory Poisoning       | Injected memories alter future behavior        | Statistical z-score analysis  |
| 🤝 Inter-Agent Injection  | Agent-to-agent prompt attacks in multi-agent   | Cross-agent prompt monitoring |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Your Agent Code                    │
├─────────────────────────────────────────────────────┤
│  Layer 1: Interceptors (LLM / Tool / Memory hooks)  │
├─────────────────────────────────────────────────────┤
│  Layer 2: Detection Engine (5 threat detectors)      │
├─────────────────────────────────────────────────────┤
│  Layer 3: Policy Compiler (YAML → runtime rules)     │
├─────────────────────────────────────────────────────┤
│  Layer 4: Event System (Redis pub/sub + audit log)   │
├─────────────────────────────────────────────────────┤
│  Layer 5: Security Console (React real-time UI)      │
└─────────────────────────────────────────────────────┘
```

## How It Works

1. **Install** — `pip install agentshield`
2. **Wrap** — `agent = shield(your_agent, policy="no_exfiltration")`
3. **Intercept** — Every LLM call, tool execution, and memory operation is captured
4. **Detect** — Five specialized detectors analyze events in real time
5. **Protect** — Threats are flagged, alerted, or blocked based on policy

## Full Setup

```bash
# Clone and run everything
git clone https://github.com/GroundTruth/agentshield.git
cd agentshield
cp .env.example .env
# Add your OPENAI_API_KEY to .env
make docker-up

# Open the security console
open http://localhost:5173
```

See [docs/quickstart.md](docs/quickstart.md) for detailed instructions.

## Documentation

- [Quickstart Guide](docs/quickstart.md)
- [Architecture](docs/architecture.md)
- [SDK Reference](docs/sdk-reference.md)
- [Attack Vectors](docs/attack-vectors.md)
- [Policy Guide](docs/policy-guide.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT — see [LICENSE](LICENSE) for details.

---

**Team GroundTruth** | AMD Slingshot Hackathon
