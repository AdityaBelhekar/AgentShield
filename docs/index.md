# AgentShield

!!! tip "The security primitive the agent ecosystem is missing."
	AgentShield wraps your existing AI agent with runtime threat detection, policy enforcement, and forensic telemetry.

AgentShield is a production security runtime SDK for AI agents. It is not an agent, and it is not a chatbot. It is a firewall layer that sits between your agent runtime and the outside world, inspecting execution events in real time and enforcing policy decisions before dangerous behavior propagates.

```python
from agentshield import shield

protected = shield(your_langchain_agent, policy="no_exfiltration")
protected.run("Summarize this document")
```

| Threat Covered | Detection Method | Action |
| --- | --- | --- |
| Prompt Injection | Signature matching + semantic similarity + canary trigger checks | FLAG, ALERT, or BLOCK based on confidence and policy |
| Goal Drift | Embedding distance from original task with rolling correlation | FLAG/ALERT and BLOCK when thresholds and policy allow |
| Tool Chain Escalation | Forbidden sequence matching + heuristic escalation scoring | Pre-execution BLOCK for dangerous chains, else escalated actions |
| Memory Poisoning | Pattern signatures + semantic z-score + content length anomaly | ALERT/BLOCK when anomaly confidence crosses thresholds |
| Behavioral Anomalies | Agent DNA baseline deviation scoring across 13 behavioral features | FLAG/ALERT and correlation-driven escalation |
| Inter-Agent Injection | Trust-graph analysis across sender/receiver trust boundaries | LOG/FLAG/ALERT based on sender state and confidence |

## Why AgentShield?

- Framework-agnostic protection for LangChain, LlamaIndex, AutoGen, and raw provider clients.
- Multi-detector correlation logic that reduces single-signal false positives.
- Cryptographic audit chain for tamper-evident post-incident forensics.
- Policy-driven controls that let teams start in monitor mode and progressively harden.

## Quick Links

- [Installation](getting-started/installation.md)
- [Quickstart](getting-started/quickstart.md)