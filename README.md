[![PyPI](https://img.shields.io/pypi/v/agentshield-x?style=flat-square)](https://pypi.org/project/agentshield-x/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-live-blueviolet?style=flat-square)](https://AdityaBelhekar.github.io/AgentShield)
[![Stars](https://img.shields.io/github/stars/AdityaBelhekar/AgentShield?style=flat-square)](https://github.com/AdityaBelhekar/AgentShield)

# AgentShield

<p align="center"><strong>The security primitive the agent ecosystem is missing.</strong></p>

```python
from agentshield import shield

# Wrap any LangChain agent in one line
protected = shield(your_langchain_agent, policy="no_exfiltration")

# Fully protected — prompt injection, goal drift, tool chain escalation
result = protected.run("Summarize and email this document")
```

## What Is AgentShield

AgentShield is a runtime security SDK for AI agents. It is not an agent and not a chatbot. It is a defensive execution layer that wraps existing agent runtimes, intercepts execution events, scores threats, and enforces policy before unsafe behavior reaches tools, memory, or external channels.

This category was missing because agent frameworks optimized for capability and orchestration, not adversarial resilience. As a result, teams had no single primitive for prompt-level abuse detection, multi-step tool-chain control, and forensic-grade runtime telemetry in one place.

## Threat Coverage

| Threat | Detection Method | Default Action | Detector Class |
| --- | --- | --- | --- |
| Prompt Injection | 3-layer (pattern + semantic + canary) | BLOCK | PromptInjectionDetector |
| Goal Drift | Cosine distance + rolling average | ALERT | GoalDriftDetector |
| Tool Chain Escalation | Forbidden sequence detection | BLOCK | ToolChainDetector |
| Memory Poisoning | Z-score anomaly | ALERT | MemoryPoisonDetector |
| Behavioral Anomalies | Agent DNA fingerprinting | FLAG | DNAAnomalyScorer |
| Inter-Agent Injection | Provenance + trust graph | BLOCK | InterAgentMonitor |

## Original Research (not found elsewhere)

- **Agent DNA Fingerprinting**: Learns a per-agent behavioral baseline from clean sessions and flags statistically meaningful deviations.
- **Canary Injection**: Uses cryptographic canary tokens to confirm active instruction hijack with near-zero ambiguity.
- **Prompt Provenance Tracking**: Tags context by trust origin (`TRUSTED`, `INTERNAL`, `EXTERNAL`, `UNTRUSTED`) before model execution.
- **Cryptographic Audit Trail**: Hash-chains security events into tamper-evident JSONL for verification and incident reconstruction.
- **Red Team CLI**: Runs curated adversarial scenarios against live agents and emits structured security reports.
- **AgentShield Certify**: Converts red-team outcomes into reproducible certification artifacts and badge output.

## Installation

```bash
pip install agentshield-x
```

| Extra | Installs | When to use |
| --- | --- | --- |
| [redis] | redis, hiredis | pub/sub + dashboard |
| [otel] | opentelemetry-* | observability export |
| [all] | everything | full feature set |

## Quick Example - 3 Policies

```python
# 1. Monitor only (zero risk, great for first run)
protected = shield(agent, policy="monitor_only")
```

```python
# 2. Block exfiltration attempts
protected = shield(agent, policy="no_exfiltration")
```

```python
# 3. Maximum security
protected = shield(agent, policy="strict")
```

```python
# 4. Custom YAML policy
protected = shield(agent, tools=tools, policy="./my_policy.yaml")
```

## Catching Violations

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

## Built-in Policies

| Policy | Blocks | Best For |
| --- | --- | --- |
| monitor_only | Nothing (observe only) | Testing, onboarding |
| no_exfiltration | read→send chains, high injection | Production agents |
| strict | Medium drift, execute tools | High-security envs |

## Integrations

[LangChain](https://python.langchain.com/) | [LlamaIndex](https://www.llamaindex.ai/) | [AutoGen](https://github.com/microsoft/autogen) | [OpenAI](https://platform.openai.com/) | [Anthropic](https://www.anthropic.com/)

```python
# LangChain
from agentshield import shield; protected = shield(langchain_agent, policy="monitor_only")
```

```python
# LlamaIndex
from agentshield import shield; protected = shield(llamaindex_agent, policy="monitor_only")
```

```python
# AutoGen
from agentshield import shield; protected = shield(autogen_agent, policy="monitor_only")
```

```python
# OpenAI
from agentshield import shield; protected = shield(openai_client, policy="monitor_only")
```

```python
# Anthropic
from agentshield import shield; protected = shield(anthropic_client, policy="monitor_only")
```

## Red Team CLI

```bash
# List available attack scenarios
agentshield attack list

# Run a specific attack
agentshield attack run --scenario prompt_injection --target my_agent.py

# Generate certification report
agentshield certify --agent my_agent.py --policy no_exfiltration
```

## Architecture Diagram

```text
User Input
  |
  v
┌─────────────────────────────────────────────────────┐
│                  AgentShield Runtime                │
│                                                     │
│  LLM Hook -> Tool Hook -> Memory Hook              │
│       |           |           |                     │
│       └───────────┴───────────┘                     │
│                   |                                  │
│            DetectionEngine                           │
│     ┌──────────────────────────────┐                 │
│     │  Canary -> DNA -> Provenance │                 │
│     │  PromptInjection Detector    │                 │
│     │  GoalDrift Detector          │                 │
│     │  ToolChain Detector          │                 │
│     │  MemoryPoison Detector       │                 │
│     │  InterAgent Monitor          │                 │
│     └──────────────────────────────┘                 │
│                   |                                  │
│           Cross-Correlation                          │
│                   |                                  │
│           PolicyEvaluator                            │
│                   |                                  │
│          BLOCK / ALERT / LOG                         │
└─────────────────────────────────────────────────────┘
  |
  v
Agent continues (or PolicyViolationError raised)
```

## Documentation

- Full Docs: https://AdityaBelhekar.github.io/AgentShield
- Quickstart: ./QUICKSTART.md
- SDK Reference: ./docs/sdk-reference.md
- Contributing: ./CONTRIBUTING.md

## Exception Hierarchy

```text
AgentShieldError
├── ConfigurationError
├── AdapterError
├── InterceptorError
├── DetectionError
├── EventEmissionError
├── RedisConnectionError
├── ProvenanceError
├── CanaryError
├── DNAError
├── AuditChainError
└── PolicyViolationError
  ├── ToolCallBlockedError
  │   └── PrivilegeEscalationError
  ├── GoalDriftError
  ├── PromptInjectionError
  ├── MemoryPoisonError
  ├── BehavioralAnomalyError
  └── InterAgentInjectionError
```

## License + Author

MIT License. Built by Aditya Belhekar.
AgentShield is and will always remain free and open-source.
