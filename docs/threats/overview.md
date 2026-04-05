# Threat Coverage Overview

AgentShield currently covers six primary runtime threat families and correlates signals before enforcing actions.

| Threat Type | Primary Module | Typical Trigger Surface |
| --- | --- | --- |
| Prompt Injection | `PromptInjectionDetector` | LLM prompts, tool outputs |
| Goal Drift | `GoalDriftDetector` | Prompt intent deviation over time |
| Tool Chain Escalation | `ToolChainDetector` | Tool call sequence transitions |
| Memory Poisoning | `MemoryPoisonDetector` | Memory writes with anomalous content |
| Behavioral Anomalies | `DNAAnomalyScorer` | Session-end baseline deviation |
| Inter-Agent Injection | `InterAgentMonitor` | Cross-agent message trust boundary |

Correlation behavior is centralized in `DetectionEngine`: single detector signals are softened, multi-detector convergence escalates, and canary-triggered events block immediately.

See the per-threat pages for thresholds, sample payloads, and policy recommendations.