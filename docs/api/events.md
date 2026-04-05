# Events

The `agentshield.events.models` module defines all event envelopes used in runtime detection, transport, policy evaluation, and forensics.

::: agentshield.events.models

## Core Enums

### `EventType`

- `SESSION_START`, `SESSION_END`
- `TOOL_CALL_START`, `TOOL_CALL_COMPLETE`, `TOOL_CALL_BLOCKED`
- `LLM_PROMPT`, `LLM_RESPONSE`
- `CHAIN_START`, `CHAIN_END`
- `MEMORY_READ`, `MEMORY_WRITE`
- `THREAT_DETECTED`, `THREAT_CLEARED`, `POLICY_VIOLATION`
- `CANARY_INJECTED`, `CANARY_TRIGGERED`
- `PROVENANCE_TAGGED`

### `SeverityLevel`

- `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

### `ThreatType`

- `PROMPT_INJECTION`
- `GOAL_DRIFT`
- `TOOL_POISONING`
- `TOOL_CHAIN_ESCALATION`
- `MEMORY_POISONING`
- `BEHAVIORAL_ANOMALY`
- `INTER_AGENT_INJECTION`

### `RecommendedAction`

- `BLOCK`
- `FLAG`
- `ALERT`
- `LOG_ONLY`

### `TrustLevel`

- `TRUSTED`
- `INTERNAL`
- `EXTERNAL`
- `UNTRUSTED`