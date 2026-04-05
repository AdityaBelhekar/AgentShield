# SDK Reference

## 1. shield() - Entry Point

Signature:

```python
def shield(
    agent: Any,
    tools: list[BaseTool] | None = None,
    policy: str | PolicyConfig = "monitor_only",
    config: AgentShieldConfig | None = None,
    session_id: str | None = None,
) -> WrappedAgent
```

Parameter table:

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| agent | Any | required | The agent to protect |
| tools | list[BaseTool] \| None | None | Tools to intercept |
| policy | str \| PolicyConfig | "monitor_only" | Policy name, path, or object |
| config | AgentShieldConfig \| None | None | Config override (uses env defaults) |
| session_id | str \| None | None | Custom session ID (auto if None) |

Returns: WrappedAgent  
Raises: ConfigurationError if policy file not found or invalid

## 2. WrappedAgent

Methods:

- `.run(input: str) -> str`  
  Runs the agent with full protection active.  
  Raises PolicyViolationError subclass if action=BLOCK.

- `.arun(input: str) -> str` (async)  
  Async equivalent of `.run()`.

- `.get_session_id() -> str`  
  Returns current session UUID.

- `.get_runtime() -> AgentShieldRuntime`  
  Returns the underlying runtime for advanced use.

## 3. AgentShieldConfig

All fields with types, defaults, and env var names:

| Field | Type | Default | Env Var |
| --- | --- | --- | --- |
| redis_url | str | None | AGENTSHIELD_REDIS_URL |
| redis_enabled | bool | False | AGENTSHIELD_REDIS_ENABLED |
| injection_pattern_threshold | float | 0.60 | AGENTSHIELD_INJECTION_PATTERN_THRESHOLD |
| injection_semantic_threshold | float | 0.75 | AGENTSHIELD_INJECTION_SEMANTIC_THRESHOLD |
| goal_drift_threshold | float | 0.45 | AGENTSHIELD_GOAL_DRIFT_THRESHOLD |
| memory_zscore_threshold | float | 2.5 | AGENTSHIELD_MEMORY_ZSCORE_THRESHOLD |
| anomaly_sensitivity | float | 0.85 | AGENTSHIELD_ANOMALY_SENSITIVITY |
| dna_min_sessions | int | 10 | AGENTSHIELD_DNA_MIN_SESSIONS |
| audit_log_path | str | "agentshield_audit.jsonl" | AGENTSHIELD_AUDIT_LOG_PATH |
| log_level | str | "INFO" | AGENTSHIELD_LOG_LEVEL |
| canary_inject_probability | float | 0.15 | AGENTSHIELD_CANARY_INJECT_PROBABILITY |

## 4. PolicyConfig (Custom Policy Schema)

Full YAML -> Python mapping.

```python
class PolicyConfig(BaseModel):
    name: str
    default_action: PolicyAction        # BLOCK/ALERT/FLAG/LOG/ALLOW
    denied_tools: list[str] = []
    rules: list[PolicyRule] = []

class PolicyRule(BaseModel):
    name: str
    condition: RuleCondition
    action: PolicyAction
    priority: int = 0                   # higher = evaluated first

class RuleCondition(BaseModel):
    type: ConditionType                 # INJECTION_SCORE | GOAL_DRIFT |
                                        # TOOL_SEQUENCE | TOOL_CALL |
                                        # MEMORY_WRITE | MEMORY_READ
    threshold: float | None = None      # for score-based conditions
    tool_names: list[str] | None = None # for TOOL_CALL
    sequence: list[str] | None = None   # for TOOL_SEQUENCE
```

## 5. PolicyDecision

```python
class PolicyDecision:
    action: PolicyAction        # BLOCK / ALERT / FLAG / LOG / ALLOW
    should_block: bool          # True only if BLOCK
    should_suppress: bool       # True if ALLOW (bypass detection entirely)
    matched_rule: str | None    # name of triggered rule, None if default
    reason: str                 # human-readable explanation
```

## 6. ThreatEvent

Key fields that consumers care about:

| Field | Type | Description |
| --- | --- | --- |
| event_id | UUID | Unique event identifier |
| session_id | str | Session this event belongs to |
| threat_type | ThreatType | Which attack vector was detected |
| severity | SeverityLevel | INFO/LOW/MEDIUM/HIGH/CRITICAL |
| recommended_action | RecommendedAction | BLOCK/FLAG/ALERT/LOG_ONLY |
| confidence | float | 0.0-1.0 detector confidence |
| canary_triggered | bool | True if canary token found |
| detector_name | str | Which detector fired |
| timestamp | datetime | UTC event time |

## 7. Enums Reference

All 5 enums with every value listed:

EventType (17 values):

- TOOL_CALL
- TOOL_RESULT
- LLM_PROMPT
- LLM_RESPONSE
- MEMORY_READ
- MEMORY_WRITE
- THREAT_DETECTED
- SESSION_START
- SESSION_END
- AGENT_START
- AGENT_END
- ERROR
- CANARY_INJECTED
- CANARY_TRIGGERED
- PROVENANCE_TAGGED
- INTER_AGENT_MESSAGE
- POLICY_DECISION

SeverityLevel:

- INFO
- LOW
- MEDIUM
- HIGH
- CRITICAL

ThreatType:

- PROMPT_INJECTION
- GOAL_DRIFT
- TOOL_CHAIN_ESCALATION
- MEMORY_POISONING
- BEHAVIORAL_ANOMALY
- INTER_AGENT_INJECTION

RecommendedAction:

- BLOCK
- FLAG
- ALERT
- LOG_ONLY

TrustLevel:

- TRUSTED
- INTERNAL
- EXTERNAL
- UNTRUSTED

## 8. Exception Reference

Full hierarchy table:

| Exception | When raised |
| --- | --- |
| AgentShieldError | Base - never raised directly |
| ConfigurationError | Invalid config / missing file |
| InterceptorError | Hook installation failure |
| DetectionError | Detector internal error |
| EventEmissionError | emit() failure (never propagates to caller) |
| RedisConnectionError | Redis unreachable |
| ProvenanceError | Provenance tracking failure |
| CanaryError | Canary system failure |
| DNAError | DNA baseline/scoring failure |
| AuditChainError | Hash chain integrity violation |
| PolicyViolationError | Base blocking exception |
| ToolCallBlockedError | Tool call blocked by policy |
| PrivilegeEscalationError | Privilege escalation via tool chain |
| GoalDriftError | Goal drift exceeded threshold |
| PromptInjectionError | Injection detected and blocked |
| MemoryPoisonError | Memory poisoning detected and blocked |
| BehavioralAnomalyError | DNA anomaly exceeded threshold |
| InterAgentInjectionError | Cross-agent injection detected |

## 9. Listening to Events (Advanced)

How to subscribe to the event stream via Redis pub/sub:

```python
import redis
import json

r = redis.from_url("redis://localhost:6379")
pubsub = r.pubsub()
pubsub.subscribe("agentshield:events")

for message in pubsub.listen():
    if message["type"] == "message":
        event = json.loads(message["data"])
        if event["event_type"] == "THREAT_DETECTED":
            print(f"Threat: {event['threat_type']} | {event['severity']}")
```

## 10. Audit Log Format

JSONL file, one event per line.

Each line contains:

- All ThreatEvent fields (no raw content, no canary token values)
- chain_hash: SHA-256 of (prev_hash + current_event_json)
- sequence_number: monotonically increasing integer

Verification:

```bash
agentshield audit verify --log agentshield_audit.jsonl
agentshield audit export --log agentshield_audit.jsonl --format json
```