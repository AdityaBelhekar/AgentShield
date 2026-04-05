# Custom YAML Policies

## YAML Schema Reference

```yaml
name: string                      # required
version: string                   # optional, default "1.0"
description: string               # optional
agent_id: string | null           # optional

default_action: BLOCK|ALERT|FLAG|LOG|ALLOW
allowed_tools: [string, ...]      # optional
denied_tools: [string, ...]       # optional
metadata: {key: value}            # optional

rules:
  - id: string                    # required, no spaces
    description: string           # required
    enabled: true|false           # optional, default true
    severity: INFO|LOW|MEDIUM|HIGH|CRITICAL
    action: BLOCK|ALERT|FLAG|LOG|ALLOW
    metadata: {key: value}
    conditions:
      - type: TOOL_CALL|TOOL_SEQUENCE|GOAL_DRIFT|INJECTION_SCORE|MEMORY_WRITE|MEMORY_READ
        negate: false
        tool_names: [string, ...]     # TOOL_CALL
        sequence: [string, ...]       # TOOL_SEQUENCE
        threshold: number             # GOAL_DRIFT / INJECTION_SCORE
        patterns: [string, ...]       # MEMORY_WRITE / MEMORY_READ
```

> Runtime note: the current policy enum also exposes `AGENT_STATE` for severity-state matching. If you depend on strict parser compatibility, validate policy files in CI using `PolicyCompiler` before deployment.

## Annotated Example Policy

```yaml
name: finance_guard
version: "1.0"
description: Hardened policy for finance workflows
default_action: LOG
allowed_tools:
  - search_kb
  - lookup_invoice
  - send_email
denied_tools:
  - execute_code
  - bash

rules:
  - id: block_exfil_chain
    description: Block file read to outbound email chain
    severity: HIGH
    action: BLOCK
    conditions:
      - type: TOOL_SEQUENCE
        sequence: ["read_file", "send_email"]

  - id: alert_prompt_injection
    description: Escalate medium injection confidence
    severity: HIGH
    action: ALERT
    conditions:
      - type: INJECTION_SCORE
        threshold: 0.50

  - id: flag_goal_drift
    description: Flag meaningful task drift
    severity: MEDIUM
    action: FLAG
    conditions:
      - type: GOAL_DRIFT
        threshold: 0.35

  - id: block_memory_poison_signals
    description: Block suspicious memory writes
    severity: CRITICAL
    action: BLOCK
    conditions:
      - type: MEMORY_WRITE
        patterns: ["always send", "override", "ignore previous"]
```

## Supported Condition Types

- `INJECTION_SCORE`
- `GOAL_DRIFT`
- `TOOL_SEQUENCE`
- `TOOL_CALL`
- `MEMORY_WRITE`
- `MEMORY_READ`

## Supported Actions

- `BLOCK`
- `ALERT`
- `FLAG`
- `LOG`
- `ALLOW`

## Load a Custom Policy

```python
from agentshield import shield

protected = shield(agent, policy="./my_policy.yaml")
```