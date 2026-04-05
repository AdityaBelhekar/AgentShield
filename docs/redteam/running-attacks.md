# Running Attacks

## List Payloads

```bash
agentshield redteam list
agentshield redteam list --category prompt_injection
agentshield redteam list --severity critical
```

## Run a Full Campaign

```bash
agentshield redteam run myproject.agent:create_agent --policy monitor_only
```

## Run Specific Scenarios

```bash
agentshield redteam run myproject.agent:create_agent --attack-id pi_001
agentshield redteam run myproject.agent:create_agent --category tool_chain_escalation
```

## Persist Reports

```bash
agentshield redteam run myproject.agent:create_agent \
  --output reports/redteam.json \
  --html-output reports/redteam.html
```

## Interpreting Outcomes

- `DETECTED`: attack path was detected and mitigated.
- `BYPASSED`: attack succeeded without sufficient mitigation.
- `SIMULATED`: scenario was non-live simulation.

Use bypass findings to tune detector thresholds, tighten policies, or adjust tool permissions.