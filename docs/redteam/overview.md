# Red Team CLI Overview

The Red Team CLI lets you attack your own agent with a curated library before deploying to production.

## Core Commands

```bash
agentshield attack list
agentshield attack run --scenario <name>
```

Current command group mapping in this repository:

```bash
agentshield redteam list
agentshield redteam run <agent_module>
```

## Available Attack Scenarios

- Prompt injection: `pi_001` .. `pi_005`
- Goal drift: `gd_001` .. `gd_005`
- Tool-chain escalation: `tce_001` .. `tce_005`
- Memory poisoning: `mp_001` .. `mp_005`
- Inter-agent injection: `iai_001` .. `iai_005`
- Behavioral anomaly: `ba_001` .. `ba_005`

Use category filters (`prompt_injection`, `goal_drift`, `tool_chain_escalation`, `memory_poisoning`, `inter_agent_injection`, `behavioral_anomaly`) to scope runs.