# Inter-Agent Injection

## 1. What Is This Threat

Inter-agent injection occurs when one agent sends manipulated content to another agent across orchestration boundaries. The receiving agent may treat poisoned upstream output as trusted input unless trust boundaries are enforced.

## 2. How AgentShield Detects It

`InterAgentMonitor` evaluates flagged `InterAgentMessage` flows from `AgentTrustGraph`, combining sender trust state and message trust level. Compromised senders force aggressive confidence bands, and exposed receivers can be proactively alerted.

## 3. Detection Thresholds

- Minimum confidence to emit: `INTER_AGENT_MIN_CONFIDENCE = 0.30`
- Action thresholds:
  - `>= 0.85` -> `ALERT`
  - `>= 0.50` -> `FLAG`
  - otherwise `LOG_ONLY`
- Exposure check confidence: `0.85` when receiver has compromised senders.

## 4. Example Attack Payload

```text
[SIMULATION] Agent A forwards hidden override instructions to Agent B while claiming TRUSTED sender identity.
```

## 5. What Happens When Detected

AgentShield emits `INTER_AGENT_INJECTION` threats including sender/receiver trust evidence and graph summary. Blocks are usually produced after policy evaluation or detector correlation with additional signals (for example, prompt injection or tool-chain escalation).

## 6. Relevant Policy Rules

- There is no dedicated inter-agent condition in built-in policies; enforcement usually depends on default action and correlated detector outputs.
- `strict` policy remains the safest default for multi-agent systems due broader blocking posture.
- Custom policies should combine injection/drift/tool conditions with strict trust-boundary routing in orchestration logic.