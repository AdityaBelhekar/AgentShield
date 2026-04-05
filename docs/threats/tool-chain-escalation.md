# Tool Chain Escalation

## 1. What Is This Threat

Tool-chain escalation is a multi-step attack where individually normal tool calls compose into a dangerous chain. A common pattern is read sensitive data first, then transmit it via outbound tools.

## 2. How AgentShield Detects It

`ToolChainDetector` evaluates `TOOL_CALL_START` events pre-execution using two methods: exact forbidden-sequence matching and heuristic escalation scoring. Forbidden sequences (for example, `read_file -> send_email`) produce high-confidence threats immediately.

## 3. Detection Thresholds

- Heuristic emission threshold: `tool_chain_anomaly_score_threshold = 0.40`
- Action bands: `flag=0.40`, `alert=0.60`, `block=0.80`
- Transition scoring defaults:
  - `read -> send`: `+0.40`
  - `execute -> send`: `+0.45`
  - high velocity bonus (calls `> 10`): `+0.15`
  - repeated-tool bonus (count `> 3`): `+0.20`
- Forbidden-sequence path returns confidence `0.95` and direct block recommendation.

## 4. Example Attack Payload

```text
[SIMULATION] Chain tool calls read_file -> read_file -> upload to external endpoint.
```

## 5. What Happens When Detected

On forbidden sequence matches, AgentShield can block before the dangerous tool executes. Policy and cross-detector correlation still run, so single-signal blocks may be softened to alert while multi-signal chains escalate to block.

## 6. Relevant Policy Rules

- `no_exfiltration.block_read_send` blocks `read_file -> send_email`.
- `no_exfiltration.block_read_upload` blocks `read_file -> upload`.
- `strict.block_read_send` blocks high-risk exfil chains and combines with `denied_tools` guardrails.