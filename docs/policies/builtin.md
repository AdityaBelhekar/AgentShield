# Built-in Policies

## Policy Matrix

| Policy Name | Default Action | Key Rules | Use Case |
| --- | --- | --- | --- |
| `no_exfiltration` | `LOG` | block read->send chains, alert high drift, block high injection | Production baseline with exfiltration controls |
| `strict` | `FLAG` | stricter drift/injection blocks, memory write alerts, deny execute-like tools | High-security workloads and privileged environments |
| `monitor_only` | `LOG` | log drift/injection only, never explicit block rules | Safe first rollout and telemetry-only tuning |

## Full Rule Breakdown

### `no_exfiltration`

- `block_read_send`: `TOOL_SEQUENCE` = `read_file -> send_email` -> `BLOCK` (`HIGH`)
- `block_read_upload`: `TOOL_SEQUENCE` = `read_file -> upload` -> `BLOCK` (`HIGH`)
- `alert_high_drift`: `GOAL_DRIFT >= 0.55` -> `ALERT` (`HIGH`)
- `block_high_injection`: `INJECTION_SCORE >= 0.80` -> `BLOCK` (`CRITICAL`)
- Default action: `LOG`

### `strict`

- `block_read_send`: `TOOL_SEQUENCE` = `read_file -> send_email` -> `BLOCK`
- `block_medium_drift`: `GOAL_DRIFT >= 0.35` -> `BLOCK`
- `block_medium_injection`: `INJECTION_SCORE >= 0.50` -> `BLOCK`
- `alert_memory_write`: any `MEMORY_WRITE` -> `ALERT`
- `block_execute_tools`: `TOOL_CALL` matches execute/shell/eval patterns -> `BLOCK`
- Denied tools list includes: `execute_code`, `bash`, `shell`, `run_command`, `eval`
- Default action: `FLAG`

### `monitor_only`

- `log_injection`: `INJECTION_SCORE >= 0.25` -> `LOG`
- `log_drift`: `GOAL_DRIFT >= 0.35` -> `LOG`
- No explicit block rules
- Default action: `LOG`