# Agent DNA Fingerprinting

## 1. The Problem

Traditional detector stacks are signature-heavy, so unknown attack paths can evade static rules while still causing unusual runtime behavior. Most agent systems also lack per-agent behavioral baselines, making it hard to distinguish normal variance from compromised operation.

## 2. How AgentShield Solves It

AgentShield builds a per-agent behavioral baseline from clean sessions and scores each completed session against that baseline. This converts runtime telemetry into a stable "DNA" profile that catches deviations even when no known injection phrase or tool-chain signature appears.

## 3. Technical Detail

### Feature Vector (13 Features)

| Feature | Weight |
| --- | ---: |
| `tool_call_count` | 1.0 |
| `unique_tools_used` | 1.0 |
| `tool_diversity` | 1.5 |
| `mean_prompt_length` | 1.0 |
| `prompt_length_variance` | 1.0 |
| `tool_call_velocity` | 2.0 |
| `session_duration_seconds` | 0.5 |
| `memory_write_count` | 1.5 |
| `memory_read_count` | 1.0 |
| `mean_response_length` | 1.0 |
| `llm_call_count` | 1.0 |
| `max_tool_chain_depth` | 2.0 |
| `threat_detector_firings` | 3.0 |

### Baseline Establishment

- Minimum sessions required: `dna_min_sessions = 10` (configurable).
- Baseline updates use **clean sessions only** (`is_clean=True`, no confirmed threats).
- Stored baseline stats include `mean_vector`, `std_vector`, `min_vector`, and `max_vector`.

### Anomaly Scoring Formula

For each feature $i$:

$$
z_i = \frac{x_i - \mu_i}{\sigma_i}
$$

$$
c_i = \frac{\max(0, |z_i| - 1)}{\text{anomaly\_sensitivity}}
$$

$$
\text{weighted}_i = c_i \cdot w_i
$$

$$
\text{composite} = \mathrm{clip}\left(\frac{\sum_i \text{weighted}_i}{\sum_i w_i},\ 0,\ 1\right)
$$

Default anomaly threshold: `anomaly_sensitivity = 0.85`.

## 4. Code Example

```python
from agentshield.config import AgentShieldConfig
from agentshield.dna.baseline import DNASystem

config = AgentShieldConfig(dna_min_sessions=10, anomaly_sensitivity=0.85)
dna = DNASystem(config)

# During runtime, events are streamed into the DNA system per session.
# After session close, score_session compares this session to baseline.
```

## 5. Limitations and Future Work

- Requires enough clean history before it can score reliably.
- Fast product changes can shift normal behavior, requiring adaptive baseline hygiene.
- Future work includes online drift compensation and feature attribution tuned by workload type.