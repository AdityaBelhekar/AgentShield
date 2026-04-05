# Behavioral Anomalies

## 1. What Is This Threat

Behavioral anomalies are deviations from how a specific agent normally operates, even when no known attack signature matches. This catches unknown attack paths that manifest as unusual behavior patterns.

## 2. How AgentShield Detects It

At session close, `DNAAnomalyScorer` compares the session's 13-feature vector to the established baseline (`AgentBaseline`) using weighted z-score contributions. This is behavior-first detection, not static pattern matching.

## 3. Detection Thresholds

- Baseline establishment minimum: `dna_min_sessions = 10` clean sessions
- Global sensitivity threshold: `anomaly_sensitivity = 0.85`
- Threat event mapping:
  - score `>= 0.90` -> `ALERT` (`HIGH`)
  - score `>= 0.85` -> `FLAG` (`MEDIUM`)

## 4. Example Attack Payload

```text
[SIMULATION] Trigger deep tool-chain nesting and abnormal call velocity far above historical baseline.
```

## 5. What Happens When Detected

Behavioral anomalies are emitted as `THREAT_DETECTED` with `ThreatType.BEHAVIORAL_ANOMALY` and rich feature evidence. They can remain informational in monitor mode or escalate to block when combined with other detectors through correlation.

## 6. Relevant Policy Rules

- Built-in policies do not include a dedicated DNA-specific condition, so handling is mainly via default actions and correlation.
- `strict` policy's lower thresholds in other detectors make behavioral anomalies more likely to converge into blocking outcomes.
- Custom policies can still gate downstream actions using threat score-oriented conditions.