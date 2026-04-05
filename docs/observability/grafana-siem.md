# Grafana & SIEM

## Grafana / Prometheus Path

`PrometheusExporter` subscribes to Redis events and exposes runtime metrics on `/metrics`.

Example metrics include:

- `agentshield_threats_total`
- `agentshield_sessions_active`
- `agentshield_detection_score`
- `agentshield_policy_blocks_total`
- `agentshield_canary_triggers_total`
- `agentshield_session_duration_seconds`

## SIEM Path

`SIEMManager` orchestrates syslog and HTTP exporters behind one API.

`SIEMConfig` supports:

- syslog export (`udp` or `tcp`)
- HTTP export (`generic` or `splunk_hec`)
- severity threshold gating (`INFO` .. `CRITICAL`)

## Example

```python
from agentshield.siem import SIEMConfig, SIEMManager

siem_config = SIEMConfig(
    syslog_enabled=True,
    syslog_host="siem.local",
    syslog_port=514,
    syslog_protocol="udp",
    min_severity="LOW",
)

siem = SIEMManager(
    siem_config=siem_config,
    redis_url="redis://localhost:6379",
)
```

For Grafana dashboards, start from `agentshield/observability/grafana_dashboard.json` and tune panels to your incident-response workflow.