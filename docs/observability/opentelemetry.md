# OpenTelemetry

AgentShield can export traces and metrics through OTLP for centralized observability.

## Configuration

Core fields in `OTelConfig`:

- `enabled`
- `service_name`
- `service_version`
- `otlp_endpoint` (default `http://localhost:4317`)
- `export_traces`
- `export_metrics`
- `export_timeout_ms`
- `redis_channel`

## Example

```python
from agentshield.config import AgentShieldConfig
from agentshield.observability import OTelConfig, OTelExporter

runtime_config = AgentShieldConfig(
    otel_enabled=True,
    otel_otlp_endpoint="http://localhost:4317",
)

otel_config = OTelConfig(
    enabled=True,
    service_name="agentshield",
    service_version="0.1.0",
    otlp_endpoint="http://localhost:4317",
)

exporter = OTelExporter(
    otel_config=otel_config,
    redis_url=runtime_config.redis_url,
)
```

## Operational Notes

- Ensure collector endpoint is reachable from your runtime network.
- Keep exporter timeouts low enough to avoid backpressure in degraded environments.
- Use trace + metric correlation to tie policy blocks to upstream request lifecycles.