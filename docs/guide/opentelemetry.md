# OpenTelemetry

```bash
pip install "agentshield-x[otel]"
```

Every decision becomes one `agentshield.decision` span event with these attributes:

| Attribute | Value |
|---|---|
| `gen_ai.tool.name` | The tool |
| `agentshield.verdict` | `allow`, `deny` or `ask` |
| `agentshield.rule` | The rule that decided, or empty |
| `agentshield.reason` | Human-readable reason |
| `agentshield.session.id` | The session |
| `agentshield.policy.digest` | SHA-256 of the policy |

Arguments are never attached. The event joins the current span when one is recording (for
example a framework's `execute_tool` span); otherwise a short `execute_tool {name}` span is
started with the GenAI semantic-convention attributes `gen_ai.operation.name` and
`gen_ai.tool.name`.

Telemetry cannot affect enforcement: every error in it is swallowed. Configure your tracer
provider with a `BatchSpanProcessor` so export runs off the agent's thread; a
`SimpleSpanProcessor` exports inline and a slow collector would then slow tool calls.

```python
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

provider = TracerProvider()
provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
trace.set_tracer_provider(provider)
```

Without the extra, `opentelemetry` is never imported and nothing is emitted.
