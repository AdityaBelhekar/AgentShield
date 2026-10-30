# Installation

Python 3.11, 3.12 or 3.13.

```bash
pip install agentshield-x
```

The core depends on `pydantic` and `pyyaml` only. Everything else is an extra:

| Extra | Adds | Needed for |
|---|---|---|
| `[langchain]` | `langchain`, `langgraph` | [`shield.langchain()`](../guide/langchain.md) |
| `[audit]` | `cryptography` | Ed25519-signed [audit checkpoints](../guide/audit-log.md) |
| `[otel]` | `opentelemetry-api` | [OpenTelemetry events](../guide/opentelemetry.md) |
| `[classifier]` | `onnxruntime`, `tokenizers`, `huggingface-hub`, `numpy` | The bundled [prompt-injection classifier](../guide/detectors.md) |
| `[bench]` | `agentdojo` | [`agentshield bench`](../benchmark.md) |

```bash
pip install "agentshield-x[langchain,audit]"
```

The [MCP gateway](../guide/mcp-gateway.md), the [flow-graph viewer](../guide/audit-log.md#flow-graph)
and audit verification need no extra.

## From a checkout

```bash
git clone https://github.com/AdityaBelhekar/AgentShield
cd AgentShield
pip install -e ".[dev]"
python examples/exfil_demo.py
```

## Upgrading from 0.1.x

The 0.1.x API (`shield()`, the detectors, adapters, dashboard and red-team CLI) was removed
in 0.2.0 and has no compatibility layer. See the
[changelog](https://github.com/AdityaBelhekar/AgentShield/blob/main/CHANGELOG.md).
