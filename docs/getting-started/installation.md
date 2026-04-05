# Installation

## Requirements

- Python 3.11+
- `pip` 23+
- Redis (required for pub/sub event streaming and the live dashboard)

## Install AgentShield

```bash
pip install agentshield-sdk
```

## Optional Extras

```bash
pip install "agentshield-sdk[redis]"
pip install "agentshield-sdk[otel]"
pip install "agentshield-sdk[all]"
```

If you are using the current public build where OpenTelemetry extras are published under `observability`, use:

```bash
pip install "agentshield-sdk[observability]"
```

## Redis Setup

AgentShield can run without Redis for local-only runtime behavior, but Redis is required for:

- real-time event pub/sub,
- backend live feed fanout, and
- frontend dashboard streaming.

Run Redis locally:

```bash
docker run --name agentshield-redis -p 6379:6379 -d redis:7-alpine
```

## Verify Installation

```bash
python -c "import agentshield; print(agentshield.__version__)"
```