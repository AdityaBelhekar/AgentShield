# AgentShield

**A policy-enforcing reference monitor for AI agent tool calls.** Version 0.3.0, alpha.

!!! warning "Not a sandbox"
    AgentShield decides whether one tool call may run, from labels you assign to your tools
    and the taint of the current session. It cannot tell data from instructions inside a
    tool result, and it does not isolate tool code. Read the
    [threat model](threat-model.md) before relying on it.

The guarantee is narrow and explicit: **once a session has read both untrusted and
confidential data, a tool marked external needs approval.** Every checked call is evaluated
before it runs, fail-closed, and recorded after. Undeclared tools are denied by default.

```bash
pip install agentshield-x
```

The core install is `pydantic` and `pyyaml`. No model download, no network call on import.

## Where it sits

| Entry point | Use it for |
|---|---|
| [`shield.tool(...)`](getting-started/quickstart.md) | Plain Python sync and async tool functions |
| [`shield.langchain()`](guide/langchain.md) | LangChain / LangGraph agents |
| [`agentshield gateway`](guide/mcp-gateway.md) | Any MCP client talking to a stdio MCP server |

Around the engine: an [audit log](guide/audit-log.md) with a flow-graph viewer,
[OpenTelemetry events](guide/opentelemetry.md), optional
[detectors](guide/detectors.md), and a reproducible [benchmark](benchmark.md).

## Start here

1. [Install](getting-started/installation.md) and pick your extras.
2. Run the [quickstart](getting-started/quickstart.md): a scripted agent tries to email a
   secret and is stopped before the call runs.
3. Read [how it decides](getting-started/how-it-works.md), then write your
   [policy](guide/policies.md).
