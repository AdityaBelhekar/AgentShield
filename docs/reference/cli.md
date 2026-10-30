# CLI

All commands are subcommands of `agentshield` (or `python -m agentshield`).

| Command | What it does |
|---|---|
| `agentshield gateway --policy P [--audit F] [--audit-key K] [--lock L] -- <cmd>` | Proxy a stdio MCP server, checking every `tools/call`. See [MCP gateway](../guide/mcp-gateway.md). |
| `agentshield draft-policy -- <cmd>` | Print a starting policy for an MCP server's tools. |
| `agentshield audit verify FILE [--json]` | Verify an audit log's hash chain and signatures. Exit 0 if valid, 1 if not. |
| `agentshield audit keygen --out FILE` | Write an unencrypted Ed25519 private key (PEM) for signed checkpoints. |
| `agentshield ui FILE [--policy P] [--out HTML]` | Render an audit log as an HTML flow graph. |
| `agentshield bench [--markdown \| --json] [--out F]` | Run AgentDojo banking through the engine (`[bench]` extra). See [benchmark](../benchmark.md). |
| `agentshield bench --model M [--base-url U] [--api-key K] [--attack A]` | The same with a real model. |
| `agentshield bench --classifier [--threshold T]` | Measure the bundled classifier (`[classifier]` extra). |

Exit code 2 means a usage or configuration error (bad policy, missing extra, unreadable
file); the message goes to standard error.
