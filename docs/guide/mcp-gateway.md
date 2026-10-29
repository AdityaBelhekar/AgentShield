# MCP gateway

The gateway sits between any MCP client and a stdio MCP server. Every `tools/call` is
checked by the engine; every other message passes through byte for byte, so it works with
whatever protocol version the two ends negotiate. No extra is needed.

```bash
agentshield gateway --policy policy.yaml --audit audit.jsonl -- python my_server.py
```

In the client's server configuration, use that whole line as the server command.

To see it work with nothing installed but AgentShield, run
`python examples/mcp_gateway_demo.py`: a scripted client fetches a page, reads a secret
and tries to email it through the gateway, and the server never receives the email call.

## What happens to a call

- **allow**: forwarded unchanged. The response is recorded (taint), and the text content
  of an `untrusted` tool's result is delimited.
- **deny** or **ask**: answered by the gateway with a tool error the model can read. The
  server never sees the request. There is no human on a stdio pipe, so `ask` is a denial
  (and is audited as an unapproved `ask`).

Fail-closed on input it cannot read: a client line that is not one JSON object with unique
keys, or a batch containing a `tools/call`, gets an error instead of being forwarded.

One gateway process serves one client connection and holds one session.

## Servers you did not write

```bash
# A starting policy: every tool at [untrusted, external], the server's
# descriptions and annotations as comments only.
agentshield draft-policy -- python my_server.py > policy.yaml

# Pin tool definitions on first sight.
agentshield gateway --policy policy.yaml --lock mcp.lock.json -- python my_server.py
```

- **Draft policy.** Annotations such as `readOnlyHint` come from the server and are not
  trusted: the draft labels every tool at its most restrictive and shows the hints for you
  to review. It also sets `mcp.allowed_servers` to the command.
- **Lockfile.** The hash of each tool's name, title, description, input schema and
  annotations is pinned the first time it is listed. If a later listing differs, calls to
  that tool are denied: a description is part of the prompt, and a server that rewrites it
  after review is changing what the model is told. Delete the tool's entry from the
  lockfile to accept the new version. The check runs on `tools/list` responses that pass
  through the gateway, so a client that calls a tool without listing it is not covered.
- **Allow-list.** `mcp.allowed_servers` in the policy lists the exact commands (words
  joined by single spaces) the gateway may start.

## Options

| Option | Meaning |
|---|---|
| `--policy` | Built-in name or YAML file. Required. |
| `--audit FILE` | Append decisions to a JSONL [audit log](audit-log.md). |
| `--audit-key PEM` | Sign audit checkpoints with this Ed25519 key (`[audit]` extra). |
| `--lock FILE` | Pin tool definitions in this lockfile. |
