# Policies

A policy is YAML, a Python mapping, or a built-in name. It is validated into immutable
models: unknown keys, labels, actions and tools are rejected with the offending field named,
and duplicate YAML keys are rejected instead of silently overwritten.

```python
shield = Shield.from_policy("policy.yaml")      # a file
shield = Shield.from_policy("strict")           # a built-in
shield = Shield.from_policy({"extends": "strict", "tools": {...}})  # a mapping
```

## A complete example

```yaml
version: 2
name: support-agent
extends: strict          # optional: start from a built-in
mode: enforce            # or monitor
unlabelled_tools: deny   # deny, ask or allow

tools:
  web_fetch:
    labels: [untrusted]
    args:
      url:
        allow_domains: [docs.example.com]
  read_file:
    labels: [confidential]
    args:
      path:
        deny_glob: ["**/.env", "**/.ssh/**", "**/id_rsa"]
        sensitive_glob: ["**/secrets/**"]
  send_email:
    labels: [external]
  bash:
    deny: true

flows:
  - name: lethal-trifecta
    when:
      session_has: [untrusted, confidential]
      tool_has: [external]
    then: ask
  - name: no-shell-after-untrusted
    when: {session_has: [untrusted], tool: bash}
    then: deny

limits:
  max_tool_calls: 50
  max_identical_calls: 5

mcp:                      # used only by `agentshield gateway`
  allowed_servers: ["python my_server.py"]
```

## Fields

| Field | Meaning |
|---|---|
| `version` | Always `2`. |
| `extends` | `strict` or `monitor`. Your `tools` and `limits` are merged over the built-in's; your `flows` are appended. |
| `mode` | `enforce` blocks. `monitor` records what it would have done and allows the call. |
| `unlabelled_tools` | Verdict for a tool not under `tools`. Default `deny`. |
| `tools.<name>.labels` | Any of `untrusted`, `confidential`, `external`. Tool names match exactly. |
| `tools.<name>.deny` | `true`: the tool never runs. |
| `tools.<name>.args.<param>` | Checks on one argument, matched by parameter name (see below). |
| `flows[]` | `name`, `when` (all conditions must hold), `then` (`deny` or `ask`). |
| `flows[].when.session_has` | Labels the session's taint must all include. |
| `flows[].when.tool_has` | Labels the called tool must all have. |
| `flows[].when.tool` | One tool name, which must be declared under `tools`. |
| `limits.max_tool_calls` | Calls per session; the next one is denied. |
| `limits.max_identical_calls` | Calls to the same tool per session. |
| `mcp.allowed_servers` | Exact server commands the [gateway](mcp-gateway.md) may start. |

A `deny` flow or a limit wins over an `ask` flow regardless of order.

## Argument rules

| Rule | Effect |
|---|---|
| `deny_glob` | Deny when the argument (a path) matches. `~` and `..` are normalised first. |
| `deny_regex` | Deny when the regex matches anywhere in the argument. |
| `allow_domains` | Deny a URL whose host is not one of these or a subdomain. Bare hostnames only. |
| `sensitive_glob` | Never denies. A match adds `confidential` taint after the call runs. |

Independently of rules, an `external` tool's arguments are scanned for credential-shaped
values (AWS, OpenAI, Anthropic, GitHub, Slack, Stripe and Google keys, private-key headers),
and such a call is denied.

## Built-ins

`strict`: `unlabelled_tools: deny`, the flow
`untrusted-and-confidential-to-external` (`ask`), `max_tool_calls: 50`,
`max_identical_calls: 5`. `monitor`: the same rules in `monitor` mode.

## Policy digest

`shield.policy.digest` is a SHA-256 of the effective policy, stable across processes and
YAML formatting. Every audit record carries it, so a log names the exact rules it was
decided under.
