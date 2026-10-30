# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately to: belhekaraditya96@gmail.com
Subject line: `[AgentShield SECURITY] Brief description`

Include:
- Description of the vulnerability
- Steps to reproduce (a policy and a short script are ideal)
- Potential impact
- Suggested fix (if any)

We aim to acknowledge within 48 hours and agree a timeline for the fix. Reporters are
credited in the CHANGELOG unless they ask not to be.

## What counts as a vulnerability

AgentShield's guarantees are stated in the [threat model](docs/threat-model.md). A report is
a vulnerability when it breaks one of them, for example:

- a tool call marked `deny`, an undeclared tool under `unlabelled_tools: deny`, or a call
  matching a `deny` flow runs anyway;
- a session holding `untrusted` and `confidential` taint reaches an `external` tool under
  the `strict` flow without an approval;
- an argument rule or the outbound secret scan can be bypassed by an encoding the engine
  should have normalised;
- the MCP gateway forwards a `tools/call` the engine did not check, or a changed tool
  definition is not caught under `--lock`;
- a detector, telemetry exporter or audit failure turns a `deny` or `ask` into `allow`;
- an edited, deleted or reordered audit record passes `agentshield audit verify`;
- the flow-graph page executes content from an audit log.

Not vulnerabilities, because the threat model puts them out of scope: prompt injection that
stays inside allowed flows, a wrong label in your policy, code run by a tool you allowed,
calls that bypass every entry point, and rewriting an entire audit file including its header
key.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | ✅        |
| 0.2.x   | Critical fixes until 0.4.0 |
| 0.1.x   | ❌ (removed; upgrade) |
