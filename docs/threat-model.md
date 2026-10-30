# Threat model

AgentShield is a reference monitor for tool calls. This page says what it defends, what it
assumes, and what it does not cover.

## What it protects

The asset is what an agent can **do**: the tool calls it makes and the data those calls
carry. The defended outcome is narrow:

> Once a session has read both untrusted and confidential data, a tool labelled external
> needs approval. A tool marked `deny` never runs. An undeclared tool is denied by default.

Everything else (argument checks, the canary, delimiting, detectors, audit) supports that
guarantee or makes it observable.

## Attacker

- **Can** control the content of anything an `untrusted` tool returns: web pages, emails,
  documents, issue comments, MCP server responses.
- **Can** write instructions into that content and hope the model follows them (indirect
  prompt injection).
- **Can** run or modify an MCP server the agent connects to, including rewriting tool
  descriptions after they were reviewed.
- **Cannot** edit your policy, your code, the AgentShield process or the audit log's header
  key. If they can, AgentShield gives no guarantee.

## Trust assumptions

- **The labels are right.** The policy is your statement of what each tool touches. A tool
  labelled `confidential` that is really attacker-controlled taints the session wrongly.
- **Every tool goes through an entry point**: `shield.tool`, the LangChain middleware or
  the MCP gateway. A call that bypasses them is invisible.
- **The approver is a human paying attention.** `ask` is only as good as the person
  answering it.
- **The process is trusted.** Tool code runs with your privileges; AgentShield is not a
  sandbox.

## In scope

| Threat | Mechanism |
|---|---|
| Exfiltration after reading attacker-controlled content | Session taint and flows (`untrusted` + `confidential` → `external` asks) |
| Calling a dangerous tool at all | `deny: true`; `unlabelled_tools: deny` |
| Reading secret paths, reaching unapproved hosts | `deny_glob`, `allow_domains`, `deny_regex` |
| Credentials in outbound arguments | Secret scan on `external` tools |
| System prompt exfiltration | Per-session canary in arguments and final output |
| Runaway loops | `max_tool_calls`, `max_identical_calls` |
| MCP tool descriptions changed after review ("rug pull") | Gateway lockfile |
| Starting an unapproved MCP server | `mcp.allowed_servers` |
| Undetected tampering with the decision record | Hash chain, signed checkpoints, `audit verify` |
| A wrong or slow detector loosening a decision | Detectors can only add `ask` or taint; errors fail closed |

## Out of scope

- **Value-level tracking.** Taint is per session and per label, not per value. Once a session
  is tainted, every external call asks, even one that carries no secret.
- **Telling data from instructions.** Labels come from the policy, not the content.
  Delimiting and the optional classifier help a model ignore injected text; neither is a
  boundary.
- **Direct prompt injection and misuse within allowed flows.** A model persuaded to do
  something harmful without crossing a labelled flow is not stopped.
- **Sandboxing.** No syscall, filesystem or network enforcement. A malicious tool can do
  anything your process can.
- **Multi-agent identity and delegation.** One session is one agent run; agents calling
  agents are not modelled.
- **Supply-chain integrity of packages and models.** The classifier is pinned to a revision
  but not signature-verified.
- **Tamper-proof logging.** The log is tamper-evident; whoever can rewrite the whole file and
  its header key can forge a chain. External anchoring is not provided.
- **Availability.** A denied or slow call degrades the agent; that is intended.

## OWASP Top 10 for Agentic Applications (2026)

Coverage against the [OWASP GenAI Security Project's list](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).
"Partial" means AgentShield limits the damage of the risk; it does not prevent the risk.

| ID | Risk | Coverage | How |
|---|---|---|---|
| ASI01 | Agent Goal Hijack | Partial | Cannot stop the hijack; stops the hijacked agent from completing labelled exfiltration flows and denied tools. Detectors may flag injected text. |
| ASI02 | Tool Misuse and Exploitation | **Primary** | Deny-list, default-deny, argument rules, flows and limits on every call. |
| ASI03 | Identity and Privilege Abuse | Partial | Least privilege per tool via the policy. No identity, credential or delegation management. |
| ASI04 | Agentic Supply Chain Vulnerabilities | Partial | MCP lockfile and server allow-list; draft policies treat server annotations as untrusted. Packages and models are not verified. |
| ASI05 | Unexpected Code Execution | Partial | A shell or code tool can be denied, or denied after untrusted input. No sandbox. |
| ASI06 | Memory and Context Poisoning | Partial | Results from untrusted tools taint the session and are delimited. Persistent memory across sessions is not tracked. |
| ASI07 | Insecure Inter-Agent Communication | Not covered | Treat another agent as an `untrusted` tool; no protocol-level protection. |
| ASI08 | Cascading Failures | Partial | Call limits and fail-closed decisions bound a runaway session. |
| ASI09 | Human-Agent Trust Exploitation | Partial | Approvals show the rule and reason and are audited. A persuaded human can still approve. |
| ASI10 | Rogue Agents | Partial | The audit log, flow graph and OpenTelemetry events make behaviour observable; the policy bounds what a rogue agent can call. |

## Reporting

Security issues: see [SECURITY.md](https://github.com/AdityaBelhekar/AgentShield/blob/main/SECURITY.md).
