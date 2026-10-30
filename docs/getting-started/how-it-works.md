# How it decides

AgentShield is a reference monitor: one deterministic engine that every checked tool call
passes through. It has three pieces of state.

- **The policy**: immutable once loaded. It labels each tool and declares forbidden flows.
- **The session**: one agent run. It holds the run's *taint* (which labels it has
  touched) and its call counters. It lives in a `ContextVar`, so concurrent runs in
  threads or asyncio tasks never see each other's taint.
- **The labels**: `untrusted` (the result may contain attacker-controlled text),
  `confidential` (the result must not leave), `external` (the tool sends data out).

## Before a call: `check`

Evaluated on every call, in this order:

1. **Deny-list.** A tool declared `deny: true` never runs.
2. **Labels.** An undeclared tool gets `unlabelled_tools` (default `deny`).
3. **Arguments.** Path deny-globs, URL domain allow-lists, regex denies; credential-shaped
   values in an `external` tool's arguments; the session's canary marker anywhere.
4. **Flows.** Session taint × the tool's labels, for example
   `session_has: [untrusted, confidential]` with `tool_has: [external]`.
5. **Limits.** Total calls and identical calls per session.
6. **Detectors** (optional). Only on a call that would be allowed: a flag makes it `ask`.

A `deny` flow or a limit always wins over an `ask` flow, so more taint can only make a
decision stricter. If the engine cannot decide (an internal error, a failed audit write),
the answer is `deny`.

The verdict is `allow`, `deny`, or `ask`. `ask` goes to your approval handler; without one
it raises `ApprovalRequired`. An approval covers one call and is written to the audit log.

## After a call: `record`

The tool's labels are added to the session's taint, plus `confidential` if an argument
matched a `sensitive_glob`, plus `untrusted` if a detector flagged the result. Taint is only
ever added within a session. `record` is the only place it grows.

## Results from untrusted tools

String results from `untrusted` tools are wrapped in delimiters with a random nonce, so the
model is told where data starts and ends and fetched content cannot close the block early.
This makes injected text easier to ignore. It is not a boundary.

## The canary

`shield.system_prompt(text)` appends a random per-session marker to your system prompt.
The marker has no reason to appear anywhere else: a tool call carrying it is denied, and
`shield.check_output(answer)` raises `CanaryLeakError` if the final answer contains it.

## Monitor mode

`mode: monitor` runs the same evaluation and records what it would have done, but allows
the call. Use it to roll out a policy, then switch to `enforce`.
