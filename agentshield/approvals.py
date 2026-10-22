"""Approval handlers for calls the policy answers with ``ask``.

A handler receives the call and the decision that produced it, and returns ``True`` to
allow this one call. An approval is about a single call: it never changes the policy and
never clears the session's taint.
"""

from __future__ import annotations

from collections.abc import Callable

from agentshield.session import Decision, ToolCall

ApprovalHandler = Callable[[ToolCall, Decision], bool]
"""Decide whether one ``ask`` call may run. Returning ``False`` denies it."""


def terminal_approval(call: ToolCall, decision: Decision) -> bool:
    """Ask on the terminal. Only an explicit ``y`` or ``yes`` allows the call."""
    print(f"\nAgentShield needs approval for {call.name!r}")
    print(f"  reason: {decision.reason}")
    print(f"  rule:   {decision.rule or '(none)'}")
    print(f"  args:   {dict(call.args)!r}")
    try:
        answer = input("Allow this call once? [y/N] ").strip().lower()
    except EOFError:
        return False
    return answer in {"y", "yes"}
