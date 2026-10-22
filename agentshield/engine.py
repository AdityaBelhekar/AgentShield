"""The deterministic enforcement engine every tool call must pass through.

``check`` is evaluated on every call, in this order: deny-list, unlabelled default,
flow rules against the session's taint, then limits. ``record`` is called after a tool
returns and is the only place that grows the session's taint.

Fail-closed: if the engine cannot decide, the answer is ``deny``. In ``monitor`` mode the
same evaluation runs and the decision is reported, but the returned verdict is ``allow``.
"""

from __future__ import annotations

from agentshield.arguments import argument_violation, sensitive_argument_touched
from agentshield.exceptions import AgentShieldError
from agentshield.policy import Flow, Policy
from agentshield.session import Decision, Label, Session, ToolCall, Verdict, current_session


class EnforcementEngine:
    """Applies one immutable policy to tool calls for a session."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def check(self, call: ToolCall, session: Session | None = None) -> Decision:
        """Decide whether ``call`` may run. Never raises; an internal error is a deny."""
        try:
            return self._decide(call, session if session is not None else current_session())
        except Exception as exc:  # noqa: BLE001 - enforcement must fail closed
            return Decision(
                Verdict.DENY,
                f"internal error while evaluating {call.name!r}: {type(exc).__name__}: {exc}",
                rule="internal-error",
            )

    def record(self, call: ToolCall, result: object = None, session: Session | None = None) -> None:
        """Account for a completed tool call and taint the session with its labels."""
        active = session if session is not None else current_session()
        if active is None:
            raise AgentShieldError(f"cannot record {call.name!r}: no active session")
        active.tool_calls += 1
        active.identical_calls[call.name] += 1
        rule = self.policy.tools.get(call.name)
        if rule is not None:
            active.taint.update(rule.labels)
            if sensitive_argument_touched(call, rule):
                active.taint.add(Label.CONFIDENTIAL)

    def _decide(self, call: ToolCall, session: Session | None) -> Decision:
        if session is None:
            return Decision(
                Verdict.DENY,
                "no active session; open one with `shield.session(...)`",
                rule="session",
            )

        rule = self.policy.tools.get(call.name)
        if rule is None:
            decision = Decision(
                self.policy.unlabelled_tools,
                f"tool {call.name!r} is not declared in the policy",
                rule="unlabelled_tools",
            )
            if decision.verdict is not Verdict.ALLOW:
                return self._monitor(decision)
        elif rule.deny:
            return self._monitor(
                Decision(
                    Verdict.DENY,
                    f"tool {call.name!r} is denied by the policy",
                    rule=f"tools.{call.name}.deny",
                )
            )
        else:
            violation = argument_violation(call, rule)
            if violation is not None:
                return self._monitor(
                    Decision(
                        Verdict.DENY,
                        violation,
                        rule=f"tools.{call.name}.args",
                    )
                )

        labels = rule.labels if rule is not None else frozenset()
        for flow in self.policy.flows:
            if _matches(flow, call, labels, session):
                return self._monitor(
                    Decision(
                        flow.verdict,
                        f"flow {flow.name!r} matched for tool {call.name!r}",
                        rule=flow.name,
                    )
                )

        limits = self.policy.limits
        if limits.max_tool_calls is not None and session.tool_calls >= limits.max_tool_calls:
            return self._monitor(
                Decision(
                    Verdict.DENY,
                    f"session has reached its {limits.max_tool_calls} tool-call limit",
                    rule="limits.max_tool_calls",
                )
            )
        if (
            limits.max_identical_calls is not None
            and session.identical_calls[call.name] >= limits.max_identical_calls
        ):
            return self._monitor(
                Decision(
                    Verdict.DENY,
                    f"tool {call.name!r} has been called {limits.max_identical_calls} times "
                    "in this session",
                    rule="limits.max_identical_calls",
                )
            )

        return Decision(Verdict.ALLOW, f"tool {call.name!r} is allowed by the policy")

    def _monitor(self, decision: Decision) -> Decision:
        if self.policy.mode != "monitor" or decision.verdict is Verdict.ALLOW:
            return decision
        return Decision(
            Verdict.ALLOW,
            f"monitor: would {decision.verdict.value}: {decision.reason}",
            rule=decision.rule,
        )


def _matches(flow: Flow, call: ToolCall, labels: frozenset[Label], session: Session) -> bool:
    condition = flow.when
    return (
        condition.session_has <= session.taint
        and condition.tool_has <= labels
        and (condition.tool is None or condition.tool == call.name)
    )
