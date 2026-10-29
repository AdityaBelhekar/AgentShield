"""The deterministic enforcement engine every tool call must pass through.

``check`` is evaluated on every call, in this order: deny-list, unlabelled default,
flow rules against the session's taint, then limits. ``record`` is called after a tool
returns and is the only place that grows the session's taint.

Optional detectors (``agentshield.detectors``) run after the policy, and only on a call it
allows: a flag turns ``allow`` into ``ask``. On ``record`` a flagged result adds
``untrusted`` taint. Neither path can loosen a decision.

Fail-closed: if the engine cannot decide, the answer is ``deny``. In ``monitor`` mode the
same evaluation runs and the decision is reported, but the returned verdict is ``allow``.
"""

from __future__ import annotations

from collections.abc import Sequence

from agentshield.arguments import argument_violation, sensitive_argument_touched
from agentshield.audit import AuditLog
from agentshield.detectors import Detector, as_text, run_detectors
from agentshield.exceptions import AgentShieldError
from agentshield.policy import Flow, Policy
from agentshield.session import Decision, Label, Session, ToolCall, Verdict, current_session
from agentshield.spotlight import contains_marker
from agentshield.telemetry import emit_decision


class EnforcementEngine:
    """Applies one immutable policy to tool calls for a session."""

    def __init__(
        self,
        policy: Policy,
        *,
        audit: AuditLog | None = None,
        detectors: Sequence[Detector] = (),
        detector_timeout: float = 2.0,
    ) -> None:
        self.policy = policy
        self.audit = audit
        self.detectors = tuple(detectors)
        self.detector_timeout = detector_timeout

    def check(self, call: ToolCall, session: Session | None = None) -> Decision:
        """Decide whether ``call`` may run. Never raises; an internal error is a deny."""
        active = session if session is not None else current_session()
        try:
            decision = self._decide(call, active)
            # rule is None only for a plain allow, not a monitor-mode "would deny".
            if decision.verdict is Verdict.ALLOW and decision.rule is None and self.detectors:
                flagged = run_detectors(
                    self.detectors, as_text(dict(call.args)), self.detector_timeout
                )
                if flagged is not None:
                    decision = self._monitor(
                        Decision(
                            Verdict.ASK,
                            f"detector {flagged} flagged the arguments of {call.name!r}",
                            rule=f"detector.{flagged.split(' ')[0]}",
                        )
                    )
        except Exception as exc:  # noqa: BLE001 - enforcement must fail closed
            decision = Decision(
                Verdict.DENY,
                f"internal error while evaluating {call.name!r}: {type(exc).__name__}: {exc}",
                rule="internal-error",
            )

        if self.audit is not None:
            try:
                self.audit.write(call, decision, active, policy=self.policy.digest)
            except Exception as exc:  # noqa: BLE001 - no audit, no authorization
                decision = Decision(
                    Verdict.DENY,
                    f"audit failure while recording {call.name!r}: {type(exc).__name__}: {exc}",
                    rule="audit-error",
                )
        emit_decision(call, decision, active, self.policy.digest)
        return decision

    def resolve_approval(
        self, call: ToolCall, approved: bool, session: Session | None = None
    ) -> bool:
        """Audit the outcome of an ``ask``. Returns whether the call may run.

        An approval that cannot be written to the audit log is not granted.
        """
        active = session if session is not None else current_session()
        decision = Decision(
            Verdict.ALLOW if approved else Verdict.DENY,
            "approved" if approved else "approval not granted",
            rule="approval",
        )
        if self.audit is not None:
            try:
                self.audit.write(call, decision, active, policy=self.policy.digest)
            except Exception:  # noqa: BLE001 - no audit, no authorization
                return False
        return approved

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
        if (
            self.detectors
            and Label.UNTRUSTED not in active.taint
            and run_detectors(self.detectors, as_text(result), self.detector_timeout) is not None
        ):
            active.taint.add(Label.UNTRUSTED)

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

        if contains_marker(call.args, session.canary):
            return self._monitor(
                Decision(
                    Verdict.DENY,
                    "a tool argument contains the session's canary marker",
                    rule="canary",
                )
            )

        labels = rule.labels if rule is not None else frozenset()
        # A deny flow or a limit beats an ask flow, whatever the order, so more taint can
        # never turn a deny into an ask.
        asked: Decision | None = None
        for flow in self.policy.flows:
            if _matches(flow, call, labels, session):
                decision = Decision(
                    flow.verdict,
                    f"flow {flow.name!r} matched for tool {call.name!r}",
                    rule=flow.name,
                )
                if decision.verdict is Verdict.DENY:
                    return self._monitor(decision)
                asked = asked or decision

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

        if asked is not None:
            return self._monitor(asked)
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
