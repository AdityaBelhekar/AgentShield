"""The public entry point."""

from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping, Sequence
from functools import wraps
from pathlib import Path
from typing import Any, overload

from agentshield.approvals import ApprovalHandler
from agentshield.audit import AuditLog
from agentshield.detectors import Detector
from agentshield.engine import EnforcementEngine
from agentshield.exceptions import (
    AgentShieldError,
    ApprovalRequired,
    CanaryLeakError,
    PolicyViolationError,
)
from agentshield.policy import Policy, load_policy
from agentshield.session import (
    Label,
    Session,
    SessionScope,
    ToolCall,
    Verdict,
    current_session,
)
from agentshield.spotlight import canary_instruction, delimit

ToolFunction = Callable[..., Any]


class Shield:
    """Holds one immutable policy, its enforcement engine, and opens sessions."""

    def __init__(
        self,
        policy: Policy | None = None,
        *,
        approval: ApprovalHandler | None = None,
        audit: AuditLog | str | Path | None = None,
        detectors: Sequence[Detector] = (),
    ) -> None:
        self.policy = policy if policy is not None else load_policy("strict")
        self.audit = AuditLog(audit) if isinstance(audit, (str, Path)) else audit
        self.engine = EnforcementEngine(self.policy, audit=self.audit, detectors=detectors)
        self.approval = approval

    @classmethod
    def from_policy(
        cls,
        source: str | Path | Mapping[str, Any],
        *,
        approval: ApprovalHandler | None = None,
        audit: AuditLog | str | Path | None = None,
        detectors: Sequence[Detector] = (),
    ) -> Shield:
        """Build a shield from a built-in policy name, a YAML file, or a mapping."""
        return cls(load_policy(source), approval=approval, audit=audit, detectors=detectors)

    def close(self) -> None:
        """Flush a final signed checkpoint and close the audit log, if one is open."""
        if self.audit is not None:
            self.audit.close()

    def session(self, *, user: str | None = None, task: str | None = None) -> SessionScope:
        """Start a session for one agent run.

        Use as ``with shield.session(user=...) as s:`` or ``async with``.
        """
        return SessionScope(Session(user=user, task=task))

    def system_prompt(self, text: str) -> str:
        """Append this session's canary instruction to a system prompt.

        Build the prompt inside ``with shield.session(...)`` so the marker belongs to the
        run it protects. ``check_output`` and the engine's argument check look for it.
        """
        session = current_session()
        if session is None:
            raise AgentShieldError("system_prompt() needs an active session")
        return f"{text}\n\n{canary_instruction(session.canary)}"

    def check_output(self, text: str) -> str:
        """Return ``text``, or raise ``CanaryLeakError`` if it leaks the session marker.

        Call this on the model's final answer. It is a check, not a filter: the caller
        decides what to do with the exception.
        """
        session = current_session()
        if session is not None and session.canary in text:
            raise CanaryLeakError("output contains the session's canary marker")
        return text

    def langchain(self) -> Any:
        """Return middleware that routes a LangChain / LangGraph agent's tool calls here.

        Pass it to ``create_agent(..., middleware=[shield.langchain()])``. Needs the
        ``[langchain]`` extra.
        """
        try:
            from agentshield.langchain import ShieldMiddleware
        except ImportError as exc:  # pragma: no cover - depends on the environment
            raise ImportError(
                "Shield.langchain() needs the LangChain extra: "
                'pip install "agentshield-x[langchain]"'
            ) from exc
        return ShieldMiddleware(self)

    @overload
    def tool(self, name: str) -> Callable[[ToolFunction], ToolFunction]: ...

    @overload
    def tool(self, name: str, fn: ToolFunction) -> ToolFunction: ...

    def tool(self, name: str, fn: ToolFunction | None = None) -> Any:
        """Wrap one sync or async callable so every call passes through the engine.

        Use as a decorator (``@shield.tool("read_file")``) or directly
        (``send = shield.tool("send_email", send)``). The wrapped function is unchanged
        apart from the check before it and the ``record`` after it.
        """
        if fn is None:
            return lambda function: self.tool(name, function)

        if inspect.iscoroutinefunction(fn):

            @wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                call = self._authorize(ToolCall(name, _bind_arguments(fn, args, kwargs)))
                try:
                    result = await fn(*args, **kwargs)
                except BaseException:
                    self.engine.record(call)
                    raise
                self.engine.record(call, result)
                return self._spotlight_result(call, result)

            return async_wrapper

        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            call = self._authorize(ToolCall(name, _bind_arguments(fn, args, kwargs)))
            try:
                result = fn(*args, **kwargs)
            except BaseException:
                self.engine.record(call)
                raise
            self.engine.record(call, result)
            return self._spotlight_result(call, result)

        return wrapper

    def _spotlight_result(self, call: ToolCall, result: Any) -> Any:
        """Delimit a string result from an ``untrusted`` tool; leave other results alone."""
        if not isinstance(result, str):
            return result
        rule = self.policy.tools.get(call.name)
        if rule is None or Label.UNTRUSTED not in rule.labels:
            return result
        return delimit(result, source=call.name)

    def _authorize(self, call: ToolCall) -> ToolCall:
        """Run the engine and any approval handler for one call, or raise."""
        decision = self.engine.check(call)
        if decision.verdict is Verdict.DENY:
            raise PolicyViolationError(decision.reason)
        if decision.verdict is Verdict.ASK:
            approved = self.approval is not None and self.approval(call, decision)
            if not self.engine.resolve_approval(call, approved):
                if self.approval is None:
                    raise ApprovalRequired(decision.reason)
                raise ApprovalRequired(f"approval denied: {decision.reason}")
        return call


def _bind_arguments(
    fn: ToolFunction, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    """Name the arguments the way the signature does, so a manifest can match them."""
    try:
        signature = inspect.signature(fn)
    except (TypeError, ValueError):
        named = {f"arg{i}": value for i, value in enumerate(args)}
        named.update(kwargs)
        return named
    bound = signature.bind(*args, **kwargs)
    bound.apply_defaults()
    return dict(bound.arguments)
