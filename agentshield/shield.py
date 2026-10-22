"""The public entry point."""

from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping
from functools import wraps
from pathlib import Path
from typing import Any, overload

from agentshield.approvals import ApprovalHandler
from agentshield.engine import EnforcementEngine
from agentshield.exceptions import ApprovalRequired, PolicyViolationError
from agentshield.policy import Policy, load_policy
from agentshield.session import Session, SessionScope, ToolCall, Verdict

ToolFunction = Callable[..., Any]


class Shield:
    """Holds one immutable policy, its enforcement engine, and opens sessions."""

    def __init__(
        self, policy: Policy | None = None, *, approval: ApprovalHandler | None = None
    ) -> None:
        self.policy = policy if policy is not None else load_policy("strict")
        self.engine = EnforcementEngine(self.policy)
        self.approval = approval

    @classmethod
    def from_policy(
        cls,
        source: str | Path | Mapping[str, Any],
        *,
        approval: ApprovalHandler | None = None,
    ) -> Shield:
        """Build a shield from a built-in policy name, a YAML file, or a mapping."""
        return cls(load_policy(source), approval=approval)

    def session(self, *, user: str | None = None, task: str | None = None) -> SessionScope:
        """Start a session for one agent run.

        Use as ``with shield.session(user=...) as s:`` or ``async with``.
        """
        return SessionScope(Session(user=user, task=task))

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
                call = self._gate(name, _bind_arguments(fn, args, kwargs))
                try:
                    return await fn(*args, **kwargs)
                finally:
                    self.engine.record(call)

            return async_wrapper

        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            call = self._gate(name, _bind_arguments(fn, args, kwargs))
            try:
                return fn(*args, **kwargs)
            finally:
                self.engine.record(call)

        return wrapper

    def _gate(self, name: str, arguments: dict[str, Any]) -> ToolCall:
        call = ToolCall(name=name, args=arguments)
        decision = self.engine.check(call)
        if decision.verdict is Verdict.DENY:
            raise PolicyViolationError(decision.reason)
        if decision.verdict is Verdict.ASK:
            if self.approval is None:
                raise ApprovalRequired(decision.reason)
            if not self.approval(call, decision):
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
