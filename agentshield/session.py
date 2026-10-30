"""Session vocabulary and the context that scopes one agent run.

A session records what an agent run has touched (its taint) and how many tool calls it
has made. The current session lives in a ``ContextVar``, so concurrent requests in
threads or asyncio tasks each see their own, while work spawned *inside* a session
(``asyncio.gather``, ``copy_context().run``) shares it.
"""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Mapping
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from enum import StrEnum
from types import TracebackType
from typing import Any

from agentshield.exceptions import AgentShieldError
from agentshield.spotlight import new_canary


class Label(StrEnum):
    """What a tool's data is, or what a tool does with data."""

    UNTRUSTED = "untrusted"
    """The tool's result may contain attacker-controlled content."""
    CONFIDENTIAL = "confidential"
    """The tool's result contains data that must not leave the system."""
    EXTERNAL = "external"
    """The tool sends data outside the system."""


class Verdict(StrEnum):
    """The outcome of checking a tool call."""

    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


@dataclass(frozen=True, slots=True)
class ToolCall:
    """A tool invocation the agent is about to make."""

    name: str
    args: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Decision:
    """The verdict on a tool call, with the reason and the rule that produced it."""

    verdict: Verdict
    reason: str
    rule: str | None = None

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW


@dataclass(slots=True)
class Session:
    """State for one agent run: who it is for, what it has touched, what it has done."""

    user: str | None = None
    task: str | None = None
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    canary: str = field(default_factory=new_canary)
    taint: set[Label] = field(default_factory=set)
    tool_calls: int = 0
    identical_calls: Counter[str] = field(default_factory=Counter)


_current: ContextVar[Session | None] = ContextVar("agentshield_session", default=None)


def current_session() -> Session | None:
    """Return the session active in the current context, if any."""
    return _current.get()


class SessionScope:
    """Makes a session current for one ``with`` or ``async with`` block.

    Single use: call ``Shield.session()`` again for another block.
    """

    def __init__(self, session: Session) -> None:
        self.session = session
        self._token: Token[Session | None] | None = None
        self._used = False

    def __enter__(self) -> Session:
        if self._used:
            raise AgentShieldError("a session scope can only be entered once")
        self._used = True
        self._token = _current.set(self.session)
        return self.session

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        assert self._token is not None
        _current.reset(self._token)
        self._token = None

    async def __aenter__(self) -> Session:
        return self.__enter__()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.__exit__(exc_type, exc, tb)
