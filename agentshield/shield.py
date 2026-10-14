"""The public entry point."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from agentshield.policy import Policy, load_policy
from agentshield.session import Session, SessionScope


class Shield:
    """Holds one immutable policy and opens sessions; stage 4 adds enforcement."""

    def __init__(self, policy: Policy | None = None) -> None:
        self.policy = policy if policy is not None else load_policy("strict")

    @classmethod
    def from_policy(cls, source: str | Path | Mapping[str, Any]) -> Shield:
        """Build a shield from a built-in policy name, a YAML file, or a mapping."""
        return cls(load_policy(source))

    def session(self, *, user: str | None = None, task: str | None = None) -> SessionScope:
        """Start a session for one agent run.

        Use as ``with shield.session(user=...) as s:`` or ``async with``.
        """
        return SessionScope(Session(user=user, task=task))
