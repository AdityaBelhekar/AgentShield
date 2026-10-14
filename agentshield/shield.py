"""The public entry point."""

from __future__ import annotations

from agentshield.session import Session, SessionScope


class Shield:
    """Opens sessions; later stages add the policy and the engine."""

    def session(self, *, user: str | None = None, task: str | None = None) -> SessionScope:
        """Start a session for one agent run.

        Use as ``with shield.session(user=...) as s:`` or ``async with``.
        """
        return SessionScope(Session(user=user, task=task))
