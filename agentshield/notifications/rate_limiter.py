from __future__ import annotations

import time


class _RateLimiter:
    """Simple cooldown-based notification rate limiter.

    The limiter enforces one notification per `(agent_id, threat_type)` key
    within the configured cooldown window.
    """

    _cooldown_seconds: int
    _last_sent: dict[str, float]

    def __init__(self, cooldown_seconds: int) -> None:
        """Initialize rate limiter state.

        Args:
            cooldown_seconds: Cooldown period for each key.
        """
        self._cooldown_seconds = cooldown_seconds
        self._last_sent = {}

    def is_allowed(self, agent_id: str, threat_type: str) -> bool:
        """Check if a notification is allowed under the rate limit.

        Returns True and records the current timestamp if the cooldown period
        has elapsed since the last notification for this `(agent_id, threat_type)`
        pair. Returns False otherwise.

        Args:
            agent_id: Agent identifier.
            threat_type: Threat type string.

        Returns:
            Whether a notification should be sent.
        """
        key = f"{agent_id}:{threat_type}"
        now = time.monotonic()
        last_sent = self._last_sent.get(key)

        if last_sent is None or now - last_sent >= float(self._cooldown_seconds):
            self._last_sent[key] = now
            return True
        return False

    def reset(self) -> None:
        """Clear all rate limiter state."""
        self._last_sent.clear()
