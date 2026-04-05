from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, ClassVar

from loguru import logger

from agentshield.notifications.rate_limiter import _RateLimiter
from agentshield.notifications.webhook_config import WebhookConfig

_httpx_runtime: Any = None
_HTTPX_AVAILABLE: bool = False
try:
    import httpx as _httpx_runtime

    _HTTPX_AVAILABLE = True
except ImportError:
    _httpx_runtime = None

if TYPE_CHECKING:
    from httpx import AsyncClient

_PAGERDUTY_ENDPOINT: str = "https://events.pagerduty.com/v2/enqueue"


class PagerDutyNotifier:
    """Internal PagerDuty Events API notifier.

    This helper builds trigger/resolve payloads and sends them with retries,
    enforcing cooldown limits only for trigger events.
    """

    _SEVERITY_ORDER: ClassVar[dict[str, int]] = {
        "INFO": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }
    _PAGERDUTY_SEVERITY_MAP: ClassVar[dict[str, str]] = {
        "CRITICAL": "critical",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "info",
        "INFO": "info",
    }

    _config: WebhookConfig
    _rate_limiter: _RateLimiter
    _missing_httpx_warned: bool

    def __init__(self, config: WebhookConfig) -> None:
        """Initialize PagerDuty notifier dependencies.

        Args:
            config: Validated webhook configuration.
        """
        self._config = config
        self._rate_limiter = _RateLimiter(config.pagerduty_cooldown_seconds)
        self._missing_httpx_warned = False

    def should_notify(self, severity: str, canary_triggered: bool) -> bool:
        """Determine whether this threat should trigger PagerDuty.

        Args:
            severity: Threat severity string.
            canary_triggered: Whether canary detection fired.

        Returns:
            True when PagerDuty trigger criteria are met.
        """
        normalized_severity = severity.upper()
        min_severity = self._config.pagerduty_min_severity.upper()

        if canary_triggered:
            return True

        severity_rank = self._SEVERITY_ORDER.get(normalized_severity, 0)
        min_rank = self._SEVERITY_ORDER.get(min_severity, 0)
        return severity_rank >= min_rank

    def build_trigger_payload(
        self,
        agent_id: str,
        session_id: str,
        threat_type: str,
        severity: str,
        recommended_action: str,
        threat_score: float,
        canary_triggered: bool,
        timestamp: str,
    ) -> dict[str, Any]:
        """Build PagerDuty Events API v2 trigger payload.

        Args:
            agent_id: Agent identifier.
            session_id: Session identifier.
            threat_type: Threat type string.
            severity: Threat severity level.
            recommended_action: Recommended policy action.
            threat_score: Threat confidence score.
            canary_triggered: Canary trigger status.
            timestamp: Event timestamp as ISO-8601 string.

        Returns:
            PagerDuty trigger payload dictionary.
        """
        normalized_severity = severity.upper()
        pd_severity = self._PAGERDUTY_SEVERITY_MAP.get(normalized_severity, "info")
        dedup_key = self._dedup_key(agent_id, session_id)

        return {
            "routing_key": self._config.pagerduty_routing_key,
            "event_action": "trigger",
            "dedup_key": dedup_key,
            "payload": {
                "summary": f"[AgentShield] {threat_type} detected — Agent {agent_id}",
                "source": f"agentshield/{agent_id}",
                "severity": pd_severity,
                "timestamp": timestamp,
                "custom_details": {
                    "session_id": session_id,
                    "threat_type": threat_type,
                    "recommended_action": recommended_action.upper(),
                    "threat_score": f"{threat_score:.4f}",
                    "canary_triggered": canary_triggered,
                },
            },
        }

    def build_resolve_payload(self, agent_id: str, session_id: str) -> dict[str, Any]:
        """Build PagerDuty resolve payload.

        Args:
            agent_id: Agent identifier.
            session_id: Session identifier.

        Returns:
            PagerDuty resolve payload dictionary.
        """
        dedup_key = self._dedup_key(agent_id, session_id)
        return {
            "routing_key": self._config.pagerduty_routing_key,
            "event_action": "resolve",
            "dedup_key": dedup_key,
        }

    async def send_trigger(
        self,
        payload: dict[str, Any],
        agent_id: str,
        threat_type: str,
    ) -> None:
        """Send PagerDuty trigger payload with rate limiting and retries.

        Args:
            payload: Trigger payload body.
            agent_id: Agent identifier.
            threat_type: Threat type used for rate-limit keying.
        """
        if not _HTTPX_AVAILABLE or _httpx_runtime is None:
            if not self._missing_httpx_warned:
                logger.warning("httpx not installed. Install agentshield-sdk[notifications].")
                self._missing_httpx_warned = True
            return

        if not self._rate_limiter.is_allowed(agent_id, threat_type):
            return

        httpx_runtime: Any = _httpx_runtime
        max_attempts = self._config.max_retries
        timeout_seconds = float(self._config.http_timeout_seconds)
        dedup_key = str(payload.get("dedup_key", ""))

        for attempt in range(1, max_attempts + 1):
            try:
                client: AsyncClient
                async with httpx_runtime.AsyncClient(timeout=timeout_seconds) as client:
                    response = await client.post(_PAGERDUTY_ENDPOINT, json=payload)

                if 200 <= int(response.status_code) < 300:
                    logger.info("PagerDuty incident triggered: {}", dedup_key)
                    return

                logger.warning(
                    "PagerDuty HTTP {} on attempt {}/{}",
                    response.status_code,
                    attempt,
                    max_attempts,
                )
            except Exception as exc:
                logger.warning(
                    "PagerDuty trigger error on attempt {}/{} | error={}",
                    attempt,
                    max_attempts,
                    exc,
                )

            if attempt < max_attempts:
                await asyncio.sleep(float(2 ** (attempt - 1)))

        logger.warning("PagerDuty trigger failed after {} retries", max_attempts)

    async def send_resolve(self, payload: dict[str, Any], session_id: str) -> None:
        """Send PagerDuty resolve payload with retries and no rate limit.

        Args:
            payload: Resolve payload body.
            session_id: Session identifier for logging context.
        """
        if not _HTTPX_AVAILABLE or _httpx_runtime is None:
            if not self._missing_httpx_warned:
                logger.warning("httpx not installed. Install agentshield-sdk[notifications].")
                self._missing_httpx_warned = True
            return

        httpx_runtime: Any = _httpx_runtime
        max_attempts = self._config.max_retries
        timeout_seconds = float(self._config.http_timeout_seconds)
        dedup_key = str(payload.get("dedup_key", ""))

        for attempt in range(1, max_attempts + 1):
            try:
                client: AsyncClient
                async with httpx_runtime.AsyncClient(timeout=timeout_seconds) as client:
                    response = await client.post(_PAGERDUTY_ENDPOINT, json=payload)

                if 200 <= int(response.status_code) < 300:
                    logger.info("PagerDuty incident resolved: {}", dedup_key)
                    return

                logger.warning(
                    "PagerDuty resolve HTTP {} on attempt {}/{} | session={}",
                    response.status_code,
                    attempt,
                    max_attempts,
                    session_id,
                )
            except Exception as exc:
                logger.warning(
                    "PagerDuty resolve error on attempt {}/{} | session={} error={}",
                    attempt,
                    max_attempts,
                    session_id,
                    exc,
                )

            if attempt < max_attempts:
                await asyncio.sleep(float(2 ** (attempt - 1)))

        logger.warning("PagerDuty resolve failed after {} retries", max_attempts)

    def reset(self) -> None:
        """Reset trigger rate-limiter state for lifecycle cleanup and tests."""
        self._rate_limiter.reset()

    @classmethod
    def map_pagerduty_severity(cls, severity: str) -> str:
        """Map AgentShield severity to PagerDuty severity value.

        Args:
            severity: AgentShield severity string.

        Returns:
            PagerDuty-compatible severity value.
        """
        return cls._PAGERDUTY_SEVERITY_MAP.get(severity.upper(), "info")

    @staticmethod
    def _dedup_key(agent_id: str, session_id: str) -> str:
        """Build stable PagerDuty deduplication key.

        Args:
            agent_id: Agent identifier.
            session_id: Session identifier.

        Returns:
            PagerDuty deduplication key.
        """
        return f"agentshield:{agent_id}:{session_id}"
