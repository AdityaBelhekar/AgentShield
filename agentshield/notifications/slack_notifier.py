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


class SlackNotifier:
    """Internal Slack webhook sender with threshold and retry logic.

    This helper encapsulates Slack-specific payload construction and delivery
    while enforcing severity thresholds and per-threat cooldown limits.
    """

    _SEVERITY_COLORS: ClassVar[dict[str, str]] = {
        "CRITICAL": "#FF0000",
        "HIGH": "#FF6600",
        "MEDIUM": "#FFAA00",
        "LOW": "#FFFF00",
        "INFO": "#AAAAAA",
    }
    _SEVERITY_EMOJI: ClassVar[dict[str, str]] = {
        "CRITICAL": "🚨",
        "HIGH": "🔴",
        "MEDIUM": "🟡",
        "LOW": "🟢",
        "INFO": "⚪",
    }
    _SEVERITY_ORDER: ClassVar[dict[str, int]] = {
        "INFO": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    _config: WebhookConfig
    _rate_limiter: _RateLimiter
    _missing_httpx_warned: bool

    def __init__(self, config: WebhookConfig) -> None:
        """Initialize Slack notifier dependencies.

        Args:
            config: Validated webhook configuration.
        """
        self._config = config
        self._rate_limiter = _RateLimiter(config.slack_cooldown_seconds)
        self._missing_httpx_warned = False

    def should_notify(
        self,
        threat_type: str,
        severity: str,
        recommended_action: str,
        canary_triggered: bool,
    ) -> bool:
        """Determine whether this threat should notify Slack.

        Args:
            threat_type: Threat type string.
            severity: Threat severity level.
            recommended_action: Recommended policy action.
            canary_triggered: Whether canary detection fired.

        Returns:
            True when the event meets Slack alerting criteria.
        """
        del threat_type

        normalized_severity = severity.upper()
        normalized_action = recommended_action.upper()
        min_severity = self._config.slack_min_severity.upper()

        if canary_triggered:
            return True
        if normalized_action == "BLOCK":
            return True

        severity_rank = self._SEVERITY_ORDER.get(normalized_severity, 0)
        min_rank = self._SEVERITY_ORDER.get(min_severity, 0)
        return severity_rank >= min_rank

    def build_payload(
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
        """Build Slack Block Kit payload without sensitive content.

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
            Slack Incoming Webhook payload dictionary.
        """
        normalized_severity = severity.upper()
        color = self._SEVERITY_COLORS.get(normalized_severity, "#AAAAAA")
        emoji = self._SEVERITY_EMOJI.get(normalized_severity, "⚪")
        canary_text = "Yes ⚠️" if canary_triggered else "No"

        return {
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"{emoji} AgentShield Alert — {threat_type}",
                            },
                        },
                        {
                            "type": "section",
                            "fields": [
                                {"type": "mrkdwn", "text": f"*Agent:*\n{agent_id}"},
                                {"type": "mrkdwn", "text": f"*Session:*\n{session_id}"},
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Severity:*\n{normalized_severity}",
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Action:*\n{recommended_action.upper()}",
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Score:*\n{threat_score:.4f}",
                                },
                                {"type": "mrkdwn", "text": f"*Canary:*\n{canary_text}"},
                                {"type": "mrkdwn", "text": f"*Time:*\n{timestamp}"},
                            ],
                        },
                    ],
                }
            ]
        }

    async def send(
        self,
        payload: dict[str, Any],
        agent_id: str,
        threat_type: str,
    ) -> None:
        """Send Slack webhook payload with rate limiting and retries.

        Args:
            payload: Slack webhook payload.
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

        for attempt in range(1, max_attempts + 1):
            try:
                client: AsyncClient
                async with httpx_runtime.AsyncClient(timeout=timeout_seconds) as client:
                    response = await client.post(
                        self._config.slack_webhook_url,
                        json=payload,
                    )

                if response.status_code == 200:
                    logger.debug(
                        "Slack alert sent | agent={} threat_type={} attempt={}",
                        agent_id,
                        threat_type,
                        attempt,
                    )
                    return

                logger.warning(
                    "Slack HTTP {} on attempt {}/{}",
                    response.status_code,
                    attempt,
                    max_attempts,
                )
            except Exception as exc:
                logger.warning(
                    "Slack send error on attempt {}/{} | error={}",
                    attempt,
                    max_attempts,
                    exc,
                )

            if attempt < max_attempts:
                await asyncio.sleep(float(2 ** (attempt - 1)))

        logger.warning("Slack alert failed after {} retries", max_attempts)

    def reset(self) -> None:
        """Reset rate-limiter state for lifecycle cleanup and tests."""
        self._rate_limiter.reset()
