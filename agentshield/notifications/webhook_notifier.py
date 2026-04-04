from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import TYPE_CHECKING, Any

import redis.asyncio as aioredis
from loguru import logger

from agentshield.notifications.pagerduty_notifier import PagerDutyNotifier
from agentshield.notifications.slack_notifier import SlackNotifier
from agentshield.notifications.webhook_config import WebhookConfig

_httpx_runtime: Any = None
_HTTPX_AVAILABLE: bool = False
try:
    import httpx as _httpx_runtime

    _HTTPX_AVAILABLE = True
except ImportError:
    _httpx_runtime = None

if TYPE_CHECKING:
    from redis.asyncio.client import PubSub


class WebhookNotifier:
    """Redis-subscriber webhook notification exporter.

    The notifier is decoupled from the hot path and consumes events from Redis
    in a background asyncio task, forwarding eligible threats to Slack and
    PagerDuty based on validated notification configuration.
    """

    _webhook_config: WebhookConfig
    _redis_url: str
    _redis: aioredis.Redis[Any] | None
    _task: asyncio.Task[None] | None
    _slack: SlackNotifier | None
    _pagerduty: PagerDutyNotifier | None
    _open_incidents: set[str]
    _active: bool

    def __init__(self, webhook_config: WebhookConfig, redis_url: str) -> None:
        """Initialize webhook notifier dependencies.

        Args:
            webhook_config: Validated webhook config snapshot.
            redis_url: Redis URL used for event pub/sub subscription.
        """
        self._webhook_config = webhook_config
        self._redis_url = redis_url
        self._redis = None
        self._task = None
        self._slack = None
        self._pagerduty = None
        self._open_incidents = set()
        self._active = False

        if not _HTTPX_AVAILABLE:
            logger.warning(
                "httpx not installed. Install agentshield-sdk[notifications]."
            )
            return

        if not (
            self._webhook_config.slack_enabled or self._webhook_config.pagerduty_enabled
        ):
            logger.warning("WebhookNotifier: neither Slack nor PagerDuty enabled.")
            return

        if self._webhook_config.slack_enabled:
            self._slack = SlackNotifier(self._webhook_config)

        if self._webhook_config.pagerduty_enabled:
            self._pagerduty = PagerDutyNotifier(self._webhook_config)

        self._active = True

    async def start(self) -> None:
        """Start Redis subscription and background notification loop."""
        if not self._active:
            return

        try:
            self._redis = aioredis.from_url(self._redis_url, decode_responses=False)
            await self._redis.ping()
            self._task = asyncio.create_task(self._listen_loop())
            logger.info("WebhookNotifier started.")
        except Exception as exc:
            logger.warning("WebhookNotifier failed to start | error={}", exc)

    async def stop(self) -> None:
        """Stop background task and close notifier resources."""
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                logger.debug("WebhookNotifier listener task cancelled")
            except Exception as exc:
                logger.warning("WebhookNotifier task stop warning | error={}", exc)
            self._task = None

        if self._redis is not None:
            try:
                close_method = getattr(self._redis, "aclose", None)
                if callable(close_method):
                    close_result = close_method()
                    if asyncio.iscoroutine(close_result):
                        await close_result
                else:
                    legacy_close = getattr(self._redis, "close", None)
                    if callable(legacy_close):
                        legacy_close()
            except Exception as exc:
                logger.warning("WebhookNotifier Redis close warning | error={}", exc)
            self._redis = None

        if self._slack is not None:
            self._slack.reset()
        if self._pagerduty is not None:
            self._pagerduty.reset()

        self._open_incidents.clear()
        logger.info("WebhookNotifier stopped.")

    async def _listen_loop(self) -> None:
        """Subscribe to Redis and process event messages continuously."""
        if self._redis is None:
            return

        pubsub: PubSub = self._redis.pubsub()
        try:
            await pubsub.subscribe(self._webhook_config.redis_channel)
            while True:
                try:
                    message = await pubsub.get_message(
                        ignore_subscribe_messages=True,
                        timeout=1.0,
                    )
                    if message is None:
                        continue

                    payload = message.get("data")
                    if isinstance(payload, bytes):
                        payload_text = payload.decode("utf-8")
                    elif isinstance(payload, str):
                        payload_text = payload
                    else:
                        continue

                    raw = json.loads(payload_text)
                    if isinstance(raw, dict):
                        await self._process_message(raw)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.warning(
                        "WebhookNotifier listen loop warning | error={}", exc
                    )
        except asyncio.CancelledError:
            logger.debug("WebhookNotifier listen loop cancelled")
        except Exception as exc:
            logger.warning("WebhookNotifier listener setup warning | error={}", exc)
        finally:
            try:
                unsubscribe_method = getattr(pubsub, "unsubscribe", None)
                if callable(unsubscribe_method):
                    unsubscribe_result = unsubscribe_method(
                        self._webhook_config.redis_channel
                    )
                    if asyncio.iscoroutine(unsubscribe_result):
                        await unsubscribe_result
            except Exception as exc:
                logger.warning("WebhookNotifier unsubscribe warning | error={}", exc)

            try:
                close_method = getattr(pubsub, "aclose", None)
                if callable(close_method):
                    close_result = close_method()
                    if asyncio.iscoroutine(close_result):
                        await close_result
                else:
                    legacy_close = getattr(pubsub, "close", None)
                    if callable(legacy_close):
                        legacy_result = legacy_close()
                        if asyncio.iscoroutine(legacy_result):
                            await legacy_result
            except Exception as exc:
                logger.warning("WebhookNotifier pubsub close warning | error={}", exc)

    async def _process_message(self, raw: dict[str, Any]) -> None:
        """Route one raw message to threat or session-end handlers.

        Args:
            raw: Raw Redis event payload.
        """
        try:
            event_type_raw = str(raw.get("event_type", "")).lower()
            if event_type_raw == "threat_detected":
                await self._handle_threat(raw)
                return
            if event_type_raw == "session_end":
                await self._handle_session_end(raw)
        except Exception as exc:
            logger.warning("WebhookNotifier message processing warning | error={}", exc)

    async def _handle_threat(self, raw: dict[str, Any]) -> None:
        """Handle threat events for Slack/PagerDuty forwarding.

        Args:
            raw: Raw threat event payload.
        """
        try:
            agent_id = self._as_text(raw.get("agent_id"), default="unknown")
            session_id = self._as_text(raw.get("session_id"), default="unknown")
            threat_type = self._as_text(raw.get("threat_type"), default="UNKNOWN")
            severity = self._as_text(raw.get("severity"), default="INFO").upper()
            recommended_action = self._as_text(
                raw.get("recommended_action"),
                default="ALERT",
            ).upper()
            threat_score = round(
                self._as_float(raw.get("threat_score", raw.get("confidence", 0.0))),
                4,
            )
            canary_triggered = bool(raw.get("canary_triggered", False))
            timestamp_value = raw.get("timestamp")
            timestamp = (
                self._as_text(timestamp_value)
                if timestamp_value is not None
                else datetime.utcnow().isoformat()
            )
            if not timestamp:
                timestamp = datetime.utcnow().isoformat()

            if (
                self._slack is not None
                and self._webhook_config.slack_enabled
                and self._slack.should_notify(
                    threat_type,
                    severity,
                    recommended_action,
                    canary_triggered,
                )
            ):
                slack_payload = self._slack.build_payload(
                    agent_id=agent_id,
                    session_id=session_id,
                    threat_type=threat_type,
                    severity=severity,
                    recommended_action=recommended_action,
                    threat_score=threat_score,
                    canary_triggered=canary_triggered,
                    timestamp=timestamp,
                )
                await self._slack.send(slack_payload, agent_id, threat_type)

            if (
                self._pagerduty is not None
                and self._webhook_config.pagerduty_enabled
                and self._pagerduty.should_notify(severity, canary_triggered)
            ):
                dedup_key = f"agentshield:{agent_id}:{session_id}"
                self._open_incidents.add(dedup_key)
                pd_payload = self._pagerduty.build_trigger_payload(
                    agent_id=agent_id,
                    session_id=session_id,
                    threat_type=threat_type,
                    severity=severity,
                    recommended_action=recommended_action,
                    threat_score=threat_score,
                    canary_triggered=canary_triggered,
                    timestamp=timestamp,
                )
                await self._pagerduty.send_trigger(pd_payload, agent_id, threat_type)
        except Exception as exc:
            logger.warning("WebhookNotifier threat handling warning | error={}", exc)

    async def _handle_session_end(self, raw: dict[str, Any]) -> None:
        """Resolve open PagerDuty incidents when sessions end.

        Args:
            raw: Raw session-end event payload.
        """
        try:
            if self._pagerduty is None or not self._webhook_config.pagerduty_enabled:
                return

            agent_id = self._as_text(raw.get("agent_id"), default="unknown")
            session_id = self._as_text(raw.get("session_id"), default="unknown")
            dedup_key = f"agentshield:{agent_id}:{session_id}"

            if dedup_key in self._open_incidents:
                payload = self._pagerduty.build_resolve_payload(agent_id, session_id)
                await self._pagerduty.send_resolve(payload, session_id)
                self._open_incidents.discard(dedup_key)
        except Exception as exc:
            logger.warning("WebhookNotifier session_end warning | error={}", exc)

    @staticmethod
    def _as_text(value: Any, default: str = "") -> str:
        """Normalize a raw field to a string.

        Args:
            value: Raw field value.
            default: Fallback string for missing values.

        Returns:
            Normalized string value.
        """
        if value is None:
            return default
        return str(value)

    @staticmethod
    def _as_float(value: Any, default: float = 0.0) -> float:
        """Normalize a raw field to a float.

        Args:
            value: Raw field value.
            default: Fallback float for parse failures.

        Returns:
            Parsed float value.
        """
        try:
            return float(value)
        except (TypeError, ValueError):
            return default
