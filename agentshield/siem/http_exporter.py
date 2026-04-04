from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime
from typing import TYPE_CHECKING, Any, ClassVar

import redis.asyncio as aioredis
from loguru import logger

from agentshield.siem.siem_config import SIEMConfig

_httpx_runtime: Any = None
_HTTPX_AVAILABLE: bool = False
try:
    import httpx as _httpx_runtime

    _HTTPX_AVAILABLE = True
except ImportError:
    _httpx_runtime = None

if TYPE_CHECKING:
    from httpx import AsyncClient
    from redis.asyncio.client import PubSub


class HttpSIEMExporter:
    """HTTP-based SIEM exporter for generic and Splunk HEC endpoints."""

    _SEVERITY_ORDER: ClassVar[dict[str, int]] = {
        "INFO": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    _config: SIEMConfig
    _version: str
    _redis_url: str
    _redis: aioredis.Redis[Any] | None
    _task: asyncio.Task[None] | None
    _active: bool

    def __init__(self, config: SIEMConfig, version: str, redis_url: str) -> None:
        """Initialize HTTP SIEM exporter.

        Args:
            config: Validated SIEM configuration.
            version: AgentShield version string.
            redis_url: Redis URL for pub/sub subscription.
        """
        self._config = config
        self._version = version
        self._redis_url = redis_url
        self._redis = None
        self._task = None
        self._active = False

        if not _HTTPX_AVAILABLE:
            logger.warning("httpx not installed. Install agentshield-sdk[siem].")
            return

        self._active = True

    async def start(self) -> None:
        """Start Redis listener for HTTP SIEM export."""
        if not self._active:
            return

        try:
            self._redis = aioredis.from_url(self._redis_url, decode_responses=False)
            await self._redis.ping()
            self._task = asyncio.create_task(self._listen_loop())
            logger.info("HttpSIEMExporter started ({})", self._config.http_mode)
        except Exception as exc:
            logger.warning("HttpSIEMExporter failed to start | error={}", exc)

    async def stop(self) -> None:
        """Stop Redis listener and release HTTP SIEM resources."""
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                logger.debug("HttpSIEMExporter listener task cancelled")
            except Exception as exc:
                logger.warning("HttpSIEMExporter task stop warning | error={}", exc)
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
                logger.warning("HttpSIEMExporter Redis close warning | error={}", exc)
            self._redis = None

        logger.info("HttpSIEMExporter stopped.")

    async def _listen_loop(self) -> None:
        """Subscribe to Redis and process threat events for HTTP export."""
        if self._redis is None:
            return

        pubsub: PubSub = self._redis.pubsub()
        try:
            await pubsub.subscribe(self._config.redis_channel)
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
                    logger.warning("HttpSIEMExporter listen warning | error={}", exc)
        except asyncio.CancelledError:
            logger.debug("HttpSIEMExporter listen loop cancelled")
        except Exception as exc:
            logger.warning("HttpSIEMExporter listener setup warning | error={}", exc)
        finally:
            try:
                unsubscribe_method = getattr(pubsub, "unsubscribe", None)
                if callable(unsubscribe_method):
                    unsubscribe_result = unsubscribe_method(self._config.redis_channel)
                    if asyncio.iscoroutine(unsubscribe_result):
                        await unsubscribe_result
            except Exception as exc:
                logger.warning("HttpSIEMExporter unsubscribe warning | error={}", exc)

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
                logger.warning("HttpSIEMExporter pubsub close warning | error={}", exc)

    async def _process_message(self, raw: dict[str, Any]) -> None:
        """Process one threat event and forward it to HTTP SIEM.

        Args:
            raw: Raw Redis event payload.
        """
        try:
            event_type_raw = str(raw.get("event_type", "")).lower()
            if event_type_raw != "threat_detected":
                return

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
            epoch_seconds = self._to_epoch_seconds(raw.get("timestamp"))
            iso_timestamp = self._to_iso_timestamp(raw.get("timestamp"), epoch_seconds)

            if not self._meets_min_severity(severity):
                return

            if self._config.http_mode == "splunk_hec":
                url = self._splunk_hec_url(self._config.http_endpoint)
                headers = {
                    "Authorization": f"Splunk {self._config.http_token}",
                    "Content-Type": "application/json",
                }
                payload = {
                    "time": epoch_seconds,
                    "event": {
                        "threat_type": threat_type,
                        "severity": severity,
                        "agent_id": agent_id,
                        "session_id": session_id,
                        "recommended_action": recommended_action,
                        "threat_score": threat_score,
                        "canary_triggered": canary_triggered,
                        "timestamp": iso_timestamp,
                        "source": "agentshield",
                    },
                    "sourcetype": "agentshield",
                    "source": f"agentshield/{agent_id}",
                }
            else:
                url = self._config.http_endpoint
                headers = {"Content-Type": "application/json"}
                if self._config.http_token:
                    headers["Authorization"] = f"Bearer {self._config.http_token}"
                payload = {
                    "threat_type": threat_type,
                    "severity": severity,
                    "agent_id": agent_id,
                    "session_id": session_id,
                    "recommended_action": recommended_action,
                    "threat_score": threat_score,
                    "canary_triggered": canary_triggered,
                    "timestamp": iso_timestamp,
                    "source": "agentshield",
                    "version": self._version,
                }

            await self._send_with_retry(url, headers, payload, self._config.http_mode)
        except Exception as exc:
            logger.warning("HttpSIEMExporter process warning | error={}", exc)

    async def _send_with_retry(
        self,
        url: str,
        headers: dict[str, str],
        payload: dict[str, Any],
        mode: str,
    ) -> None:
        """Send one HTTP payload with retries and backoff.

        Args:
            url: Destination URL.
            headers: HTTP headers.
            payload: JSON payload body.
            mode: Export mode name used for logging.
        """
        httpx_runtime: Any = _httpx_runtime
        max_attempts = self._config.http_max_retries
        timeout_seconds = float(self._config.http_timeout_seconds)

        for attempt in range(1, max_attempts + 1):
            try:
                client: AsyncClient
                async with httpx_runtime.AsyncClient(timeout=timeout_seconds) as client:
                    response = await client.post(url, headers=headers, json=payload)

                if 200 <= int(response.status_code) < 300:
                    logger.debug("HttpSIEMExporter: event sent ({})", mode)
                    return

                logger.warning(
                    "HttpSIEMExporter HTTP {} on attempt {}/{}",
                    response.status_code,
                    attempt,
                    max_attempts,
                )
            except Exception as exc:
                logger.warning(
                    "HttpSIEMExporter send error on attempt {}/{} | error={}",
                    attempt,
                    max_attempts,
                    exc,
                )

            if attempt < max_attempts:
                await asyncio.sleep(float(2 ** (attempt - 1)))

        logger.warning("HttpSIEMExporter: failed after {} retries", max_attempts)

    def _meets_min_severity(self, severity: str) -> bool:
        """Evaluate severity against configured export threshold.

        Args:
            severity: Threat severity value.

        Returns:
            True when severity is at or above configured threshold.
        """
        severity_rank = self._SEVERITY_ORDER.get(severity.upper(), 0)
        min_rank = self._SEVERITY_ORDER.get(self._config.min_severity.upper(), 0)
        return severity_rank >= min_rank

    @staticmethod
    def _as_text(value: Any, default: str = "") -> str:
        """Normalize raw values to strings.

        Args:
            value: Raw value.
            default: Fallback string for missing values.

        Returns:
            Normalized string value.
        """
        if value is None:
            return default
        return str(value)

    @staticmethod
    def _as_float(value: Any, default: float = 0.0) -> float:
        """Normalize raw values to floats.

        Args:
            value: Raw value.
            default: Fallback float on parse failure.

        Returns:
            Parsed float value.
        """
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _to_epoch_seconds(value: Any) -> float:
        """Convert timestamp values into epoch seconds.

        Args:
            value: Timestamp as float/int/ISO string.

        Returns:
            Epoch seconds.
        """
        if isinstance(value, (int, float)):
            return float(value)

        if isinstance(value, str) and value:
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                return float(parsed.timestamp())
            except ValueError:
                return float(time.time())

        return float(time.time())

    @staticmethod
    def _to_iso_timestamp(value: Any, epoch_seconds: float) -> str:
        """Normalize incoming timestamps into ISO-8601 strings.

        Args:
            value: Original raw timestamp value.
            epoch_seconds: Parsed epoch seconds fallback.

        Returns:
            ISO-8601 timestamp string.
        """
        if isinstance(value, str) and value:
            return value

        return datetime.utcfromtimestamp(epoch_seconds).isoformat()

    @staticmethod
    def _splunk_hec_url(endpoint: str) -> str:
        """Build Splunk HEC event ingest URL from base endpoint.

        Args:
            endpoint: Base endpoint configured by user.

        Returns:
            Full Splunk HEC event URL.
        """
        return endpoint.rstrip("/") + "/services/collector/event"
