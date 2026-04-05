from __future__ import annotations

import asyncio
import json
import socket
import time
from datetime import datetime
from typing import TYPE_CHECKING, Any, ClassVar

import redis.asyncio as aioredis
from loguru import logger

from agentshield.siem.cef_formatter import (
    _SEVERITY_MAP,
    _SYSLOG_SEVERITY_MAP,
    CEFFormatter,
)
from agentshield.siem.siem_config import SIEMConfig

if TYPE_CHECKING:
    from redis.asyncio.client import PubSub


class SyslogSIEMExporter:
    """CEF over syslog exporter backed by Redis pub/sub subscription."""

    _SEVERITY_ORDER: ClassVar[dict[str, int]] = {
        "INFO": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }
    _SYSLOG_FROM_CEF: ClassVar[dict[int, int]] = dict(_SYSLOG_SEVERITY_MAP)

    _config: SIEMConfig
    _version: str
    _redis_url: str
    _hostname: str
    _formatter: CEFFormatter
    _redis: aioredis.Redis[Any] | None
    _task: asyncio.Task[None] | None
    _active: bool

    def __init__(self, config: SIEMConfig, version: str, redis_url: str) -> None:
        """Initialize Syslog SIEM exporter.

        Args:
            config: Validated SIEM configuration.
            version: AgentShield version string.
            redis_url: Redis URL for pub/sub subscription.
        """
        self._config = config
        self._version = version
        self._redis_url = redis_url
        self._hostname = socket.gethostname()
        self._formatter = CEFFormatter()
        self._redis = None
        self._task = None
        self._active = True

    async def start(self) -> None:
        """Start Redis listener for syslog SIEM export."""
        if not self._active:
            return

        try:
            self._redis = aioredis.from_url(self._redis_url, decode_responses=False)
            await self._redis.ping()
            self._task = asyncio.create_task(self._listen_loop())
            logger.info(
                "SyslogSIEMExporter started -> {}:{}/{}",
                self._config.syslog_host,
                self._config.syslog_port,
                self._config.syslog_protocol,
            )
        except Exception as exc:
            logger.warning("SyslogSIEMExporter failed to start | error={}", exc)

    async def stop(self) -> None:
        """Stop Redis listener and release exporter resources."""
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                logger.debug("SyslogSIEMExporter listener task cancelled")
            except Exception as exc:
                logger.warning("SyslogSIEMExporter task stop warning | error={}", exc)
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
                logger.warning("SyslogSIEMExporter Redis close warning | error={}", exc)
            self._redis = None

        logger.info("SyslogSIEMExporter stopped.")

    async def _listen_loop(self) -> None:
        """Subscribe to Redis and process threat events."""
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
                        self._process_message(raw)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.warning("SyslogSIEMExporter listen warning | error={}", exc)
        except asyncio.CancelledError:
            logger.debug("SyslogSIEMExporter listen loop cancelled")
        except Exception as exc:
            logger.warning("SyslogSIEMExporter listener setup warning | error={}", exc)
        finally:
            try:
                unsubscribe_method = getattr(pubsub, "unsubscribe", None)
                if callable(unsubscribe_method):
                    unsubscribe_result = unsubscribe_method(self._config.redis_channel)
                    if asyncio.iscoroutine(unsubscribe_result):
                        await unsubscribe_result
            except Exception as exc:
                logger.warning("SyslogSIEMExporter unsubscribe warning | error={}", exc)

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
                logger.warning("SyslogSIEMExporter pubsub close warning | error={}", exc)

    def _process_message(self, raw: dict[str, Any]) -> None:
        """Process one raw threat event payload.

        Args:
            raw: Raw event payload.
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
            timestamp_ms = self._to_epoch_ms(raw.get("timestamp"))

            if not self._meets_min_severity(severity):
                return

            cef_line = self._formatter.format(
                agent_id=agent_id,
                session_id=session_id,
                threat_type=threat_type,
                severity=severity,
                recommended_action=recommended_action,
                threat_score=threat_score,
                canary_triggered=canary_triggered,
                timestamp_ms=timestamp_ms,
                version=self._version,
            )

            cef_severity = 10 if canary_triggered else _SEVERITY_MAP.get(severity, 5)
            syslog_severity = self._SYSLOG_FROM_CEF.get(cef_severity, 4)
            data = self._formatter.to_syslog_bytes(
                cef_line=cef_line,
                syslog_severity=syslog_severity,
                hostname=self._hostname,
            )
            self._send_bytes(data)
        except Exception as exc:
            logger.warning("SyslogSIEMExporter process warning | error={}", exc)

    def _send_bytes(self, data: bytes) -> None:
        """Send syslog payload bytes over configured transport.

        Args:
            data: Encoded syslog payload bytes.
        """
        try:
            if self._config.syslog_protocol == "udp":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.sendto(data, (self._config.syslog_host, self._config.syslog_port))
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(5.0)
                    sock.connect((self._config.syslog_host, self._config.syslog_port))
                    sock.sendall(data)
        except Exception as exc:
            logger.warning("SyslogSIEMExporter send failed: {}", exc)

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
        """Normalize a raw value to a string.

        Args:
            value: Raw value to normalize.
            default: Default string when value is missing.

        Returns:
            Normalized string.
        """
        if value is None:
            return default
        return str(value)

    @staticmethod
    def _as_float(value: Any, default: float = 0.0) -> float:
        """Normalize a raw value to a float.

        Args:
            value: Raw value to normalize.
            default: Default float when parse fails.

        Returns:
            Parsed float.
        """
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _to_epoch_ms(value: Any) -> int:
        """Convert timestamps into epoch milliseconds.

        Args:
            value: Timestamp value as float, int, or ISO-8601 string.

        Returns:
            Epoch timestamp in milliseconds.
        """
        if isinstance(value, (int, float)):
            return int(float(value) * 1000)

        if isinstance(value, str) and value:
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                return int(parsed.timestamp() * 1000)
            except ValueError:
                return int(time.time() * 1000)

        return int(time.time() * 1000)
