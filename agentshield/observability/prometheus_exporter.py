from __future__ import annotations

import asyncio
import json
import threading
import time
from datetime import datetime
from typing import TYPE_CHECKING, Any

import redis.asyncio as aioredis
from loguru import logger

_PROMETHEUS_AVAILABLE: bool = False
try:
    import prometheus_client as _prometheus_runtime
    from prometheus_client import Counter, Gauge, Histogram, start_http_server

    _PROMETHEUS_AVAILABLE = True
except ImportError:
    _prometheus_runtime = None
    Counter = None
    Gauge = None
    Histogram = None
    start_http_server = None

if TYPE_CHECKING:
    from redis.asyncio.client import PubSub


class PrometheusExporter:
    """Redis-driven Prometheus metrics exporter for AgentShield events.

    The exporter is fully decoupled from the hot path. It subscribes to Redis
    events in a background task and updates Prometheus instruments that are
    exposed via the built-in `prometheus_client` HTTP server.
    """

    _port: int
    _redis_url: str
    _redis_channel: str
    _redis: aioredis.Redis[Any] | None
    _task: asyncio.Task[None] | None
    _server_thread: threading.Thread | None
    _session_start_times: dict[str, float]
    _registry: Any | None
    _threats_total: Any | None
    _sessions_active: Any | None
    _detection_score_hist: Any | None
    _policy_blocks_total: Any | None
    _canary_triggers_total: Any | None
    _session_duration_seconds: Any | None
    _active: bool

    def __init__(self, port: int, redis_url: str, redis_channel: str) -> None:
        """Initialize the Prometheus exporter.

        Args:
            port: HTTP port used for `/metrics` exposure.
            redis_url: Redis URL for event subscription.
            redis_channel: Redis pub/sub channel to subscribe to.
        """
        self._port = port
        self._redis_url = redis_url
        self._redis_channel = redis_channel
        self._redis = None
        self._task = None
        self._server_thread = None
        self._session_start_times = {}
        self._registry = None
        self._threats_total = None
        self._sessions_active = None
        self._detection_score_hist = None
        self._policy_blocks_total = None
        self._canary_triggers_total = None
        self._session_duration_seconds = None
        self._active = False

        if not _PROMETHEUS_AVAILABLE:
            logger.warning(
                "prometheus-client not installed. Install agentshield-sdk[grafana]."
            )
            return

        if (
            _prometheus_runtime is None
            or Counter is None
            or Gauge is None
            or Histogram is None
            or start_http_server is None
        ):
            logger.warning("Prometheus imports unavailable after initialization guard")
            return

        try:
            prometheus_runtime: Any = _prometheus_runtime
            counter_cls: Any = Counter
            gauge_cls: Any = Gauge
            histogram_cls: Any = Histogram

            self._registry = prometheus_runtime.CollectorRegistry()

            self._threats_total = counter_cls(
                "agentshield_threats_total",
                "Total number of threats detected by AgentShield",
                ["threat_type", "severity", "recommended_action", "agent_id"],
                registry=self._registry,
            )
            self._sessions_active = gauge_cls(
                "agentshield_sessions_active",
                "Currently active AgentShield sessions",
                ["agent_id"],
                registry=self._registry,
            )
            self._detection_score_hist = histogram_cls(
                "agentshield_detection_score",
                "Distribution of threat detection scores",
                ["threat_type", "agent_id"],
                buckets=(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0),
                registry=self._registry,
            )
            self._policy_blocks_total = counter_cls(
                "agentshield_policy_blocks_total",
                "Total number of policy BLOCK actions taken",
                ["threat_type", "agent_id"],
                registry=self._registry,
            )
            self._canary_triggers_total = counter_cls(
                "agentshield_canary_triggers_total",
                "Total number of canary token triggers",
                ["agent_id"],
                registry=self._registry,
            )
            self._session_duration_seconds = histogram_cls(
                "agentshield_session_duration_seconds",
                "Session duration in seconds",
                ["agent_id"],
                buckets=(1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600),
                registry=self._registry,
            )
            self._active = True
        except Exception as exc:
            logger.warning("PrometheusExporter initialization failed | error={}", exc)
            self._active = False

    async def start(self) -> None:
        """Start the metrics HTTP endpoint and Redis listener task."""
        if not self._active:
            return

        try:
            start_server_fn: Any = start_http_server
            self._server_thread = threading.Thread(
                target=start_server_fn,
                args=(self._port,),
                kwargs={"registry": self._registry},
                daemon=True,
            )
            self._server_thread.start()

            self._redis = aioredis.from_url(self._redis_url, decode_responses=False)
            await self._redis.ping()
            self._task = asyncio.create_task(self._listen_loop())
            logger.info("PrometheusExporter started on :{}/metrics", self._port)
        except Exception as exc:
            logger.warning("PrometheusExporter failed to start | error={}", exc)

    async def stop(self) -> None:
        """Stop Redis listener resources for the exporter."""
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                logger.debug("PrometheusExporter listener task cancelled")
            except Exception as exc:
                logger.warning("PrometheusExporter task stop warning | error={}", exc)
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
                logger.warning("PrometheusExporter Redis close warning | error={}", exc)
            self._redis = None

        logger.info("PrometheusExporter stopped.")

    async def _listen_loop(self) -> None:
        """Listen on Redis pub/sub and process supported event messages."""
        if self._redis is None:
            return

        pubsub: PubSub = self._redis.pubsub()
        try:
            await pubsub.subscribe(self._redis_channel)
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
                    logger.warning(
                        "PrometheusExporter listen loop warning | error={}",
                        exc,
                    )
        except asyncio.CancelledError:
            logger.debug("PrometheusExporter listen loop cancelled")
        except Exception as exc:
            logger.warning("PrometheusExporter listener setup warning | error={}", exc)
        finally:
            try:
                unsubscribe_method = getattr(pubsub, "unsubscribe", None)
                if callable(unsubscribe_method):
                    unsubscribe_result = unsubscribe_method(self._redis_channel)
                    if asyncio.iscoroutine(unsubscribe_result):
                        await unsubscribe_result
            except Exception as exc:
                logger.warning("PrometheusExporter unsubscribe warning | error={}", exc)

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
                logger.warning(
                    "PrometheusExporter pubsub close warning | error={}",
                    exc,
                )

    def _process_message(self, raw: dict[str, Any]) -> None:
        """Route raw event payloads to metric update handlers.

        Args:
            raw: Raw Redis event payload.
        """
        try:
            event_type_raw = str(raw.get("event_type", "")).lower()
            if event_type_raw == "session_start":
                self._handle_session_start(raw)
                return
            if event_type_raw == "session_end":
                self._handle_session_end(raw)
                return
            if event_type_raw == "threat_detected":
                self._handle_threat(raw)
        except Exception as exc:
            logger.warning(
                "PrometheusExporter message processing warning | error={}", exc
            )

    def _handle_session_start(self, raw: dict[str, Any]) -> None:
        """Handle session-start events for active session metrics.

        Args:
            raw: Raw session-start payload.
        """
        try:
            agent_id = self._as_text(raw.get("agent_id"), default="unknown")
            session_id = self._as_text(raw.get("session_id"), default="")
            timestamp_seconds = self._extract_timestamp_seconds(raw)

            if self._sessions_active is not None:
                self._sessions_active.labels(agent_id=agent_id).inc()

            if session_id:
                self._session_start_times[session_id] = timestamp_seconds
        except Exception as exc:
            logger.warning("PrometheusExporter session_start warning | error={}", exc)

    def _handle_session_end(self, raw: dict[str, Any]) -> None:
        """Handle session-end events for session metrics.

        Args:
            raw: Raw session-end payload.
        """
        try:
            agent_id = self._as_text(raw.get("agent_id"), default="unknown")
            session_id = self._as_text(raw.get("session_id"), default="")

            if self._sessions_active is not None:
                self._sessions_active.labels(agent_id=agent_id).dec()

            if not session_id:
                return

            duration_seconds: float | None = self._extract_session_duration_seconds(raw)

            if duration_seconds is None:
                start_time = self._session_start_times.pop(session_id, None)
                if start_time is not None:
                    duration_seconds = max(time.time() - start_time, 0.0)
            else:
                self._session_start_times.pop(session_id, None)

            if (
                duration_seconds is not None
                and self._session_duration_seconds is not None
            ):
                self._session_duration_seconds.labels(agent_id=agent_id).observe(
                    duration_seconds
                )
        except Exception as exc:
            logger.warning("PrometheusExporter session_end warning | error={}", exc)

    def _handle_threat(self, raw: dict[str, Any]) -> None:
        """Handle threat-detected events for threat metrics.

        Args:
            raw: Raw threat payload.
        """
        try:
            agent_id = self._as_text(raw.get("agent_id"), default="unknown")
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

            if self._threats_total is not None:
                self._threats_total.labels(
                    threat_type=threat_type,
                    severity=severity,
                    recommended_action=recommended_action,
                    agent_id=agent_id,
                ).inc()

            if self._detection_score_hist is not None:
                self._detection_score_hist.labels(
                    threat_type=threat_type,
                    agent_id=agent_id,
                ).observe(threat_score)

            if recommended_action == "BLOCK" and self._policy_blocks_total is not None:
                self._policy_blocks_total.labels(
                    threat_type=threat_type,
                    agent_id=agent_id,
                ).inc()

            if canary_triggered and self._canary_triggers_total is not None:
                self._canary_triggers_total.labels(agent_id=agent_id).inc()
        except Exception as exc:
            logger.warning("PrometheusExporter threat warning | error={}", exc)

    @staticmethod
    def _as_text(value: Any, default: str = "") -> str:
        """Normalize a raw field value into a string.

        Args:
            value: Raw value to normalize.
            default: Default string for missing values.

        Returns:
            Normalized string value.
        """
        if value is None:
            return default
        return str(value)

    @staticmethod
    def _as_float(value: Any, default: float = 0.0) -> float:
        """Normalize a raw field value into a float.

        Args:
            value: Raw value to normalize.
            default: Default float for parse failures.

        Returns:
            Parsed float value.
        """
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _extract_timestamp_seconds(raw: dict[str, Any]) -> float:
        """Extract a best-effort UNIX timestamp in seconds from payload data.

        Args:
            raw: Raw event payload.

        Returns:
            Timestamp seconds.
        """
        timestamp_value = raw.get("timestamp")
        if isinstance(timestamp_value, (float, int)):
            return float(timestamp_value)

        if isinstance(timestamp_value, str) and timestamp_value:
            try:
                parsed = datetime.fromisoformat(timestamp_value.replace("Z", "+00:00"))
                return parsed.timestamp()
            except ValueError:
                return time.time()

        return time.time()

    @staticmethod
    def _extract_session_duration_seconds(raw: dict[str, Any]) -> float | None:
        """Extract session duration seconds when explicitly present.

        Args:
            raw: Raw session-end payload.

        Returns:
            Parsed duration seconds, or None when unavailable.
        """
        metadata = raw.get("metadata")
        candidates = [
            raw.get("session_duration"),
            raw.get("session_duration_seconds"),
            (
                metadata.get("session_duration_seconds")
                if isinstance(metadata, dict)
                else None
            ),
        ]

        for candidate in candidates:
            if candidate is None:
                continue
            try:
                duration = float(candidate)
                if duration >= 0.0:
                    return duration
            except (TypeError, ValueError):
                continue

        return None
