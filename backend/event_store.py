from __future__ import annotations

import asyncio
import collections
from pathlib import Path

from loguru import logger

from agentshield.events.models import BaseEvent, ThreatEvent
from backend.config import BackendConfig


class EventStore:
    """Rolling in-memory store for AgentShield events.

    Uses a bounded deque so memory stays capped at max_size.
    When full, the oldest event is dropped automatically.
    All mutations are protected by asyncio.Lock for coroutine safety.

    If persist_events=True in config, every event is also
    appended to a JSONL file at persistence_path.
    """

    _config: BackendConfig
    _store: collections.deque[BaseEvent]
    _lock: asyncio.Lock
    _updated: asyncio.Event

    def __init__(self, config: BackendConfig) -> None:
        """Initialize the event store.

        Args:
            config: Backend configuration with capacity and persistence options.
        """
        self._config = config
        self._store = collections.deque(maxlen=config.event_store_max_size)
        self._lock = asyncio.Lock()
        self._updated = asyncio.Event()
        logger.info(
            "EventStore initialized | max_size={} persist_events={} path={}",
            config.event_store_max_size,
            config.persist_events,
            config.persistence_path,
        )

    async def add(self, event: BaseEvent) -> None:
        """Add a single event to the store.

        Appends to the deque (dropping oldest if at capacity).
        If persist_events=True, appends serialized event to JSONL.
        Sets _updated event to wake any waiting WebSocket handlers.

        Args:
            event: Any BaseEvent subclass instance.
        """
        async with self._lock:
            self._store.append(event)
            if self._config.persist_events:
                self._append_jsonl(event)
            self._updated.set()
            self._updated.clear()

    async def get_all(self) -> list[BaseEvent]:
        """Return a snapshot of all events in insertion order.

        Returns:
            List of events from oldest to newest.
        """
        async with self._lock:
            return list(self._store)

    async def get_by_session(self, session_id: str) -> list[BaseEvent]:
        """Return all events belonging to a specific session.

        Args:
            session_id: String UUID of the target session.

        Returns:
            Filtered list, may be empty.
        """
        async with self._lock:
            return [
                event for event in self._store if str(event.session_id) == session_id
            ]

    async def get_threats(self) -> list[ThreatEvent]:
        """Return only ThreatEvent instances from the store.

        Returns:
            List containing only threat events.
        """
        async with self._lock:
            return [event for event in self._store if isinstance(event, ThreatEvent)]

    async def get_recent(self, n: int = 100) -> list[BaseEvent]:
        """Return the n most recent events.

        Args:
            n: Maximum number of events to return.

        Returns:
            List of up to n events, most recent last.
        """
        count = max(n, 0)
        async with self._lock:
            if count == 0:
                return []
            if count >= len(self._store):
                return list(self._store)
            return list(self._store)[-count:]

    async def clear(self) -> None:
        """Clear all events from the in-memory store."""
        async with self._lock:
            self._store.clear()
            logger.info("EventStore cleared")

    def size(self) -> int:
        """Return current event count.

        Returns:
            Current number of in-memory events.
        """
        return len(self._store)

    def _append_jsonl(self, event: BaseEvent) -> None:
        """Append one serialized event to JSONL persistence.

        Args:
            event: Event to serialize and append.
        """
        path = Path(self._config.persistence_path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(event.model_dump_json())
                handle.write("\n")
        except OSError as exc:
            logger.error(
                "Event persistence failed | path={} event_id={} error={}",
                path,
                event.id,
                exc,
            )
