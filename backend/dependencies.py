from __future__ import annotations

from backend.config import BackendConfig
from backend.event_store import EventStore
from backend.redis_bridge import RedisBridge

_config: BackendConfig | None = None
_event_store: EventStore | None = None
_redis_bridge: RedisBridge | None = None


def get_config() -> BackendConfig:
    """Return singleton backend configuration.

    Returns:
        Singleton BackendConfig instance.
    """
    global _config
    if _config is None:
        _config = BackendConfig()
    return _config


def get_event_store() -> EventStore:
    """Return singleton backend EventStore.

    Returns:
        Singleton EventStore instance.
    """
    global _event_store
    if _event_store is None:
        _event_store = EventStore(get_config())
    return _event_store


def get_redis_bridge() -> RedisBridge:
    """Return singleton backend RedisBridge.

    Returns:
        Singleton RedisBridge instance.
    """
    global _redis_bridge
    if _redis_bridge is None:
        _redis_bridge = RedisBridge(get_config())
    return _redis_bridge
