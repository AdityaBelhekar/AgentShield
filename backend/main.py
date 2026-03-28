from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from backend.dependencies import get_config, get_event_store, get_redis_bridge


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage backend startup and shutdown lifecycle.

    Startup:
      1. Load BackendConfig
      2. Initialize EventStore
      3. Initialize RedisBridge
      4. Register EventStore.add as handler on bridge
      5. Start bridge

    Shutdown:
      1. Stop RedisBridge cleanly
    """
    del app
    config = get_config()
    store = get_event_store()
    bridge = get_redis_bridge()

    bridge.register_handler(store.add)
    await bridge.start()
    logger.info(
        "AgentShield backend started | host={} port={} channel={}",
        config.host,
        config.port,
        config.redis_channel,
    )

    try:
        yield
    finally:
        await bridge.stop()
        logger.info("AgentShield backend stopped")


def create_app() -> FastAPI:
    """Create and configure the AgentShield FastAPI application.

    Returns:
        Configured FastAPI application instance.
    """
    config = get_config()
    app = FastAPI(
        title="AgentShield Backend",
        version="0.1.0",
        description="Real-time security event backend for AgentShield SDK",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    return app


app = create_app()
