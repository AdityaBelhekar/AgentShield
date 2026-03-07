"""Shared pytest fixtures for AgentShield tests."""

from __future__ import annotations

import os
from typing import Generator

import pytest

from agentshield.config import AgentShieldConfig


@pytest.fixture()
def config() -> AgentShieldConfig:
    """Return an AgentShieldConfig with test-safe defaults."""
    return AgentShieldConfig(
        redis_url="redis://localhost:6379",
        log_level="DEBUG",
        blocking_enabled=True,
        detection_enabled=True,
    )


@pytest.fixture()
def env_override() -> Generator[dict[str, str], None, None]:
    """Context manager that sets and restores env vars for testing."""
    original: dict[str, str | None] = {}
    overrides: dict[str, str] = {}

    def _set(key: str, value: str) -> None:
        original[key] = os.environ.get(key)
        os.environ[key] = value
        overrides[key] = value

    yield overrides  # type: ignore[misc]

    for key in original:
        if original[key] is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = original[key]  # type: ignore[assignment]
