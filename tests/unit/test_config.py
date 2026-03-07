"""Phase 0 tests — AgentShieldConfig validation."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

import pytest
import yaml

from agentshield.config import AgentShieldConfig


ROOT = Path(__file__).resolve().parents[2]


class TestModuleImports:
    """Verify all agentshield submodules import cleanly."""

    def test_import_agentshield(self) -> None:
        import agentshield  # noqa: F401

    def test_import_config(self) -> None:
        from agentshield.config import AgentShieldConfig  # noqa: F401

    def test_import_exceptions(self) -> None:
        from agentshield.exceptions import (  # noqa: F401
            AgentShieldError,
            ConfigurationError,
            DetectionError,
            EventEmissionError,
            GoalDriftError,
            InterceptorError,
            MemoryPoisonError,
            PolicyViolationError,
            PrivilegeEscalationError,
            PromptInjectionError,
            RedisConnectionError,
            ToolCallBlockedError,
        )

    def test_import_interceptors(self) -> None:
        import agentshield.interceptors  # noqa: F401

    def test_import_detection(self) -> None:
        import agentshield.detection  # noqa: F401

    def test_import_events(self) -> None:
        import agentshield.events  # noqa: F401

    def test_import_policy(self) -> None:
        import agentshield.policy  # noqa: F401


class TestAgentShieldConfig:
    """Validate AgentShieldConfig loading and env prefix."""

    def test_default_values(self) -> None:
        config = AgentShieldConfig()
        assert config.redis_url == "redis://localhost:6379"
        assert config.log_level == "INFO"
        assert config.detection_enabled is True
        assert config.blocking_enabled is True
        assert config.goal_drift_threshold == 0.35
        assert config.goal_drift_block_threshold == 0.55
        assert config.memory_poison_zscore_threshold == 2.5
        assert config.injection_similarity_threshold == 0.80
        assert config.embedding_model == "all-MiniLM-L6-v2"
        assert config.event_channel == "agentshield:events"

    def test_env_prefix_works(self) -> None:
        os.environ["AGENTSHIELD_LOG_LEVEL"] = "DEBUG"
        os.environ["AGENTSHIELD_BLOCKING_ENABLED"] = "false"
        os.environ["AGENTSHIELD_GOAL_DRIFT_THRESHOLD"] = "0.50"
        try:
            config = AgentShieldConfig()
            assert config.log_level == "DEBUG"
            assert config.blocking_enabled is False
            assert config.goal_drift_threshold == 0.50
        finally:
            os.environ.pop("AGENTSHIELD_LOG_LEVEL", None)
            os.environ.pop("AGENTSHIELD_BLOCKING_ENABLED", None)
            os.environ.pop("AGENTSHIELD_GOAL_DRIFT_THRESHOLD", None)

    def test_invalid_log_level_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid log level"):
            AgentShieldConfig(log_level="INVALID")

    def test_valid_log_levels_accepted(self) -> None:
        for level in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            config = AgentShieldConfig(log_level=level)
            assert config.log_level == level

    def test_log_level_case_insensitive(self) -> None:
        config = AgentShieldConfig(log_level="debug")
        assert config.log_level == "DEBUG"


class TestFileValidity:
    """Ensure project configuration files are structurally valid."""

    def test_pyproject_toml_is_valid(self) -> None:
        path = ROOT / "pyproject.toml"
        assert path.exists(), f"pyproject.toml not found at {path}"
        content = path.read_text(encoding="utf-8")
        data = tomllib.loads(content)
        assert "project" in data
        assert data["project"]["name"] == "agentshield"
        assert data["project"]["version"] == "0.1.0"

    def test_docker_compose_is_valid_yaml(self) -> None:
        path = ROOT / "docker-compose.yml"
        assert path.exists(), f"docker-compose.yml not found at {path}"
        content = path.read_text(encoding="utf-8")
        data = yaml.safe_load(content)
        assert "services" in data
        assert "redis" in data["services"]

    def test_gitignore_contains_scratch(self) -> None:
        path = ROOT / ".gitignore"
        assert path.exists(), ".gitignore not found"
        content = path.read_text(encoding="utf-8")
        assert "/scratch/" in content
