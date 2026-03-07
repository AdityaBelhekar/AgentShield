"""Phase 0 tests — Exception hierarchy validation."""

from __future__ import annotations

import pytest

from agentshield.exceptions import (
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


ALL_EXCEPTIONS = [
    AgentShieldError,
    ConfigurationError,
    InterceptorError,
    DetectionError,
    EventEmissionError,
    RedisConnectionError,
    PolicyViolationError,
    ToolCallBlockedError,
    PrivilegeEscalationError,
    GoalDriftError,
    PromptInjectionError,
    MemoryPoisonError,
]


class TestExceptionInstantiation:
    """All exception classes instantiate with correct fields."""

    @pytest.mark.parametrize("exc_cls", ALL_EXCEPTIONS)
    def test_instantiate_with_message(self, exc_cls: type) -> None:
        exc = exc_cls("test error")
        assert exc.message == "test error"
        assert str(exc).startswith("test error")

    @pytest.mark.parametrize("exc_cls", ALL_EXCEPTIONS)
    def test_instantiate_with_all_fields(self, exc_cls: type) -> None:
        exc = exc_cls(
            "test error",
            threat_type="PROMPT_INJECTION",
            confidence=0.95,
            evidence={"pattern": "ignore previous"},
        )
        assert exc.message == "test error"
        assert exc.threat_type == "PROMPT_INJECTION"
        assert exc.confidence == 0.95
        assert exc.evidence == {"pattern": "ignore previous"}

    @pytest.mark.parametrize("exc_cls", ALL_EXCEPTIONS)
    def test_defaults_for_optional_fields(self, exc_cls: type) -> None:
        exc = exc_cls("test")
        assert exc.threat_type is None
        assert exc.confidence is None
        assert exc.evidence == {}


class TestExceptionHierarchy:
    """Exception inheritance tree is correct."""

    def test_all_inherit_from_agentshield_error(self) -> None:
        for exc_cls in ALL_EXCEPTIONS:
            assert issubclass(exc_cls, AgentShieldError)

    def test_all_inherit_from_exception(self) -> None:
        for exc_cls in ALL_EXCEPTIONS:
            assert issubclass(exc_cls, Exception)

    def test_policy_violation_children(self) -> None:
        assert issubclass(ToolCallBlockedError, PolicyViolationError)
        assert issubclass(GoalDriftError, PolicyViolationError)
        assert issubclass(PromptInjectionError, PolicyViolationError)
        assert issubclass(MemoryPoisonError, PolicyViolationError)

    def test_privilege_escalation_is_tool_call_blocked(self) -> None:
        assert issubclass(PrivilegeEscalationError, ToolCallBlockedError)

    def test_configuration_error_direct_child(self) -> None:
        assert issubclass(ConfigurationError, AgentShieldError)
        assert not issubclass(ConfigurationError, PolicyViolationError)

    def test_interceptor_error_direct_child(self) -> None:
        assert issubclass(InterceptorError, AgentShieldError)
        assert not issubclass(InterceptorError, PolicyViolationError)

    def test_detection_error_direct_child(self) -> None:
        assert issubclass(DetectionError, AgentShieldError)
        assert not issubclass(DetectionError, PolicyViolationError)

    def test_catch_policy_violation_catches_children(self) -> None:
        with pytest.raises(PolicyViolationError):
            raise ToolCallBlockedError("blocked")

        with pytest.raises(PolicyViolationError):
            raise GoalDriftError("drifted")

        with pytest.raises(PolicyViolationError):
            raise PromptInjectionError("injected")

        with pytest.raises(PolicyViolationError):
            raise MemoryPoisonError("poisoned")

    def test_catch_agentshield_catches_all(self) -> None:
        for exc_cls in ALL_EXCEPTIONS:
            with pytest.raises(AgentShieldError):
                raise exc_cls("test")


class TestExceptionStringFormatting:
    """__str__ includes all populated fields."""

    def test_message_only(self) -> None:
        exc = AgentShieldError("simple error")
        assert str(exc) == "simple error"

    def test_with_threat_type(self) -> None:
        exc = AgentShieldError("error", threat_type="GOAL_DRIFT")
        result = str(exc)
        assert "error" in result
        assert "GOAL_DRIFT" in result

    def test_with_confidence(self) -> None:
        exc = AgentShieldError("error", confidence=0.87)
        result = str(exc)
        assert "0.87" in result

    def test_with_all_fields(self) -> None:
        exc = AgentShieldError(
            "blocked",
            threat_type="PROMPT_INJECTION",
            confidence=0.95,
            evidence={"sig": "ignore previous"},
        )
        result = str(exc)
        assert "blocked" in result
        assert "PROMPT_INJECTION" in result
        assert "0.95" in result
        assert "ignore previous" in result
