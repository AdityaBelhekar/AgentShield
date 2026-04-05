"""Attack execution runner for AgentShield red team CLI."""

from __future__ import annotations

import importlib
import time
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, cast

from loguru import logger
from pydantic import BaseModel, ConfigDict

from agentshield.cli.attack_library import (
    AttackCategory,
    AttackPayload,
    AttackSeverity,
)
from agentshield.exceptions import AgentShieldError, PolicyViolationError

if TYPE_CHECKING:
    from agentshield.runtime import WrappedAgent


class AttackOutcome(StrEnum):
    """Outcome classification for one attack execution."""

    DETECTED = "detected"
    BYPASSED = "bypassed"
    SIMULATED = "simulated"
    ERROR = "error"


class AttackResult(BaseModel):
    """Result of running a single attack against a shielded agent.

    Attributes:
        attack_id: ID of the AttackPayload that was run.
        attack_name: Human-readable name.
        category: Attack category.
        severity: Attack severity.
        outcome: DETECTED / BYPASSED / SIMULATED / ERROR.
        exception_type: Class name of the raised exception, if any.
        exception_message: Short message from the exception, if any.
        latency_ms: Wall-clock ms from agent.run() call to return/exception.
        timestamp: ISO 8601 UTC timestamp of when this attack was run.
        notes: Any runner-generated notes.
    """

    model_config = ConfigDict(frozen=True)

    attack_id: str
    attack_name: str
    category: AttackCategory
    severity: AttackSeverity
    outcome: AttackOutcome
    exception_type: str | None = None
    exception_message: str | None = None
    latency_ms: float
    timestamp: str
    notes: str | None = None


class AgentLoader:
    """Imports and instantiates a user-supplied agent factory.

    The agent_module string must be in the format "module.path:callable_name".
    The callable is called with no arguments and must return a WrappedAgent.
    """

    _agent_module: str

    def __init__(self, agent_module: str) -> None:
        """Initialize an AgentLoader.

        Args:
            agent_module: Import path in module.path:callable_name format.
        """
        self._agent_module = agent_module

    def load(self) -> WrappedAgent:
        """Import the module and call the factory.

        Returns:
            A WrappedAgent instance.

        Raises:
            AgentShieldError: If module path is malformed, import fails,
                callable lookup fails, callable invocation fails, or return
                value is not a WrappedAgent.
        """
        module_path, callable_name = self._parse_agent_module(self._agent_module)

        try:
            module = importlib.import_module(module_path)
        except (ModuleNotFoundError, ImportError) as exc:
            raise AgentShieldError(f"Failed to import agent module '{module_path}': {exc}") from exc

        try:
            factory = getattr(module, callable_name)
        except AttributeError as exc:
            raise AgentShieldError(
                f"Callable '{callable_name}' not found in module '{module_path}'"
            ) from exc

        if not callable(factory):
            raise AgentShieldError(
                f"Symbol '{callable_name}' in module '{module_path}' is not callable"
            )

        factory_callable = cast(Callable[[], object], factory)
        try:
            candidate = factory_callable()
        except (TypeError, ValueError, RuntimeError) as exc:
            raise AgentShieldError(f"Agent factory '{self._agent_module}' failed: {exc}") from exc
        except BaseException as exc:
            raise AgentShieldError(
                "Agent factory "
                f"'{self._agent_module}' raised unexpected error: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

        from agentshield.runtime import WrappedAgent

        if not isinstance(candidate, WrappedAgent):
            raise AgentShieldError(
                "Agent factory must return a WrappedAgent instance, got "
                f"{type(candidate).__name__}"
            )

        return candidate

    @staticmethod
    def _parse_agent_module(agent_module: str) -> tuple[str, str]:
        """Parse module.path:callable_name string.

        Args:
            agent_module: User-provided import path.

        Returns:
            Tuple of module path and callable name.

        Raises:
            AgentShieldError: If format is invalid.
        """
        if ":" not in agent_module:
            raise AgentShieldError("agent_module must be in format 'module.path:callable_name'")

        module_path, callable_name = agent_module.split(":", maxsplit=1)
        if not module_path or not callable_name:
            raise AgentShieldError("agent_module must include both module path and callable name")

        return module_path, callable_name


class AttackRunner:
    """Drives a shielded agent through a list of attack payloads.

    Args:
        agent: The WrappedAgent to attack.
        policy: Policy name or path passed to shield(). Informational only.
    """

    _agent: WrappedAgent
    _policy: str

    def __init__(self, agent: WrappedAgent, policy: str) -> None:
        """Initialize attack runner.

        Args:
            agent: Shielded agent wrapper.
            policy: Policy name/path used for this run.
        """
        self._agent = agent
        self._policy = policy

    def run_single(self, attack: AttackPayload) -> AttackResult:
        """Run one attack payload against the agent.

        Args:
            attack: Attack payload to run.

        Returns:
            AttackResult with execution metadata.
        """
        timestamp = self._utc_now_iso()

        if attack.payload.startswith("[SIMULATION]"):
            return AttackResult(
                attack_id=attack.id,
                attack_name=attack.name,
                category=attack.category,
                severity=attack.severity,
                outcome=AttackOutcome.SIMULATED,
                latency_ms=0.0,
                timestamp=timestamp,
                notes=(
                    "Simulation attack; live runner not supported for this " "category in Phase 9B."
                ),
            )

        started = time.perf_counter()
        try:
            self._agent.run(attack.payload)
        except PolicyViolationError as exc:
            return AttackResult(
                attack_id=attack.id,
                attack_name=attack.name,
                category=attack.category,
                severity=attack.severity,
                outcome=AttackOutcome.DETECTED,
                exception_type=type(exc).__name__,
                exception_message=self._truncate_message(str(exc)),
                latency_ms=self._elapsed_ms(started),
                timestamp=timestamp,
            )
        except BaseException as exc:
            logger.warning(
                "Attack run failed unexpectedly | attack_id={} exception_type={} "
                "exception_message={}",
                attack.id,
                type(exc).__name__,
                exc,
            )
            return AttackResult(
                attack_id=attack.id,
                attack_name=attack.name,
                category=attack.category,
                severity=attack.severity,
                outcome=AttackOutcome.ERROR,
                exception_type=type(exc).__name__,
                exception_message=self._truncate_message(str(exc)),
                latency_ms=self._elapsed_ms(started),
                timestamp=timestamp,
            )

        return AttackResult(
            attack_id=attack.id,
            attack_name=attack.name,
            category=attack.category,
            severity=attack.severity,
            outcome=AttackOutcome.BYPASSED,
            latency_ms=self._elapsed_ms(started),
            timestamp=timestamp,
        )

    def run_all(self, attacks: list[AttackPayload]) -> list[AttackResult]:
        """Run all attacks in sequence and return results.

        Args:
            attacks: Attack payloads to execute.

        Returns:
            Ordered list of per-attack results.
        """
        total = len(attacks)
        results: list[AttackResult] = []
        for index, attack in enumerate(attacks, start=1):
            logger.info("Running attack {}/{}: {}", index, total, attack.id)
            results.append(self.run_single(attack))
        return results

    @staticmethod
    def _utc_now_iso() -> str:
        """Return current UTC timestamp in ISO 8601 format."""
        return datetime.now(UTC).isoformat()

    @staticmethod
    def _elapsed_ms(started: float) -> float:
        """Compute elapsed time in milliseconds.

        Args:
            started: perf_counter start value.

        Returns:
            Elapsed milliseconds.
        """
        return (time.perf_counter() - started) * 1000.0

    @staticmethod
    def _truncate_message(message: str, max_length: int = 200) -> str:
        """Truncate exception messages to a bounded length.

        Args:
            message: Full message text.
            max_length: Maximum allowed length.

        Returns:
            Original or truncated message.
        """
        if len(message) <= max_length:
            return message
        return message[:max_length]
