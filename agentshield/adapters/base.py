"""Base abstractions shared by all AgentShield framework adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar

from loguru import logger
from pydantic import BaseModel, ConfigDict

if TYPE_CHECKING:
    from agentshield.runtime import AgentShieldRuntime


def get_logger(name: str) -> Any:
    """Build a Loguru logger bound to adapter module metadata.

    Args:
        name: Module name used for logger metadata.

    Returns:
        Loguru logger with module context bound.
    """
    return logger.bind(module=name)


class AdapterConfig(BaseModel):
    """Configuration payload passed to adapter implementations.

    Attributes:
        framework_name: Framework identifier for this adapter.
        enabled: Whether this adapter is active.
    """

    framework_name: str
    enabled: bool = True

    model_config = ConfigDict(extra="allow")


@dataclass(slots=True)
class AdapterContext:
    """Execution context provided to adapter wrappers.

    Attributes:
        runtime: Active AgentShield runtime instance.
        config: Adapter-scoped configuration.
        agent_id: Human-readable agent identifier.
        session_id: Runtime-level adapter session identifier.
    """

    runtime: AgentShieldRuntime
    config: AdapterConfig
    agent_id: str
    session_id: str


class BaseAdapter(ABC):
    """Abstract base class for AgentShield framework adapters."""

    framework_name: ClassVar[str]
    logger: ClassVar[Any] = get_logger(__name__)

    @classmethod
    @abstractmethod
    def supports(cls, agent: Any) -> bool:
        """Return whether this adapter supports the given agent object.

        Implementations must use duck-typing checks (for example, ``hasattr``)
        and avoid concrete ``isinstance`` checks.

        Args:
            agent: Agent object to inspect.

        Returns:
            True when this adapter can wrap the agent, else False.
        """

    @abstractmethod
    def wrap(self, agent: Any, context: AdapterContext) -> Any:
        """Wrap an agent object with framework-specific protections.

        Args:
            agent: Agent object selected for adapter wrapping.
            context: Runtime and adapter metadata.

        Returns:
            Wrapped or transformed agent object.
        """

    @classmethod
    @abstractmethod
    def get_framework_version(cls) -> str | None:
        """Return the detected framework package version.

        Returns:
            Installed framework version string, or None when unavailable.
        """
