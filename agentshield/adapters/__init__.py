"""AgentShield adapters — multi-framework integration layer."""

# isort: off
import agentshield.adapters.langchain_adapter as _lc  # noqa: F401
import agentshield.adapters.llamaindex_adapter as _li  # noqa: F401
import agentshield.adapters.autogen_adapter as _ag  # noqa: F401
# isort: on
from agentshield.adapters.base import AdapterConfig, AdapterContext, BaseAdapter
from agentshield.adapters.registry import AdapterRegistry

__all__ = [
    "AdapterConfig",
    "AdapterContext",
    "BaseAdapter",
    "AdapterRegistry",
]
