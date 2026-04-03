"""Adapter registry used for framework auto-detection."""

from __future__ import annotations

from typing import Any, ClassVar

from agentshield.adapters.base import BaseAdapter


class AdapterRegistry:
    """Class-level registry for framework adapter discovery."""

    _adapters: ClassVar[list[type[BaseAdapter]]] = []

    @classmethod
    def register(cls, adapter_cls: type[BaseAdapter]) -> type[BaseAdapter]:
        """Register an adapter class.

        Args:
            adapter_cls: Adapter class to register.

        Returns:
            The same adapter class for decorator-style registration.
        """
        if adapter_cls not in cls._adapters:
            cls._adapters.append(adapter_cls)
        return adapter_cls

    @classmethod
    def detect(cls, agent: Any) -> type[BaseAdapter] | None:
        """Detect the first adapter that supports the given agent.

        Args:
            agent: Agent object to inspect.

        Returns:
            Matching adapter class when found, else None.
        """
        for adapter_cls in cls._adapters:
            if adapter_cls.supports(agent):
                return adapter_cls
        return None

    @classmethod
    def list_adapters(cls) -> list[str]:
        """List registered framework adapter names.

        Returns:
            Ordered list of framework names from registered adapters.
        """
        return [adapter.framework_name for adapter in cls._adapters]
