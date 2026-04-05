"""Adapter registry and framework auto-detection for AgentShield."""

from __future__ import annotations

from typing import Any, ClassVar

from agentshield.adapters.base import BaseAdapter
from agentshield.exceptions import ConfigurationError


class AdapterRegistry:
    """Resolve framework adapters by explicit name or object introspection."""

    _framework_adapters: ClassVar[dict[str, type[BaseAdapter]]] = {}
    _supported_frameworks: ClassVar[tuple[str, ...]] = (
        "langchain",
        "llamaindex",
        "autogen",
        "openai",
        "anthropic",
    )

    @classmethod
    def register(cls, adapter_cls: type[BaseAdapter]) -> type[BaseAdapter]:
        """Register an adapter class by its framework_name.

        Args:
            adapter_cls: Adapter class to register.

        Returns:
            The same adapter class for decorator-style registration.
        """
        framework_name = str(getattr(adapter_cls, "framework_name", "")).lower()
        if framework_name:
            cls._framework_adapters[framework_name] = adapter_cls
        return adapter_cls

    @classmethod
    def get(cls, framework: str) -> BaseAdapter:
        """Return an adapter instance for a known framework value.

        Args:
            framework: Framework key.

        Returns:
            Instantiated adapter implementation.

        Raises:
            ConfigurationError: If framework is not supported.
        """
        normalized = framework.strip().lower()
        if normalized not in cls._supported_frameworks:
            options = ", ".join(cls._supported_frameworks)
            raise ConfigurationError(f"Invalid framework '{framework}'. Valid options: {options}.")

        adapter_cls = cls._framework_adapters.get(normalized)
        if adapter_cls is None:
            adapter_cls = cls._load_default_adapter(normalized)
            cls._framework_adapters[normalized] = adapter_cls

        return adapter_cls()

    @classmethod
    def detect(cls, agent: Any) -> BaseAdapter:
        """Detect framework adapter for an arbitrary agent object.

        Detection priority order:
          1) LangChain
          2) LlamaIndex
          3) AutoGen
          4) OpenAI
          5) Anthropic

        Args:
            agent: Candidate agent object.

        Returns:
            Instantiated adapter implementation.

        Raises:
            ConfigurationError: If no supported framework can be detected.
        """
        module_name = str(getattr(agent.__class__, "__module__", "")).lower()
        class_name = str(getattr(agent.__class__, "__name__", ""))

        if cls._is_langchain(agent, module_name):
            return cls.get("langchain")

        if cls._is_llamaindex(agent, module_name, class_name):
            return cls.get("llamaindex")

        if cls._is_autogen(agent, module_name, class_name):
            return cls.get("autogen")

        if cls._is_openai(agent, module_name):
            return cls.get("openai")

        if cls._is_anthropic(agent, module_name):
            return cls.get("anthropic")

        raise ConfigurationError(
            "AgentShield could not detect the framework for agent of type "
            f"'{type(agent).__name__}'. Supported frameworks: LangChain, "
            "LlamaIndex, AutoGen, OpenAI, Anthropic. Pass framework= explicitly "
            "if auto-detection fails."
        )

    @classmethod
    def list_adapters(cls) -> list[str]:
        """List supported framework keys.

        Returns:
            Stable list of supported framework names.
        """
        return list(cls._supported_frameworks)

    @classmethod
    def _is_langchain(cls, agent: Any, module_name: str) -> bool:
        """Return whether an object matches LangChain detection rules."""
        if module_name.startswith(("langchain", "langchain_core")):
            return True

        has_runtime_shape = all(
            hasattr(agent, attr) for attr in ("run", "invoke", "stream")
        ) and hasattr(agent, "_lc_namespace")
        if has_runtime_shape:
            return True

        import importlib

        candidates: list[type[Any]] = []
        lookups: tuple[tuple[str, str], ...] = (
            ("langchain.chains.base", "Chain"),
            ("langchain_core.language_models.chat_models", "BaseChatModel"),
            ("langchain.agents", "AgentExecutor"),
        )
        for import_path, class_name in lookups:
            try:
                module = importlib.import_module(import_path)
            except ImportError:
                continue
            candidate = getattr(module, class_name, None)
            if isinstance(candidate, type):
                candidates.append(candidate)

        return any(isinstance(agent, candidate) for candidate in candidates)

    @classmethod
    def _is_llamaindex(cls, agent: Any, module_name: str, class_name: str) -> bool:
        """Return whether an object matches LlamaIndex detection rules."""
        if module_name.startswith(("llama_index", "llama_index.core")):
            return True

        has_runtime_shape = (hasattr(agent, "query") or hasattr(agent, "chat")) and hasattr(
            agent, "_callback_manager"
        )
        if has_runtime_shape:
            return True

        return "QueryEngine" in class_name or "ChatEngine" in class_name

    @classmethod
    def _is_autogen(cls, agent: Any, module_name: str, class_name: str) -> bool:
        """Return whether an object matches AutoGen detection rules."""
        if module_name.startswith(("autogen", "pyautogen")):
            return True

        if hasattr(agent, "initiate_chat") or hasattr(agent, "generate_reply"):
            return True

        return "ConversableAgent" in class_name or "AssistantAgent" in class_name

    @classmethod
    def _is_openai(cls, agent: Any, module_name: str) -> bool:
        """Return whether an object matches OpenAI detection rules."""
        if module_name.startswith("openai"):
            return True

        try:
            import importlib

            module = importlib.import_module("openai")
            openai_type = getattr(module, "OpenAI", None)
            async_openai_type = getattr(module, "AsyncOpenAI", None)
            candidates = tuple(
                candidate
                for candidate in (openai_type, async_openai_type)
                if isinstance(candidate, type)
            )
            if candidates and isinstance(agent, candidates):
                return True
        except ImportError:
            pass

        chat_obj = getattr(agent, "chat", None)
        return chat_obj is not None and hasattr(chat_obj, "completions")

    @classmethod
    def _is_anthropic(cls, agent: Any, module_name: str) -> bool:
        """Return whether an object matches Anthropic detection rules."""
        if module_name.startswith("anthropic"):
            return True

        try:
            import importlib

            module = importlib.import_module("anthropic")
            anthropic_type = getattr(module, "Anthropic", None)
            async_anthropic_type = getattr(module, "AsyncAnthropic", None)
            candidates = tuple(
                candidate
                for candidate in (anthropic_type, async_anthropic_type)
                if isinstance(candidate, type)
            )
            if candidates and isinstance(agent, candidates):
                return True
        except ImportError:
            pass

        messages_obj = getattr(agent, "messages", None)
        create_method = getattr(messages_obj, "create", None)
        return messages_obj is not None and callable(create_method)

    @classmethod
    def _load_default_adapter(cls, framework: str) -> type[BaseAdapter]:
        """Load built-in adapter class for a framework key.

        Args:
            framework: Normalized framework name.

        Returns:
            Adapter class implementation.

        Raises:
            ConfigurationError: If framework has no mapped adapter class.
        """
        if framework == "langchain":
            from agentshield.adapters.langchain_adapter import LangChainAdapter

            return LangChainAdapter
        if framework == "llamaindex":
            from agentshield.adapters.llamaindex_adapter import LlamaIndexAdapter

            return LlamaIndexAdapter
        if framework == "autogen":
            from agentshield.adapters.autogen_adapter import AutoGenAdapter

            return AutoGenAdapter
        if framework == "openai":
            from agentshield.adapters.openai_adapter import OpenAIAdapter

            return OpenAIAdapter
        if framework == "anthropic":
            from agentshield.adapters.anthropic_adapter import AnthropicAdapter

            return AnthropicAdapter

        options = ", ".join(cls._supported_frameworks)
        raise ConfigurationError(f"Invalid framework '{framework}'. Valid options: {options}.")
