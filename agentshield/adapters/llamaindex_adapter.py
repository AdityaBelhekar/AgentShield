"""LlamaIndex adapter with runtime hook interception."""

from __future__ import annotations

import asyncio
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from loguru import logger

from agentshield.adapters.base import AdapterContext, BaseAdapter
from agentshield.adapters.registry import AdapterRegistry
from agentshield.exceptions import AdapterError, PolicyViolationError


@AdapterRegistry.register
class LlamaIndexAdapter(BaseAdapter):
    """Adapter for LlamaIndex query/chat engines."""

    framework_name = "llamaindex"

    @classmethod
    def supports(cls, agent: Any) -> bool:
        """Return whether the object appears LlamaIndex-compatible.

        Args:
            agent: Candidate object.

        Returns:
            True when object satisfies expected LlamaIndex surface.
        """
        module_name = str(getattr(agent.__class__, "__module__", "")).lower()
        class_name = str(getattr(agent.__class__, "__name__", ""))

        if module_name.startswith(("llama_index", "llama_index.core")):
            return True

        if (hasattr(agent, "query") or hasattr(agent, "chat")) and hasattr(
            agent,
            "_callback_manager",
        ):
            return True

        return "QueryEngine" in class_name or "ChatEngine" in class_name

    def wrap(self, agent: Any, context: AdapterContext) -> Any:
        """Patch LlamaIndex methods with AgentShield runtime hooks.

        Args:
            agent: LlamaIndex engine instance.
            context: Runtime context.

        Returns:
            Patched object.

        Raises:
            AdapterError: If patching fails.
        """
        if getattr(agent, "_agentshield_llamaindex_patched", False):
            return agent

        try:
            self._patch_llm_methods(agent, context)
            self._patch_tools(agent, context)
            self._patch_memory(agent, context)
            agent._agentshield_llamaindex_patched = True
            return agent
        except PolicyViolationError:
            raise
        except Exception as error:
            logger.error(f"Adapter interception failed: {error}")
            raise AdapterError("Failed to patch LlamaIndex agent") from error

    def _patch_llm_methods(self, agent: Any, context: AdapterContext) -> None:
        """Patch query/chat methods.

        Args:
            agent: LlamaIndex object.
            context: Runtime context.
        """
        for method_name in ("query", "chat", "aquery", "achat"):
            original = getattr(agent, method_name, None)
            if not callable(original):
                continue

            if asyncio.iscoroutinefunction(original):

                async def async_wrapper(
                    *args: Any, _original: Any = original, **kwargs: Any
                ) -> Any:
                    prompt = self._extract_prompt(args, kwargs)
                    context.runtime.on_llm_start(prompt)
                    self._record_multi_agent_messages(agent, context, prompt)
                    try:
                        result = await _original(*args, **kwargs)
                    except PolicyViolationError:
                        raise
                    except Exception as error:
                        logger.error(f"Adapter interception failed: {error}")
                        raise
                    context.runtime.on_llm_end(self._extract_response(result))
                    return result

                setattr(agent, method_name, async_wrapper)
            else:

                def sync_wrapper(*args: Any, _original: Any = original, **kwargs: Any) -> Any:
                    prompt = self._extract_prompt(args, kwargs)
                    context.runtime.on_llm_start(prompt)
                    self._record_multi_agent_messages(agent, context, prompt)
                    try:
                        result = _original(*args, **kwargs)
                    except PolicyViolationError:
                        raise
                    except Exception as error:
                        logger.error(f"Adapter interception failed: {error}")
                        raise
                    context.runtime.on_llm_end(self._extract_response(result))
                    return result

                setattr(agent, method_name, sync_wrapper)

    def _patch_tools(self, agent: Any, context: AdapterContext) -> None:
        """Patch tool invocation methods if tools are exposed.

        Args:
            agent: LlamaIndex object.
            context: Runtime context.
        """
        tools = getattr(agent, "tools", None)
        if not isinstance(tools, (list, tuple)):
            return

        for tool in tools:
            tool_name = self._resolve_tool_name(tool)
            for method_name in ("call", "invoke", "run", "acall"):
                original = getattr(tool, method_name, None)
                if not callable(original):
                    continue

                if asyncio.iscoroutinefunction(original):

                    async def async_wrapper(
                        *args: Any,
                        _original: Any = original,
                        _tool_name: str = tool_name,
                        **kwargs: Any,
                    ) -> Any:
                        payload = self._extract_prompt(args, kwargs)
                        context.runtime.on_tool_start(_tool_name, payload)
                        try:
                            result = await _original(*args, **kwargs)
                        except PolicyViolationError:
                            raise
                        except Exception as error:
                            logger.error(f"Adapter interception failed: {error}")
                            raise
                        context.runtime.on_tool_end(_tool_name, self._extract_response(result))
                        return result

                    setattr(tool, method_name, async_wrapper)
                else:

                    def sync_wrapper(
                        *args: Any,
                        _original: Any = original,
                        _tool_name: str = tool_name,
                        **kwargs: Any,
                    ) -> Any:
                        payload = self._extract_prompt(args, kwargs)
                        context.runtime.on_tool_start(_tool_name, payload)
                        try:
                            result = _original(*args, **kwargs)
                        except PolicyViolationError:
                            raise
                        except Exception as error:
                            logger.error(f"Adapter interception failed: {error}")
                            raise
                        context.runtime.on_tool_end(_tool_name, self._extract_response(result))
                        return result

                    setattr(tool, method_name, sync_wrapper)

    def _patch_memory(self, agent: Any, context: AdapterContext) -> None:
        """Patch memory methods if a memory object is exposed.

        Args:
            agent: LlamaIndex object.
            context: Runtime context.
        """
        memory = getattr(agent, "memory", None)
        if memory is None:
            return

        for method_name in ("get", "read", "load"):
            original = getattr(memory, method_name, None)
            if not callable(original):
                continue

            if asyncio.iscoroutinefunction(original):

                async def async_read(*args: Any, _original: Any = original, **kwargs: Any) -> Any:
                    try:
                        result = await _original(*args, **kwargs)
                    except PolicyViolationError:
                        raise
                    except Exception as error:
                        logger.error(f"Adapter interception failed: {error}")
                        raise
                    context.runtime.on_memory_read(self._extract_response(result))
                    return result

                setattr(memory, method_name, async_read)
            else:

                def sync_read(*args: Any, _original: Any = original, **kwargs: Any) -> Any:
                    try:
                        result = _original(*args, **kwargs)
                    except PolicyViolationError:
                        raise
                    except Exception as error:
                        logger.error(f"Adapter interception failed: {error}")
                        raise
                    context.runtime.on_memory_read(self._extract_response(result))
                    return result

                setattr(memory, method_name, sync_read)

        for method_name in ("set", "write", "append", "put"):
            original = getattr(memory, method_name, None)
            if not callable(original):
                continue

            if asyncio.iscoroutinefunction(original):

                async def async_write(*args: Any, _original: Any = original, **kwargs: Any) -> Any:
                    context.runtime.on_memory_write(self._extract_prompt(args, kwargs))
                    try:
                        return await _original(*args, **kwargs)
                    except PolicyViolationError:
                        raise
                    except Exception as error:
                        logger.error(f"Adapter interception failed: {error}")
                        raise

                setattr(memory, method_name, async_write)
            else:

                def sync_write(*args: Any, _original: Any = original, **kwargs: Any) -> Any:
                    context.runtime.on_memory_write(self._extract_prompt(args, kwargs))
                    try:
                        return _original(*args, **kwargs)
                    except PolicyViolationError:
                        raise
                    except Exception as error:
                        logger.error(f"Adapter interception failed: {error}")
                        raise

                setattr(memory, method_name, sync_write)

    def _record_multi_agent_messages(
        self,
        agent: Any,
        context: AdapterContext,
        prompt: str,
    ) -> None:
        """Record inter-agent messages for multi-agent pipelines.

        Args:
            agent: LlamaIndex object.
            context: Runtime context.
            prompt: Prompt text.
        """
        if not prompt:
            return

        class_name = str(getattr(agent.__class__, "__name__", ""))
        child_agents = getattr(agent, "agents", None)
        if isinstance(child_agents, (list, tuple, set)) and child_agents:
            for child in child_agents:
                receiver = str(getattr(child, "name", type(child).__name__))
                context.runtime.record_inter_agent_message(
                    sender_agent_id=context.agent_id,
                    receiver_agent_id=receiver,
                    content=prompt,
                )
            return

        if "MultiAgent" in class_name:
            context.runtime.record_inter_agent_message(
                sender_agent_id=context.agent_id,
                receiver_agent_id="multi-agent-pipeline",
                content=prompt,
            )

    def _resolve_tool_name(self, tool: Any) -> str:
        """Resolve tool name from metadata or class.

        Args:
            tool: Tool object.

        Returns:
            Tool name.
        """
        metadata = getattr(tool, "metadata", None)
        if metadata is not None:
            metadata_name = getattr(metadata, "name", None)
            if isinstance(metadata_name, str) and metadata_name:
                return metadata_name
        return str(getattr(tool, "name", type(tool).__name__))

    def _extract_prompt(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
        """Extract best-effort prompt text.

        Args:
            args: Positional args.
            kwargs: Keyword args.

        Returns:
            Prompt-like content.
        """
        for key in ("query", "prompt", "message", "input"):
            value = kwargs.get(key)
            if value is not None:
                return str(value)

        if args:
            return str(args[0])
        return ""

    def _extract_response(self, result: Any) -> str:
        """Extract best-effort response text.

        Args:
            result: Method result.

        Returns:
            Response text.
        """
        if isinstance(result, dict):
            for key in ("response", "output", "text", "result"):
                if key in result:
                    return str(result[key])
        return str(result)

    @classmethod
    def get_framework_version(cls) -> str | None:
        """Return installed LlamaIndex package version.

        Returns:
            Installed version or None.
        """
        for package in ("llama-index-core", "llama-index"):
            try:
                return version(package)
            except PackageNotFoundError:
                continue
        return None
