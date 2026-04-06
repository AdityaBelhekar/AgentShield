"""LangChain adapter with runtime hook interception."""

from __future__ import annotations

import asyncio
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from loguru import logger

from agentshield.adapters.base import AdapterContext, BaseAdapter
from agentshield.adapters.registry import AdapterRegistry
from agentshield.exceptions import AdapterError, PolicyViolationError


@AdapterRegistry.register
class LangChainAdapter(BaseAdapter):
    """Adapter for LangChain-compatible agent objects."""

    framework_name = "langchain"

    @classmethod
    def supports(cls, agent: Any) -> bool:
        """Return whether the object appears LangChain-compatible.

        Args:
            agent: Candidate object.

        Returns:
            True when object satisfies LangChain-like runtime shape.
        """
        module_name = str(getattr(agent.__class__, "__module__", "")).lower()
        if module_name.startswith(("langchain", "langchain_core")):
            return True

        return all(hasattr(agent, attr) for attr in ("run", "invoke")) and hasattr(
            agent, "_lc_namespace"
        )

    def wrap(self, agent: Any, context: AdapterContext) -> Any:
        """Patch LangChain methods with AgentShield runtime hooks.

        Args:
            agent: Agent instance to patch.
            context: Runtime context.

        Returns:
            Patched agent object.

        Raises:
            AdapterError: If mandatory patch points fail.
        """
        if getattr(agent, "_agentshield_langchain_patched", False):
            return agent

        try:
            self._patch_llm_methods(agent, context)
            self._patch_tools(agent, context)
            self._patch_memory(agent, context)
            agent._agentshield_langchain_patched = True
            return agent
        except PolicyViolationError:
            raise
        except Exception as error:
            logger.error(f"Adapter interception failed: {error}")
            raise AdapterError("Failed to patch LangChain agent") from error

    def _patch_llm_methods(self, agent: Any, context: AdapterContext) -> None:
        """Patch LLM-facing methods on a LangChain agent.

        Args:
            agent: Agent instance.
            context: Runtime context.
        """
        method_names = ["run", "invoke", "stream", "arun", "ainvoke", "astream"]

        for method_name in method_names:
            original = getattr(agent, method_name, None)
            if not callable(original):
                continue

            if asyncio.iscoroutinefunction(original):

                async def async_wrapper(
                    *args: Any, _original: Any = original, **kwargs: Any
                ) -> Any:
                    prompt = self._extract_prompt(args, kwargs)
                    context.runtime.on_llm_start(prompt)
                    self._record_sub_agent_messages(agent, context, prompt)
                    try:
                        result = await _original(*args, **kwargs)
                    except PolicyViolationError:
                        raise
                    except Exception as error:
                        logger.error(f"Adapter interception failed: {error}")
                        raise
                    context.runtime.on_llm_end(self._extract_response(result))
                    return result

                self._assign_callable(agent, method_name, async_wrapper)
            else:

                def sync_wrapper(*args: Any, _original: Any = original, **kwargs: Any) -> Any:
                    prompt = self._extract_prompt(args, kwargs)
                    context.runtime.on_llm_start(prompt)
                    self._record_sub_agent_messages(agent, context, prompt)
                    try:
                        result = _original(*args, **kwargs)
                    except PolicyViolationError:
                        raise
                    except Exception as error:
                        logger.error(f"Adapter interception failed: {error}")
                        raise
                    context.runtime.on_llm_end(self._extract_response(result))
                    return result

                self._assign_callable(agent, method_name, sync_wrapper)

    def _patch_tools(self, agent: Any, context: AdapterContext) -> None:
        """Patch tool call methods exposed by LangChain agents.

        Args:
            agent: Agent instance.
            context: Runtime context.
        """
        tools = getattr(agent, "tools", None)
        if not isinstance(tools, (list, tuple)):
            return

        for tool in tools:
            tool_name = str(getattr(tool, "name", type(tool).__name__))
            for method_name in ("run", "invoke", "call", "_run", "_arun"):
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

                    self._assign_callable(tool, method_name, async_wrapper)
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

                    self._assign_callable(tool, method_name, sync_wrapper)

    def _patch_memory(self, agent: Any, context: AdapterContext) -> None:
        """Patch memory read/write calls when an agent memory object exists.

        Args:
            agent: Agent instance.
            context: Runtime context.
        """
        memory = getattr(agent, "memory", None)
        if memory is None:
            return

        read_methods = ("load_memory_variables", "load_memory_vars", "read", "get")
        write_methods = ("save_context", "write", "set", "append")

        for method_name in read_methods:
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

                self._assign_callable(memory, method_name, async_read)
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

                self._assign_callable(memory, method_name, sync_read)

        for method_name in write_methods:
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

                self._assign_callable(memory, method_name, async_write)
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

                self._assign_callable(memory, method_name, sync_write)

    def _assign_callable(self, target: Any, name: str, wrapper: Any) -> None:
        """Assign a patched callable to a framework object.

        Some LangChain objects are Pydantic models that reject normal
        setattr for undeclared fields. Fall back to object.__setattr__
        so runtime hook patching works across both plain and Pydantic
        object types.

        Args:
            target: Object receiving the patched callable.
            name: Attribute/method name to patch.
            wrapper: Replacement callable.
        """
        try:
            setattr(target, name, wrapper)
            return
        except (ValueError, AttributeError, TypeError):
            object.__setattr__(target, name, wrapper)

    def _record_sub_agent_messages(
        self,
        agent: Any,
        context: AdapterContext,
        prompt: str,
    ) -> None:
        """Record LangChain multi-agent message hints when sub-agents are present.

        Args:
            agent: Parent LangChain agent.
            context: Runtime context.
            prompt: Prompt text routed through parent agent.
        """
        if not prompt:
            return

        sub_agents = getattr(agent, "sub_agents", None)
        if not isinstance(sub_agents, (list, tuple, set)):
            sub_agents = getattr(agent, "agents", None)

        if not isinstance(sub_agents, (list, tuple, set)):
            return

        for sub_agent in sub_agents:
            receiver = str(getattr(sub_agent, "name", type(sub_agent).__name__))
            context.runtime.record_inter_agent_message(
                sender_agent_id=context.agent_id,
                receiver_agent_id=receiver,
                content=prompt,
            )

    def _extract_prompt(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
        """Extract best-effort prompt text from wrapper call arguments.

        Args:
            args: Positional arguments.
            kwargs: Keyword arguments.

        Returns:
            Prompt-like text.
        """
        for key in ("input", "query", "prompt", "message"):
            value = kwargs.get(key)
            if value is not None:
                return str(value)

        messages = kwargs.get("messages")
        if messages is not None:
            return str(messages)

        if not args:
            return ""

        first = args[0]
        if isinstance(first, dict):
            for key in ("input", "query", "prompt", "message"):
                if key in first:
                    return str(first[key])
        return str(first)

    def _extract_response(self, result: Any) -> str:
        """Extract best-effort response text from a method result.

        Args:
            result: Method result value.

        Returns:
            Response-like text.
        """
        if isinstance(result, dict):
            for key in ("output", "response", "result", "text"):
                if key in result:
                    return str(result[key])
        return str(result)

    @classmethod
    def get_framework_version(cls) -> str | None:
        """Return installed LangChain package version.

        Returns:
            Installed version string or None.
        """
        for package in ("langchain", "langchain-core"):
            try:
                return version(package)
            except PackageNotFoundError:
                continue
        return None
