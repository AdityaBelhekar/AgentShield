"""AutoGen adapter with runtime hook interception."""

from __future__ import annotations

import asyncio
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from loguru import logger

from agentshield.adapters.base import AdapterContext, BaseAdapter
from agentshield.adapters.registry import AdapterRegistry
from agentshield.exceptions import AdapterError, PolicyViolationError


@AdapterRegistry.register
class AutoGenAdapter(BaseAdapter):
    """Adapter for AutoGen conversational agents."""

    framework_name = "autogen"

    @classmethod
    def supports(cls, agent: Any) -> bool:
        """Return whether object appears AutoGen-compatible.

        Args:
            agent: Candidate object.

        Returns:
            True when object matches common AutoGen surfaces.
        """
        module_name = str(getattr(agent.__class__, "__module__", "")).lower()
        class_name = str(getattr(agent.__class__, "__name__", ""))

        if module_name.startswith(("autogen", "pyautogen")):
            return True

        if hasattr(agent, "initiate_chat") or hasattr(agent, "generate_reply"):
            return True

        return "ConversableAgent" in class_name or "AssistantAgent" in class_name

    def wrap(self, agent: Any, context: AdapterContext) -> Any:
        """Patch AutoGen methods with AgentShield runtime hooks.

        Args:
            agent: AutoGen agent object.
            context: Runtime context.

        Returns:
            Patched object.

        Raises:
            AdapterError: If patching fails.
        """
        if getattr(agent, "_agentshield_autogen_patched", False):
            return agent

        try:
            self._patch_llm_methods(agent, context)
            self._patch_message_methods(agent, context)
            self._patch_tool_functions(agent, context)
            self._patch_memory(agent, context)
            agent._agentshield_autogen_patched = True
            return agent
        except PolicyViolationError:
            raise
        except Exception as error:
            logger.error(f"Adapter interception failed: {error}")
            raise AdapterError("Failed to patch AutoGen agent") from error

    def _patch_llm_methods(self, agent: Any, context: AdapterContext) -> None:
        """Patch LLM-facing AutoGen methods.

        Args:
            agent: AutoGen agent.
            context: Runtime context.
        """
        for method_name in (
            "initiate_chat",
            "generate_reply",
            "a_initiate_chat",
            "a_generate_reply",
        ):
            original = getattr(agent, method_name, None)
            if not callable(original):
                continue

            if asyncio.iscoroutinefunction(original):

                async def async_wrapper(
                    *args: Any, _original: Any = original, **kwargs: Any
                ) -> Any:
                    prompt = self._extract_prompt(args, kwargs)
                    context.runtime.on_llm_start(prompt)
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

    def _patch_message_methods(self, agent: Any, context: AdapterContext) -> None:
        """Patch send/receive methods for inter-agent communication logging.

        Args:
            agent: AutoGen agent.
            context: Runtime context.
        """
        for method_name in ("send", "receive"):
            original = getattr(agent, method_name, None)
            if not callable(original):
                continue

            if asyncio.iscoroutinefunction(original):

                async def async_wrapper(
                    *args: Any,
                    _original: Any = original,
                    _method_name: str = method_name,
                    **kwargs: Any,
                ) -> Any:
                    sender, receiver, content = self._extract_message_direction(
                        agent,
                        _method_name,
                        args,
                        kwargs,
                        context.agent_id,
                    )
                    context.runtime.record_inter_agent_message(
                        sender_agent_id=sender,
                        receiver_agent_id=receiver,
                        content=content,
                    )
                    try:
                        return await _original(*args, **kwargs)
                    except PolicyViolationError:
                        raise
                    except Exception as error:
                        logger.error(f"Adapter interception failed: {error}")
                        raise

                setattr(agent, method_name, async_wrapper)
            else:

                def sync_wrapper(
                    *args: Any,
                    _original: Any = original,
                    _method_name: str = method_name,
                    **kwargs: Any,
                ) -> Any:
                    sender, receiver, content = self._extract_message_direction(
                        agent,
                        _method_name,
                        args,
                        kwargs,
                        context.agent_id,
                    )
                    context.runtime.record_inter_agent_message(
                        sender_agent_id=sender,
                        receiver_agent_id=receiver,
                        content=content,
                    )
                    try:
                        return _original(*args, **kwargs)
                    except PolicyViolationError:
                        raise
                    except Exception as error:
                        logger.error(f"Adapter interception failed: {error}")
                        raise

                setattr(agent, method_name, sync_wrapper)

    def _patch_tool_functions(self, agent: Any, context: AdapterContext) -> None:
        """Patch function_map callables for tool interception.

        Args:
            agent: AutoGen agent.
            context: Runtime context.
        """
        function_map = getattr(agent, "function_map", None)
        if not isinstance(function_map, dict):
            return

        for name, fn in list(function_map.items()):
            if not callable(fn):
                continue

            if asyncio.iscoroutinefunction(fn):

                async def async_wrapper(
                    *args: Any, _fn: Any = fn, _name: str = name, **kwargs: Any
                ) -> Any:
                    payload = self._extract_prompt(args, kwargs)
                    context.runtime.on_tool_start(_name, payload)
                    try:
                        result = await _fn(*args, **kwargs)
                    except PolicyViolationError:
                        raise
                    except Exception as error:
                        logger.error(f"Adapter interception failed: {error}")
                        raise
                    context.runtime.on_tool_end(_name, self._extract_response(result))
                    return result

                function_map[name] = async_wrapper
            else:

                def sync_wrapper(
                    *args: Any, _fn: Any = fn, _name: str = name, **kwargs: Any
                ) -> Any:
                    payload = self._extract_prompt(args, kwargs)
                    context.runtime.on_tool_start(_name, payload)
                    try:
                        result = _fn(*args, **kwargs)
                    except PolicyViolationError:
                        raise
                    except Exception as error:
                        logger.error(f"Adapter interception failed: {error}")
                        raise
                    context.runtime.on_tool_end(_name, self._extract_response(result))
                    return result

                function_map[name] = sync_wrapper

    def _patch_memory(self, agent: Any, context: AdapterContext) -> None:
        """Patch memory object methods if present.

        Args:
            agent: AutoGen agent.
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

        for method_name in ("set", "write", "append", "save"):
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

    def _extract_prompt(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
        """Extract prompt-like content from call args.

        Args:
            args: Positional args.
            kwargs: Keyword args.

        Returns:
            Prompt text.
        """
        for key in ("message", "prompt", "input"):
            value = kwargs.get(key)
            if value is not None:
                return str(value)

        messages = kwargs.get("messages")
        if messages is not None:
            return str(messages)

        if args:
            return str(args[0])
        return ""

    def _extract_response(self, result: Any) -> str:
        """Extract response-like text.

        Args:
            result: Result object.

        Returns:
            Response text.
        """
        if isinstance(result, dict):
            for key in ("content", "text", "response", "output"):
                if key in result:
                    return str(result[key])
        return str(result)

    def _extract_message_direction(
        self,
        agent: Any,
        method_name: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        default_agent_id: str,
    ) -> tuple[str, str, str]:
        """Resolve sender/receiver/content from send/receive call arguments.

        Args:
            agent: AutoGen agent object.
            method_name: Patched method name.
            args: Positional arguments.
            kwargs: Keyword arguments.
            default_agent_id: Runtime agent id fallback.

        Returns:
            Sender id, receiver id, and content.
        """
        agent_name = str(getattr(agent, "name", default_agent_id))
        message_obj = kwargs.get("message", args[0] if args else "")
        peer_obj = args[1] if len(args) > 1 else kwargs.get("recipient") or kwargs.get("sender")
        peer_name = str(getattr(peer_obj, "name", peer_obj)) if peer_obj is not None else "unknown"

        if method_name == "send":
            return agent_name, peer_name, self._extract_response(message_obj)
        return peer_name, agent_name, self._extract_response(message_obj)

    @classmethod
    def get_framework_version(cls) -> str | None:
        """Return installed AutoGen package version.

        Returns:
            Installed version string or None.
        """
        for package in ("pyautogen", "autogen"):
            try:
                return version(package)
            except PackageNotFoundError:
                continue
        return None
