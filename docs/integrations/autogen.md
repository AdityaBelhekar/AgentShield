# AutoGen Integration

## Minimal Working Example

```python
import autogen

from agentshield import shield

assistant = autogen.AssistantAgent(
    name="assistant",
    llm_config={"model": "gpt-4o-mini", "temperature": 0},
)
user_proxy = autogen.UserProxyAgent(name="user")

protected = shield(
    assistant,
    policy="monitor_only",
    agent_id="autogen-assistant",
    framework="autogen",
)

with protected:
    assistant.initiate_chat(user_proxy, message="Summarize this sprint report")
```

## Adapter-Specific Notes

- Adapter support check expects `send`, `receive`, `initiate_chat`, and `name`.
- Inter-agent message hooks feed the trust graph for injection analysis across agent boundaries.
- Inbound messages are emitted as prompt events for prompt-injection detector coverage.

## Adapter Source

- [agentshield/adapters/autogen_adapter.py](https://github.com/AdityaBelhekar/AgentShield/blob/main/agentshield/adapters/autogen_adapter.py)