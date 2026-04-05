# LlamaIndex Integration

## Minimal Working Example

```python
from llama_index.core import VectorStoreIndex
from llama_index.core.schema import Document

from agentshield import shield

docs = [Document(text="AgentShield protects agent runtime execution paths.")]
agent = VectorStoreIndex.from_documents(docs).as_query_engine()

protected = shield(
    agent,
    policy="monitor_only",
    agent_id="llamaindex-agent",
    framework="llamaindex",
)

# For LlamaIndex-style runtimes, run native query/chat calls inside the shielded session.
with protected:
    result = agent.query("What does AgentShield protect?")
    print(result)
```

## Adapter-Specific Notes

- Adapter support check expects `callback_manager` plus `query` or `chat`.
- AgentShield callback handler is injected to translate LlamaIndex callbacks into AgentShield events.
- Optional tool hooks are wired when the agent exposes a list-style `tools` surface.

## Adapter Source

- [agentshield/adapters/llamaindex_adapter.py](https://github.com/AdityaBelhekar/AgentShield/blob/main/agentshield/adapters/llamaindex_adapter.py)