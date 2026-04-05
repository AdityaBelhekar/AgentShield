# Raw OpenAI / Anthropic Integration

## Minimal Working Example

```python
from openai import OpenAI

from agentshield import shield

client = OpenAI()
protected = shield(
    client,
    policy="monitor_only",
    agent_id="raw-openai-client",
    framework="raw_api",
)

with protected:
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a secure assistant."},
            {"role": "user", "content": "Summarize the attached meeting notes."},
        ],
    )
    print(response.choices[0].message.content)
```

## Adapter-Specific Notes

- OpenAI detection shape: `client.chat.completions.create(...)`
- Anthropic detection shape: `client.messages.create(...)`
- Adapter monkey-patches provider completion methods to emit prompt/response events around each call.

## Adapter Source

- [agentshield/adapters/raw_api_adapter.py](https://github.com/AdityaBelhekar/AgentShield/blob/main/agentshield/adapters/raw_api_adapter.py)