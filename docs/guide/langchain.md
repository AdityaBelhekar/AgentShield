# LangChain / LangGraph

```bash
pip install "agentshield-x[langchain]"
```

`shield.langchain()` returns agent middleware that routes every tool call through the
engine, using LangChain's own `wrap_tool_call` / `awrap_tool_call` hook. Nothing is
monkey-patched.

```python
from langchain.agents import create_agent
from agentshield import Shield

shield = Shield.from_policy(
    {
        "extends": "strict",
        "tools": {
            "search": {"labels": ["untrusted"]},
            "send_email": {"labels": ["external"]},
        },
    }
)

agent = create_agent(model, tools, middleware=[shield.langchain()])

with shield.session(user="alice", task="triage"):
    agent.invoke({"messages": [{"role": "user", "content": "..."}]})
```

- `invoke`, `stream`, `ainvoke` and `astream` are all covered.
- A denied call raises `PolicyViolationError` before the tool runs; `ask` goes to your
  approval handler or raises `ApprovalRequired`.
- Results from `untrusted` tools come back to the model delimited.
- Declare every tool the agent can call. With `unlabelled_tools: deny`, an undeclared tool is
  blocked rather than silently allowed.
- Use either the middleware or `shield.tool(...)` for a tool, not both, or the call is
  checked and counted twice.

Tested against `langchain` 1.4 / `langchain-core` 1.7 with a real compiled graph.
