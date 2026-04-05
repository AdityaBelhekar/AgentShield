# LangChain Integration

## Minimal Working Example

```python
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI

from agentshield import shield


@tool
def lookup_invoice(invoice_id: str) -> str:
    return f"Invoice {invoice_id}: paid"


tools = [lookup_invoice]
llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
prompt = ChatPromptTemplate.from_messages(
    [
        ("system", "You are a billing operations assistant."),
        ("human", "{input}"),
        ("placeholder", "{agent_scratchpad}"),
    ]
)

agent = create_tool_calling_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

protected = shield(
    executor,
    policy="monitor_only",
    agent_id="billing-agent",
    original_task="Resolve invoice queries safely.",
)

with protected:
    print(protected.run("Check status for invoice INV-4931"))
```

## Adapter-Specific Notes

- Adapter auto-detection checks for LangChain-like callback surface plus agent executor shape.
- Tool hooks are attached pre/post call so dangerous chains can be blocked before execution.
- Memory interception is enabled when the agent exposes a compatible `memory` object.

## Adapter Source

- [agentshield/adapters/langchain_adapter.py](https://github.com/AdityaBelhekar/AgentShield/blob/main/agentshield/adapters/langchain_adapter.py)