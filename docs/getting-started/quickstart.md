# Quickstart

## Step 1: Wrap Your Agent with `shield()`

Use the same agent object you already run in production. `shield()` attaches runtime interception, detection, and policy evaluation.

## Step 2: Start with `monitor_only`

For first rollout, run in monitor mode to baseline behavior and evaluate noise before hard blocking.

## Step 3: Run and Observe Events

Execute normal workloads and inspect emitted events and threat telemetry.

## Step 4: Switch to `no_exfiltration`

After validation, switch policy to enforce exfiltration controls in blocking mode.

## Full LangChain Example

```python
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI

from agentshield import shield
from agentshield.exceptions import PolicyViolationError


@tool
def lookup_customer_account(email: str) -> str:
    """Lookup account details from internal CRM."""
    return f"Account status for {email}: active, renewal in 21 days"


@tool
def send_email(recipient: str, body: str) -> str:
    """Send outbound message through approved channel."""
    return f"Email queued for {recipient}"


tools = [lookup_customer_account, send_email]

prompt = ChatPromptTemplate.from_messages(
    [
        ("system", "You are a customer-success agent. Resolve account requests only."),
        ("human", "{input}"),
        ("placeholder", "{agent_scratchpad}"),
    ]
)

llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
agent = create_tool_calling_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

protected = shield(
    executor,
    policy="monitor_only",
    agent_id="customer-success-bot",
    original_task="Resolve customer account questions safely.",
)

try:
    with protected:
        output = protected.run(
            "Customer asks: confirm account status for alice@contoso.com and summarize next steps."
        )
        print(output)
except PolicyViolationError as exc:
    print("Blocked by AgentShield:", exc)
```

When you are ready to enforce stronger controls:

```python
protected = shield(executor, policy="no_exfiltration")
```

## Handling `PolicyViolationError`

`PolicyViolationError` is the base exception for blocking outcomes. Catch it once to handle all security-block cases, or catch subclasses (for example, `PromptInjectionError`, `GoalDriftError`) if your app needs threat-specific recovery behavior.