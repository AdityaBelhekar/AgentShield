# Exceptions

AgentShield raises a structured exception hierarchy so applications can catch all security/runtime failures broadly or threat-specific failures precisely.

## Exception Tree

```text
AgentShieldError
├── ConfigurationError
├── AdapterError
├── InterceptorError
├── DetectionError
├── EventEmissionError
├── RedisConnectionError
├── ProvenanceError
├── CanaryError
├── DNAError
├── AuditChainError
└── PolicyViolationError
    ├── ToolCallBlockedError
    │   └── PrivilegeEscalationError
    ├── GoalDriftError
    ├── PromptInjectionError
    ├── MemoryPoisonError
    ├── BehavioralAnomalyError
    └── InterAgentInjectionError
```

> The tree above includes the base plus 18 specialized exceptions.

::: agentshield.exceptions.AgentShieldError

::: agentshield.exceptions.ConfigurationError

::: agentshield.exceptions.AdapterError

::: agentshield.exceptions.InterceptorError

::: agentshield.exceptions.DetectionError

::: agentshield.exceptions.EventEmissionError

::: agentshield.exceptions.RedisConnectionError

::: agentshield.exceptions.ProvenanceError

::: agentshield.exceptions.CanaryError

::: agentshield.exceptions.DNAError

::: agentshield.exceptions.AuditChainError

::: agentshield.exceptions.PolicyViolationError

::: agentshield.exceptions.ToolCallBlockedError

::: agentshield.exceptions.PrivilegeEscalationError

::: agentshield.exceptions.GoalDriftError

::: agentshield.exceptions.PromptInjectionError

::: agentshield.exceptions.MemoryPoisonError

::: agentshield.exceptions.BehavioralAnomalyError

::: agentshield.exceptions.InterAgentInjectionError