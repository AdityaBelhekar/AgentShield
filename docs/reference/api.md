# Python API

Everything below is importable from `agentshield` unless a module is named.

## Shield

::: agentshield.Shield
    options:
      members:
        - __init__
        - from_policy
        - session
        - tool
        - langchain
        - system_prompt
        - check_output
        - close

## Types

::: agentshield.ToolCall

::: agentshield.Decision

::: agentshield.Verdict

::: agentshield.Label

::: agentshield.Session

::: agentshield.current_session

## Policy

::: agentshield.policy.load_policy

::: agentshield.policy.Policy

## Approvals

::: agentshield.terminal_approval

## Audit

::: agentshield.AuditLog

::: agentshield.audit.verify_audit

::: agentshield.audit.generate_key

::: agentshield.audit.load_key

## Detectors

::: agentshield.detectors.Detector

::: agentshield.detectors.ChunkedClassifier

::: agentshield.classifier.prompt_injection_detector

## Exceptions

::: agentshield.AgentShieldError

::: agentshield.PolicyError

::: agentshield.PolicyViolationError

::: agentshield.ApprovalRequired

::: agentshield.CanaryLeakError

::: agentshield.AuditError
