"""AgentShield policy system.

Lets developers define exactly how AgentShield behaves for their specific
agent - what is allowed, what is denied,
what triggers alerts vs blocks.

Public API:
  PolicyCompiler: loads and compiles policies
  CompiledPolicy: executable compiled policy
  PolicyEvaluator: evaluates events against policy
  PolicyDecision: result of policy evaluation
  PolicyConfig: policy configuration model
  PolicyRule: single security rule
  PolicyCondition: rule trigger condition
  PolicyAction: action enum (BLOCK/ALERT/FLAG/LOG/ALLOW)
  PolicyConditionType: condition type enum
  BUILTIN_POLICIES: pre-built policy configurations
"""

from agentshield.policy.compiler import CompiledPolicy, PolicyCompiler
from agentshield.policy.evaluator import PolicyDecision, PolicyEvaluator
from agentshield.policy.models import (
    BUILTIN_POLICIES,
    PolicyAction,
    PolicyCondition,
    PolicyConditionType,
    PolicyConfig,
    PolicyRule,
)

__all__ = [
    "BUILTIN_POLICIES",
    "CompiledPolicy",
    "PolicyAction",
    "PolicyCompiler",
    "PolicyCondition",
    "PolicyConditionType",
    "PolicyConfig",
    "PolicyDecision",
    "PolicyEvaluator",
    "PolicyRule",
]
