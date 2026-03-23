"""AgentShield canary injection system.

Generates cryptographically unique honeypot tokens and
injects them into agent context. If the LLM echoes a
canary token back in its response, active prompt injection
manipulation is confirmed with near-zero false positives.

Public API:
  CanarySystem         : main canary management class
  CanaryToken          : single canary token dataclass
  CanarySessionState   : per-session canary state
  generate_canary_token: cryptographic token generator
  build_canary_instruction: context injection string builder
"""

from agentshield.canary.models import (
    CanarySessionState,
    CanaryToken,
    build_canary_instruction,
    generate_canary_token,
)
from agentshield.canary.system import CanarySystem

__all__ = [
    "CanarySessionState",
    "CanarySystem",
    "CanaryToken",
    "build_canary_instruction",
    "generate_canary_token",
]
