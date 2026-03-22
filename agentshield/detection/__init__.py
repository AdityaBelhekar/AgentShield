"""AgentShield detection engine.

Analyzes intercepted events in real time and identifies
security threats across 5 attack vectors.

Public API:
  Phase 3A: DetectionContext, BaseDetector, EmbeddingService
  Phase 3B: PromptInjectionDetector
  Phase 3C: GoalDriftDetector
  Phase 3D: ToolChainDetector
  Phase 3E: MemoryPoisonDetector
  Phase 3F: DetectionEngine
"""

from agentshield.detection.base_detector import (
    BaseDetector,
    DetectionContext,
)
from agentshield.detection.embedding_service import EmbeddingService
from agentshield.detection.goal_drift import GoalDriftDetector
from agentshield.detection.memory_poison import MemoryPoisonDetector
from agentshield.detection.prompt_injection import (
    PromptInjectionDetector,
)
from agentshield.detection.tool_chain import ToolChainDetector

__all__ = [
    "BaseDetector",
    "DetectionContext",
    "EmbeddingService",
    "GoalDriftDetector",
    "MemoryPoisonDetector",
    "PromptInjectionDetector",
    "ToolChainDetector",
]
