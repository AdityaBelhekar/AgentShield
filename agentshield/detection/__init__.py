"""AgentShield detection engine.

Analyzes intercepted events in real time and identifies
security threats across 5 attack vectors.

Public API (grows each phase):
  Phase 3A: DetectionContext, BaseDetector, EmbeddingService
  Phase 3B: PromptInjectionDetector
  Phase 3C: GoalDriftDetector
  Phase 3D: ToolChainDetector
  Phase 3E: MemoryPoisonDetector
  Phase 3F: DetectionEngine (wires everything together)
"""

from agentshield.detection.base_detector import BaseDetector, DetectionContext
from agentshield.detection.embedding_service import EmbeddingService

__all__ = [
    "BaseDetector",
    "DetectionContext",
    "EmbeddingService",
]
