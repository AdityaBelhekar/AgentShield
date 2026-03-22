"""AgentShield detection engine.

Analyzes intercepted events in real time and identifies
security threats across 5 attack vectors.

Public API:
    DetectionEngine        : main orchestrator
    DetectionContext       : session state for detectors
    BaseDetector           : abstract detector base
    EmbeddingService       : shared sentence-transformer
    PromptInjectionDetector: injection attack detection
    GoalDriftDetector      : semantic drift detection
    ToolChainDetector      : tool sequence escalation
    MemoryPoisonDetector   : memory poisoning detection
    CorrelationResult      : cross-detector result
"""

from agentshield.detection.base_detector import (
    BaseDetector,
    DetectionContext,
)
from agentshield.detection.embedding_service import EmbeddingService
from agentshield.detection.engine import CorrelationResult, DetectionEngine
from agentshield.detection.goal_drift import GoalDriftDetector
from agentshield.detection.memory_poison import MemoryPoisonDetector
from agentshield.detection.prompt_injection import (
    PromptInjectionDetector,
)
from agentshield.detection.tool_chain import ToolChainDetector

__all__ = [
    "BaseDetector",
    "CorrelationResult",
    "DetectionContext",
    "DetectionEngine",
    "EmbeddingService",
    "GoalDriftDetector",
    "MemoryPoisonDetector",
    "PromptInjectionDetector",
    "ToolChainDetector",
]
