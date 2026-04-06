from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import numpy as np
from loguru import logger

from agentshield.config import AgentShieldConfig
from agentshield.detection.embedding_service import EmbeddingService
from agentshield.events.models import (
    BaseEvent,
    EventType,
    RecommendedAction,
    SeverityLevel,
    ThreatEvent,
    ThreatType,
    ToolCallEvent,
)


@dataclass
class DetectionContext:
    """Holds all session state needed by detectors.

    One context exists per active agent session and is maintained
    by the detection engine. Detectors read from this state but
    should not mutate it directly.

    Attributes:
        session_id: UUID of the session this context belongs to.
        agent_id: Human-readable agent identifier.
        original_task: Original user task text for this session.
        original_task_embedding: Embedding of the original task.
        tool_call_history: Ordered tool call events in this session.
        memory_embeddings: Embeddings of memory writes in-session.
        memory_distances: Distances for anomaly baselining.
        all_events: All observed events in chronological order.
        threat_count: Number of detected threats in this session.
        blocked_count: Number of blocked threats in this session.
    """

    session_id: uuid.UUID
    agent_id: str
    original_task: str
    original_task_embedding: np.ndarray | None = None
    tool_call_history: list[ToolCallEvent] = field(default_factory=list)
    memory_embeddings: list[np.ndarray] = field(default_factory=list)
    memory_distances: list[float] = field(default_factory=list)
    all_events: list[BaseEvent] = field(default_factory=list)
    recent_threats: list[ThreatEvent] = field(default_factory=list)
    threat_count: int = 0
    blocked_count: int = 0


class BaseDetector(ABC):
    """Abstract base class for all AgentShield threat detectors.

    Concrete detectors analyze relevant events and return a
    ThreatEvent when a threat is detected, else None.

    Attributes:
        _config: AgentShieldConfig with detector thresholds.
        _embedding_service: Shared embedding computation service.
    """

    def __init__(
        self,
        config: AgentShieldConfig,
        embedding_service: EmbeddingService,
    ) -> None:
        """Initialize the base detector.

        Args:
            config: AgentShieldConfig with threshold settings.
            embedding_service: Shared EmbeddingService instance.
        """
        self._config: AgentShieldConfig = config
        self._embedding_service: EmbeddingService = embedding_service
        logger.debug("{} initialized", self.__class__.__name__)

    @abstractmethod
    def analyze(
        self,
        event: BaseEvent,
        context: DetectionContext,
    ) -> ThreatEvent | None:
        """Analyze one event and return a threat if detected.

        Args:
            event: Event to analyze.
            context: Session-level detection context.

        Returns:
            ThreatEvent when detection confidence exceeds threshold,
            otherwise None.
        """

    @property
    @abstractmethod
    def detector_name(self) -> str:
        """Return the human-readable detector name.

        Returns:
            Detector name used in logs and emitted threat events.
        """

    @property
    @abstractmethod
    def supported_event_types(self) -> list[EventType]:
        """Return event types this detector handles.

        Returns:
            List of EventType values consumed by this detector.
        """

    def _build_threat(
        self,
        source_event: BaseEvent,
        threat_type: ThreatType,
        confidence: float,
        explanation: str,
        evidence: dict[str, Any],
        action: RecommendedAction,
        severity: SeverityLevel,
    ) -> ThreatEvent:
        """Build a ThreatEvent from detector output.

        Args:
            source_event: Original event that triggered detection.
            threat_type: Attack vector classification.
            confidence: Detection confidence from 0.0 to 1.0.
            explanation: Human-readable threat explanation.
            evidence: Forensic evidence payload.
            action: Recommended mitigation action.
            severity: Threat severity level.

        Returns:
            Fully constructed ThreatEvent.
        """
        return ThreatEvent(
            session_id=source_event.session_id,
            agent_id=source_event.agent_id,
            event_type=EventType.THREAT_DETECTED,
            severity=severity,
            threat_type=threat_type,
            confidence=round(confidence, 4),
            affected_event_id=source_event.id,
            explanation=explanation,
            recommended_action=action,
            evidence=evidence,
            detector_name=self.detector_name,
        )

    def _cosine_similarity(self, a: np.ndarray, b: np.ndarray) -> float:
        """Compute cosine similarity between two vectors.

        Args:
            a: First embedding vector.
            b: Second embedding vector.

        Returns:
            Similarity score in [-1.0, 1.0]. Returns 0.0 for zero vectors.
        """
        norm_a = np.linalg.norm(a)
        norm_b = np.linalg.norm(b)
        if norm_a == 0.0 or norm_b == 0.0:
            logger.debug("Zero vector in cosine similarity; returning 0.0")
            return 0.0
        similarity = float(np.dot(a, b) / (norm_a * norm_b))
        return float(np.clip(similarity, -1.0, 1.0))

    def _cosine_distance(self, a: np.ndarray, b: np.ndarray) -> float:
        """Compute cosine distance between two vectors.

        Args:
            a: First embedding vector.
            b: Second embedding vector.

        Returns:
            Distance score computed as 1.0 - cosine_similarity.
        """
        distance = 1.0 - self._cosine_similarity(a, b)
        return float(np.clip(distance, 0.0, 1.0))

    def _embed(self, text: str) -> np.ndarray | None:
        """Compute embedding using the shared EmbeddingService.

        Args:
            text: Text to embed.

        Returns:
            Embedding vector or None when unavailable.
        """
        return self._embedding_service.embed(text)

    def _compute_zscore(self, value: float, values: list[float]) -> float:
        """Compute z-score of a value relative to historical values.

        Args:
            value: Value to score.
            values: Historical baseline values.

        Returns:
            Z-score. Returns 0.0 when insufficient variance exists.
        """
        if len(values) < 2:
            return 0.0
        arr = np.asarray(values, dtype=np.float64)
        mean = float(np.mean(arr))
        std = float(np.std(arr))
        if std == 0.0:
            return 0.0
        return float((value - mean) / std)

    def _confidence_to_severity(self, confidence: float) -> SeverityLevel:
        """Map confidence score to a severity level.

        Args:
            confidence: Detection confidence from 0.0 to 1.0.

        Returns:
            SeverityLevel value derived from confidence bands.
        """
        if confidence >= 0.80:
            return SeverityLevel.CRITICAL
        if confidence >= 0.60:
            return SeverityLevel.HIGH
        if confidence >= 0.40:
            return SeverityLevel.MEDIUM
        if confidence >= 0.20:
            return SeverityLevel.LOW
        return SeverityLevel.INFO

    def _confidence_to_action(
        self,
        confidence: float,
        block_threshold: float,
        alert_threshold: float,
        flag_threshold: float,
    ) -> RecommendedAction:
        """Map confidence score to a recommended action.

        Args:
            confidence: Detection confidence from 0.0 to 1.0.
            block_threshold: Confidence at or above this blocks.
            alert_threshold: Confidence at or above this alerts.
            flag_threshold: Confidence at or above this flags.

        Returns:
            RecommendedAction selected from thresholds.
        """
        if confidence >= block_threshold:
            return RecommendedAction.BLOCK
        if confidence >= alert_threshold:
            return RecommendedAction.ALERT
        if confidence >= flag_threshold:
            return RecommendedAction.FLAG
        return RecommendedAction.LOG_ONLY
