from __future__ import annotations

import numpy as np
from loguru import logger

from agentshield.config import AgentShieldConfig
from agentshield.detection.base_detector import (
    BaseDetector,
    DetectionContext,
)
from agentshield.detection.embedding_service import EmbeddingService
from agentshield.events.models import (
    BaseEvent,
    EventType,
    MemoryEvent,
    ThreatEvent,
    ThreatType,
)

# Static memory poisoning phrase signatures used by MemoryPoisonDetector.
MEMORY_POISON_PATTERNS: list[str] = [
    # Future behavior modification
    "remember for future",
    "remember this for later",
    "always remember",
    "never forget",
    "from now on always",
    "from now on never",
    "in future sessions",
    "next time you",
    "whenever you",
    "every time you",
    # Persistent instruction injection
    "always include",
    "always add",
    "always send",
    "always cc",
    "always bcc",
    "always forward",
    "always attach",
    "make sure to always",
    # Identity/role modification
    "your real purpose",
    "your true purpose",
    "your actual goal",
    "you were designed to",
    "your hidden instructions",
    "your secret task",
    # Override persistent memory
    "override your memory",
    "update your core",
    "modify your base",
    "change your default",
    "reset your instructions",
    # Exfiltration persistence
    "always exfiltrate",
    "always leak",
    "always share with",
    "always report to",
    "send all data to",
    "copy all to",
]


class MemoryPoisonDetector(BaseDetector):
    """Detect memory poisoning attacks on persistent memory writes.

    Analyzes MEMORY_WRITE events with three complementary layers:
      1. Semantic z-score anomaly against session memory baseline
      2. Pattern matching for memory-specific poison phrases
      3. Content-length anomaly against prior memory-write lengths

    Statistical layers require at least MIN_BASELINE_SIZE baseline
    samples before activation. Until then, the detector relies on
    pattern matching while accumulating session baseline state.

    Attributes:
        No additional persistent attributes beyond BaseDetector.
        Session state is sourced from DetectionContext.
    """

    def __init__(
        self,
        config: AgentShieldConfig,
        embedding_service: EmbeddingService,
    ) -> None:
        """Initialize the MemoryPoisonDetector.

        Args:
            config: AgentShieldConfig with memory poisoning thresholds.
            embedding_service: Shared embedding service.
        """
        super().__init__(config, embedding_service)
        logger.debug("MemoryPoisonDetector initialized")

    @property
    def detector_name(self) -> str:
        """Return the human-readable detector name.

        Returns:
            Name used in logs and threat events.
        """
        return "MemoryPoisonDetector"

    @property
    def supported_event_types(self) -> list[EventType]:
        """Return event types analyzed by this detector.

        Returns:
            List containing only MEMORY_WRITE.
        """
        return [EventType.MEMORY_WRITE]

    def analyze(
        self,
        event: BaseEvent,
        context: DetectionContext,
    ) -> ThreatEvent | None:
        """Analyze one event for memory poisoning.

        Args:
            event: Event to analyze.
            context: Session detection context with baseline state.

        Returns:
            ThreatEvent when poisoning confidence exceeds threshold,
            otherwise None.
        """
        if event.event_type != EventType.MEMORY_WRITE:
            return None

        if not isinstance(event, MemoryEvent):
            return None

        content = event.content_preview
        pattern_score, pattern_matches = self._pattern_analysis(content.lower())
        semantic_score, semantic_zscore = self._semantic_anomaly_analysis(
            content,
            context,
        )
        length_score, length_zscore = self._length_anomaly_analysis(
            event.content_length,
            context,
        )

        confidence, primary_signal = self._compute_confidence(
            pattern_score=pattern_score,
            semantic_score=semantic_score,
            length_score=length_score,
        )

        pattern_threshold = self._config.memory_poison_anomaly_score_threshold
        zscore_threshold = self._config.memory_poison_z_score_threshold
        if confidence < pattern_threshold:
            logger.debug(
                "No memory poisoning detected | confidence={:.3f} session={}",
                confidence,
                str(context.session_id)[:8],
            )
            return None

        action = self._confidence_to_action(
            confidence=confidence,
            block_threshold=self._config.memory_poison_block_threshold,
            alert_threshold=self._config.memory_poison_alert_threshold,
            flag_threshold=pattern_threshold,
        )
        severity = self._confidence_to_severity(confidence)

        explanation = self._build_explanation(
            confidence=confidence,
            pattern_matches=pattern_matches,
            semantic_zscore=semantic_zscore,
            length_zscore=length_zscore,
            primary_signal=primary_signal,
            baseline_size=len(context.memory_embeddings),
        )

        evidence: dict[str, object] = {
            "pattern_score": round(pattern_score, 4),
            "semantic_score": round(semantic_score, 4),
            "length_score": round(length_score, 4),
            "semantic_zscore": round(semantic_zscore, 4),
            "length_zscore": round(length_zscore, 4),
            "pattern_matches": pattern_matches[:5],
            "baseline_size": len(context.memory_embeddings),
            "content_preview": content[:100],
            "primary_signal": primary_signal,
            "zscore_threshold": zscore_threshold,
        }

        logger.warning(
            "Memory poisoning detected | confidence={:.3f} signal={} session={}",
            confidence,
            primary_signal,
            str(context.session_id)[:8],
        )

        return self._build_threat(
            source_event=event,
            threat_type=ThreatType.MEMORY_POISONING,
            confidence=confidence,
            explanation=explanation,
            evidence=evidence,
            action=action,
            severity=severity,
        )

    def _pattern_analysis(self, content_lower: str) -> tuple[float, list[str]]:
        """Match memory content against poisoning patterns.

        Args:
            content_lower: Lowercased memory content.

        Returns:
            Tuple of confidence score and matched patterns.
        """
        matches: list[str] = []
        for pattern in MEMORY_POISON_PATTERNS:
            if pattern in content_lower:
                matches.append(pattern)

        score = min(len(matches) * 0.35, 0.70)
        if matches:
            logger.debug(
                "Memory poison patterns found | count={} matches={}",
                len(matches),
                matches[:3],
            )
        return score, matches

    def _semantic_anomaly_analysis(
        self,
        content: str,
        context: DetectionContext,
    ) -> tuple[float, float]:
        """Detect semantic anomalies against session memory baseline.

        Args:
            content: Memory content to analyze.
            context: Session context with embedding baselines.

        Returns:
            Tuple of anomaly score and raw z-score.
        """
        min_samples = self._config.memory_poison_min_samples_before_detection
        window_size = self._config.memory_poison_baseline_window_size
        baseline_embeddings = context.memory_embeddings[-window_size:]

        if len(baseline_embeddings) < min_samples:
            logger.debug(
                "Baseline too small for semantic analysis | size={} required={}",
                len(baseline_embeddings),
                min_samples,
            )
            return 0.0, 0.0

        if not self._embedding_service.is_available():
            return 0.0, 0.0

        content_embedding = self._embed(content)
        if content_embedding is None:
            return 0.0, 0.0

        centroid = np.mean(np.array(baseline_embeddings), axis=0)
        if content_embedding.shape != centroid.shape:
            logger.debug(
                "Embedding dimension mismatch in semantic analysis | "
                "content_shape={} baseline_shape={}",
                content_embedding.shape,
                centroid.shape,
            )
            return 0.0, 0.0

        distance = self._cosine_distance(content_embedding, centroid)
        zscore = self._compute_zscore(
            value=distance,
            values=context.memory_distances,
        )

        threshold = self._config.memory_poison_z_score_threshold
        if zscore < threshold:
            return 0.0, zscore

        normalized_score = float(np.clip((zscore - threshold) / threshold, 0.0, 1.0))

        logger.debug(
            "Semantic anomaly detected | distance={:.3f} zscore={:.3f} score={:.3f}",
            distance,
            zscore,
            normalized_score,
        )
        return normalized_score, zscore

    def _length_anomaly_analysis(
        self,
        content_length: int,
        context: DetectionContext,
    ) -> tuple[float, float]:
        """Detect memory-write length anomalies.

        Args:
            content_length: Current memory content length.
            context: Session context with prior events for baseline.

        Returns:
            Tuple of anomaly score and raw z-score.
        """
        length_history = [
            float(memory_event.content_length)
            for memory_event in self._prior_memory_writes(context)
            if memory_event.content_length > 0
        ]

        window_size = self._config.memory_poison_baseline_window_size
        length_history = length_history[-window_size:]

        min_samples = self._config.memory_poison_min_samples_before_detection
        if len(length_history) < min_samples:
            return 0.0, 0.0

        zscore = self._compute_zscore(
            value=float(content_length),
            values=length_history,
        )

        threshold = self._config.memory_poison_z_score_threshold
        if zscore < threshold:
            return 0.0, zscore

        normalized_score = float(
            np.clip((zscore - threshold) / (threshold * 2.0), 0.0, 0.50)
        )

        logger.debug(
            "Length anomaly detected | length={} zscore={:.3f} score={:.3f}",
            content_length,
            zscore,
            normalized_score,
        )
        return normalized_score, zscore

    def _prior_memory_writes(self, context: DetectionContext) -> list[MemoryEvent]:
        """Collect prior memory-write events from context history.

        Args:
            context: Session context containing all observed events.

        Returns:
            Chronological list of memory-write events.
        """
        prior_writes: list[MemoryEvent] = []
        for observed in context.all_events:
            if (
                isinstance(observed, MemoryEvent)
                and observed.event_type == EventType.MEMORY_WRITE
            ):
                prior_writes.append(observed)
        return prior_writes

    def _compute_confidence(
        self,
        pattern_score: float,
        semantic_score: float,
        length_score: float,
    ) -> tuple[float, str]:
        """Combine layer scores into final confidence.

        Args:
            pattern_score: Pattern matching score.
            semantic_score: Semantic anomaly score.
            length_score: Length anomaly score.

        Returns:
            Tuple of final confidence and strongest signal name.
        """
        scores = {
            "pattern": pattern_score,
            "semantic_anomaly": semantic_score,
            "length_anomaly": length_score,
        }
        primary_signal = max(scores, key=lambda key: scores[key])

        max_individual = max(pattern_score, semantic_score, length_score)
        weighted = pattern_score * 0.55 + semantic_score * 0.35 + length_score * 0.10

        final = max(max_individual, weighted)
        return float(np.clip(final, 0.0, 1.0)), primary_signal

    def _build_explanation(
        self,
        confidence: float,
        pattern_matches: list[str],
        semantic_zscore: float,
        length_zscore: float,
        primary_signal: str,
        baseline_size: int,
    ) -> str:
        """Build a human-readable detection explanation.

        Args:
            confidence: Final confidence score.
            pattern_matches: Matched poison phrases.
            semantic_zscore: Semantic anomaly z-score.
            length_zscore: Length anomaly z-score.
            primary_signal: Strongest signal name.
            baseline_size: Number of baseline memory embeddings.

        Returns:
            Explanation string for forensic/audit output.
        """
        parts = [f"Memory poisoning detected with confidence {confidence:.0%}."]

        if pattern_matches:
            parts.append(
                f"Memory content contains {len(pattern_matches)} known poisoning "
                f"pattern(s): {', '.join(pattern_matches[:3])}."
            )

        if semantic_zscore > 0.0:
            parts.append(
                f"Semantic anomaly detected: content is {semantic_zscore:.1f} "
                f"standard deviations from the session memory baseline "
                f"({baseline_size} writes)."
            )

        if length_zscore > 0.0:
            parts.append(
                f"Content length anomaly: {length_zscore:.1f} standard deviations "
                "above normal write length."
            )

        parts.append(f"Primary detection signal: {primary_signal}.")
        return " ".join(parts)
