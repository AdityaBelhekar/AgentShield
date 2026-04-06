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
    LLMEvent,
    RecommendedAction,
    SeverityLevel,
    ThreatEvent,
    ThreatType,
)


class GoalDriftDetector(BaseDetector):
    """Detect semantic drift between prompts and the original task.

    Measures how far the current LLM prompt has drifted from
    the original task the user gave the agent. Uses cosine
    distance between sentence embeddings as the drift metric.

    Only analyzes LLM_PROMPT events. Requires original_task
    and original_task_embedding in DetectionContext, typically
    initialized at session start.

    Drift scoring:
      drift_score = cosine_distance(current_prompt, original_task)
      0.0 = identical meaning (no drift)
      1.0 = completely unrelated meaning (maximum drift)

    Smoothing:
    Uses rolling average of last rolling_window_size prompt
      distances to avoid triggering on a single outlier prompt.
      Raw drift score and rolling average are both considered;
      whichever is higher drives the final decision.

    Early session protection:
    Does not BLOCK on fewer than min_prompts_before_block
      prompts. The first prompt often contains setup context
      that looks unrelated but is not an attack.

    Attributes:
        _prompt_distances: History of drift scores per session.
            Keyed by session_id string for multi-session support.
        _prompt_counts: Number of prompts analyzed per session.
    """

    def __init__(
        self,
        config: AgentShieldConfig,
        embedding_service: EmbeddingService,
    ) -> None:
        """Initialize the GoalDriftDetector.

        Args:
            config: AgentShieldConfig with drift thresholds.
            embedding_service: Shared embedding service.
        """
        super().__init__(config, embedding_service)
        self._prompt_distances: dict[str, list[float]] = {}
        self._prompt_counts: dict[str, int] = {}
        self._session_peak_scores: dict[str, float] = {}

        logger.debug("GoalDriftDetector initialized")

    @property
    def detector_name(self) -> str:
        """Return the human-readable detector name.

        Returns:
            Name used in logs and threat events.
        """
        return "GoalDriftDetector"

    @property
    def supported_event_types(self) -> list[EventType]:
        """Return event types this detector analyzes.

        Returns:
            List containing only EventType.LLM_PROMPT.
        """
        return [EventType.LLM_PROMPT]

    def analyze(
        self,
        event: BaseEvent,
        context: DetectionContext,
    ) -> ThreatEvent | None:
        """Analyze an LLM prompt event for goal drift.

        Returns None immediately if:
          - Event is not LLM_PROMPT type
          - No original task embedding is available
          - Embedding service is unavailable
          - Drift score is below threshold

        Args:
            event: The event to analyze.
            context: Current session detection context.

        Returns:
            ThreatEvent if drift detected above threshold,
            otherwise None.
        """
        if event.event_type != EventType.LLM_PROMPT:
            return None

        if not isinstance(event, LLMEvent):
            return None

        if context.original_task_embedding is None:
            logger.debug("No original task embedding; skipping goal drift analysis")
            return None

        if not self._embedding_service.is_available():
            logger.debug("Embedding service unavailable; skipping goal drift analysis")
            return None

        return self._analyze_drift(event, context)

    def _analyze_drift(
        self,
        event: LLMEvent,
        context: DetectionContext,
    ) -> ThreatEvent | None:
        """Run core goal drift analysis.

        Computes drift score, updates rolling history,
        determines threshold action, and builds threat output.

        Args:
            event: The LLM_PROMPT event to analyze.
            context: Current session detection context.

        Returns:
            ThreatEvent if drift detected, else None.
        """
        original_embedding = context.original_task_embedding
        if original_embedding is None:
            return None

        session_key = str(context.session_id)

        prompt_embedding = self._embed(event.prompt)
        if prompt_embedding is None:
            logger.debug("Could not embed prompt; skipping drift analysis")
            return None

        drift_score = self._cosine_distance(prompt_embedding, original_embedding)
        self._update_history(session_key, drift_score)

        prompt_count = self._prompt_counts.get(session_key, 0)
        rolling_avg = self._rolling_average(session_key)

        # Preserve the highest recent drift signal to prevent rapid
        # oscillation when prompts alternate between benign and malicious.
        peak_so_far = self._session_peak_scores.get(session_key, 0.0)
        effective_score = max(drift_score, rolling_avg, peak_so_far)
        self._session_peak_scores[session_key] = effective_score

        # Early prompts are often setup/context handshakes; suppress
        # medium drift until a stronger signal emerges.
        if prompt_count < self._config.min_prompts_before_block:
            warmup_threshold = min(self._config.goal_drift_block_threshold + 0.15, 0.95)
            if effective_score < warmup_threshold:
                return None

        logger.debug(
            "Goal drift score | session={} drift={:.3f} rolling_avg={:.3f} prompt_count={}",
            session_key[:8],
            drift_score,
            rolling_avg,
            prompt_count,
        )

        flag_threshold = self._config.goal_drift_threshold
        block_threshold = self._config.goal_drift_block_threshold

        if effective_score < flag_threshold:
            return None

        action, severity = self._determine_action_severity(
            effective_score=effective_score,
            flag_threshold=flag_threshold,
            block_threshold=block_threshold,
            prompt_count=prompt_count,
        )

        explanation = self._build_explanation(
            drift_score=drift_score,
            rolling_avg=rolling_avg,
            effective_score=effective_score,
            action=action,
            prompt_count=prompt_count,
        )

        distance_history = [
            round(distance, 4)
            for distance in self._prompt_distances.get(session_key, [])
        ]
        evidence: dict[str, object] = {
            "drift_score": round(drift_score, 4),
            "rolling_average": round(rolling_avg, 4),
            "effective_score": round(effective_score, 4),
            "prompt_count": prompt_count,
            "original_task": context.original_task[:100],
            "prompt_preview": event.prompt[:200],
            "flag_threshold": flag_threshold,
            "block_threshold": block_threshold,
            "distance_history": distance_history,
        }

        logger.warning(
            "Goal drift detected | session={} drift={:.3f} action={} prompts={}",
            session_key[:8],
            effective_score,
            action,
            prompt_count,
        )

        return self._build_threat(
            source_event=event,
            threat_type=ThreatType.GOAL_DRIFT,
            confidence=float(np.clip(effective_score, 0.0, 1.0)),
            explanation=explanation,
            evidence=evidence,
            action=action,
            severity=severity,
        )

    def _determine_action_severity(
        self,
        effective_score: float,
        flag_threshold: float,
        block_threshold: float,
        prompt_count: int,
    ) -> tuple[RecommendedAction, SeverityLevel]:
        """Determine action and severity from drift score.

        Applies early session protection by withholding BLOCK
        until min_prompts_before_block prompts are observed.

        Args:
            effective_score: Max of raw drift and rolling average.
            flag_threshold: Threshold above which to flag.
            block_threshold: Threshold above which to block.
            prompt_count: Number of prompts observed this session.

        Returns:
            Tuple of recommended action and severity.
        """
        if effective_score >= block_threshold:
            if prompt_count >= self._config.min_prompts_before_block:
                return RecommendedAction.BLOCK, SeverityLevel.HIGH
            return RecommendedAction.ALERT, SeverityLevel.HIGH

        if effective_score >= flag_threshold:
            return RecommendedAction.FLAG, SeverityLevel.MEDIUM

        return RecommendedAction.LOG_ONLY, SeverityLevel.INFO

    def _update_history(
        self,
        session_key: str,
        drift_score: float,
    ) -> None:
        """Store drift score and increment prompt count.

        Args:
            session_key: Session identifier string.
            drift_score: Computed prompt drift score.
        """
        if session_key not in self._prompt_distances:
            self._prompt_distances[session_key] = []
            self._prompt_counts[session_key] = 0

        self._prompt_distances[session_key].append(drift_score)
        self._prompt_counts[session_key] += 1

    def _rolling_average(self, session_key: str) -> float:
        """Compute rolling average drift score for a session.

        Args:
            session_key: Session identifier string.

        Returns:
            Mean of the last rolling_window_size scores,
            or 0.0 when no history exists.
        """
        history = self._prompt_distances.get(session_key, [])
        if not history:
            return 0.0

        window_size = min(self._config.rolling_window_size, len(history))
        window = history[-window_size:]
        rolling_average = float(np.mean(window))

        recent_size = min(self._config.min_prompts_before_block, len(history))
        recent_window = history[-recent_size:]
        recent_average = float(np.mean(recent_window))

        return max(rolling_average, recent_average)

    def _build_explanation(
        self,
        drift_score: float,
        rolling_avg: float,
        effective_score: float,
        action: RecommendedAction,
        prompt_count: int,
    ) -> str:
        """Build a human-readable drift explanation message.

        Args:
            drift_score: Raw cosine distance for this prompt.
            rolling_avg: Rolling average over recent prompts.
            effective_score: Max of drift_score and rolling average.
            action: Selected response action.
            prompt_count: Number of prompts observed this session.

        Returns:
            Human-readable explanation text.
        """
        action_desc = {
            RecommendedAction.BLOCK: "blocked",
            RecommendedAction.ALERT: "flagged for review",
            RecommendedAction.FLAG: "flagged",
            RecommendedAction.LOG_ONLY: "logged",
        }.get(action, "detected")

        parts: list[str] = [
            "Goal drift "
            f"{action_desc} with drift score {effective_score:.0%} "
            "from original task."
        ]

        if rolling_avg > drift_score * 0.8:
            parts.append(
                "Sustained drift detected with rolling average "
                f"{rolling_avg:.0%} over last {self._config.rolling_window_size} prompts."
            )
        else:
            parts.append(f"Single prompt drift of {drift_score:.0%}.")

        if (
            prompt_count < self._config.min_prompts_before_block
            and effective_score >= self._config.goal_drift_block_threshold
        ):
            parts.append(
                "Block withheld because only "
                f"{prompt_count} prompt(s) seen so far; minimum "
                f"{self._config.min_prompts_before_block} required."
            )

        return " ".join(parts)

    def clear_session(self, session_id: str) -> None:
        """Clear all drift history for a completed session.

        Args:
            session_id: Session identifier to clear.
        """
        self._prompt_distances.pop(session_id, None)
        self._prompt_counts.pop(session_id, None)
        self._session_peak_scores.pop(session_id, None)
        logger.debug(
            "GoalDriftDetector session cleared | session={}",
            session_id[:8],
        )
