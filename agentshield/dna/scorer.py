from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import numpy as np
from loguru import logger

from agentshield.config import AgentShieldConfig
from agentshield.dna.features import SessionFeatureVector
from agentshield.events.models import (
    EventType,
    RecommendedAction,
    SeverityLevel,
    ThreatEvent,
    ThreatType,
)

if TYPE_CHECKING:
    from agentshield.dna.baseline import AgentBaseline


FEATURE_WEIGHTS: dict[str, float] = {
    "tool_call_count": 1.0,
    "unique_tools_used": 1.0,
    "tool_diversity": 1.5,
    "mean_prompt_length": 1.0,
    "prompt_length_variance": 1.0,
    "tool_call_velocity": 2.0,
    "session_duration_seconds": 0.5,
    "memory_write_count": 1.5,
    "memory_read_count": 1.0,
    "mean_response_length": 1.0,
    "llm_call_count": 1.0,
    "max_tool_chain_depth": 2.0,
    "threat_detector_firings": 3.0,
}


@dataclass
class AnomalyReport:
    """Detailed report of behavioral anomaly scoring results.

    Produced by DNAAnomalyScorer.score() for every session that
    is scored against an established baseline.

    Attributes:
        agent_id: Agent that was scored.
        session_id: Session that was scored.
        composite_score: Final anomaly score from 0.0 to 1.0.
        is_anomalous: Whether score exceeds threshold.
        feature_zscores: Z-score per feature name.
        anomalous_features: Features with |z| above threshold.
        feature_contributions: Weighted contribution per feature.
        baseline_session_count: Sessions represented in baseline.
        threshold_used: anomaly_sensitivity config value.
    """

    agent_id: str
    session_id: str
    composite_score: float
    is_anomalous: bool
    feature_zscores: dict[str, float] = field(default_factory=dict)
    anomalous_features: list[str] = field(default_factory=list)
    feature_contributions: dict[str, float] = field(default_factory=dict)
    baseline_session_count: int = 0
    threshold_used: float = 0.85

    def to_dict(self) -> dict[str, object]:
        """Serialize report to dictionary for evidence logging.

        Returns:
            JSON-serializable dictionary.
        """
        return {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "composite_score": round(self.composite_score, 4),
            "is_anomalous": self.is_anomalous,
            "feature_zscores": {
                key: round(value, 4) for key, value in self.feature_zscores.items()
            },
            "anomalous_features": self.anomalous_features,
            "feature_contributions": {
                key: round(value, 4)
                for key, value in self.feature_contributions.items()
            },
            "baseline_session_count": self.baseline_session_count,
            "threshold_used": self.threshold_used,
        }


class DNAAnomalyScorer:
    """Scores agent sessions against behavioral baselines.

    Uses z-score deviation from established AgentBaseline to compute
    a composite anomaly score. Scoring is session-end only and runs
    after the full SessionFeatureVector is available.

    Attributes:
        _config: AgentShieldConfig with anomaly_sensitivity.
    """

    _config: AgentShieldConfig

    def __init__(self, config: AgentShieldConfig) -> None:
        """Initialize the DNAAnomalyScorer.

        Args:
            config: AgentShieldConfig with anomaly sensitivity.
        """
        self._config = config
        logger.debug("DNAAnomalyScorer initialized")

    def score(
        self,
        feature_vector: SessionFeatureVector,
        baseline: AgentBaseline,
    ) -> AnomalyReport | None:
        """Score a session's features against the agent baseline.

        Computes z-score deviation per feature, applies feature
        importance weights, and returns a composite score.

        Args:
            feature_vector: Session features to score.
            baseline: Established agent behavioral baseline.

        Returns:
            AnomalyReport with score and per-feature detail,
            or None if baseline is not established.
        """
        if not baseline.established:
            logger.debug(
                "Baseline not established - skipping anomaly scoring | agent={}",
                feature_vector.agent_id,
            )
            return None

        zscores = baseline.get_zscore(feature_vector)
        if zscores is None:
            return None

        feature_names = SessionFeatureVector.feature_names()
        weights = np.asarray(
            [FEATURE_WEIGHTS.get(name, 1.0) for name in feature_names],
            dtype=np.float32,
        )

        threshold = self._config.anomaly_sensitivity
        z_abs = np.abs(zscores)

        denominator = max(threshold, 0.001)
        contributions = np.maximum(0.0, z_abs - 1.0) / denominator
        weighted_contributions = contributions * weights

        total_weight = float(np.sum(weights))
        composite = float(np.sum(weighted_contributions) / total_weight)
        composite = float(np.clip(composite, 0.0, 1.0))

        feature_zscores = {
            feature_name: float(zscores[index])
            for index, feature_name in enumerate(feature_names)
        }

        anomalous_features = [
            feature_name
            for index, feature_name in enumerate(feature_names)
            if abs(float(zscores[index])) > threshold
        ]

        feature_contributions = {
            feature_name: float(weighted_contributions[index])
            for index, feature_name in enumerate(feature_names)
        }

        is_anomalous = composite >= threshold

        report = AnomalyReport(
            agent_id=feature_vector.agent_id,
            session_id=feature_vector.session_id,
            composite_score=composite,
            is_anomalous=is_anomalous,
            feature_zscores=feature_zscores,
            anomalous_features=anomalous_features,
            feature_contributions=feature_contributions,
            baseline_session_count=baseline.session_count,
            threshold_used=threshold,
        )

        if is_anomalous:
            logger.warning(
                "Behavioral anomaly detected | agent={} score={:.3f} threshold={:.3f} anomalous_features={}",
                feature_vector.agent_id,
                composite,
                threshold,
                anomalous_features[:5],
            )
        else:
            logger.debug(
                "Session within normal behavior | agent={} score={:.3f}",
                feature_vector.agent_id,
                composite,
            )

        return report

    def build_threat_event(
        self,
        report: AnomalyReport,
        session_id_str: str,
        agent_id: str,
    ) -> ThreatEvent:
        """Build a ThreatEvent from an anomalous AnomalyReport.

        Produces a BEHAVIORAL_ANOMALY threat with FLAG or ALERT
        recommendation. This detector never recommends BLOCK alone.

        Args:
            report: Anomalous report to convert.
            session_id_str: Session UUID string.
            agent_id: Agent identifier string.

        Returns:
            ThreatEvent with BEHAVIORAL_ANOMALY threat type.
        """
        try:
            session_uuid = uuid.UUID(session_id_str)
        except ValueError:
            session_uuid = uuid.uuid4()

        score = report.composite_score
        if score >= 0.90:
            action = RecommendedAction.ALERT
            severity = SeverityLevel.HIGH
        elif score >= 0.85:
            action = RecommendedAction.FLAG
            severity = SeverityLevel.MEDIUM
        else:
            action = RecommendedAction.FLAG
            severity = SeverityLevel.LOW

        top_features = sorted(
            report.anomalous_features,
            key=lambda feature_name: abs(report.feature_zscores.get(feature_name, 0.0)),
            reverse=True,
        )[:3]

        explanation = (
            "Agent behavioral anomaly detected. "
            f"Session deviates {report.composite_score:.0%} from established baseline "
            f"({report.baseline_session_count} sessions). "
            "Most anomalous features: "
            f"{', '.join(top_features) if top_features else 'none'}."
        )

        return ThreatEvent(
            session_id=session_uuid,
            agent_id=agent_id,
            event_type=EventType.THREAT_DETECTED,
            severity=severity,
            threat_type=ThreatType.BEHAVIORAL_ANOMALY,
            confidence=score,
            explanation=explanation,
            recommended_action=action,
            evidence=report.to_dict(),
            detector_name="DNAAnomalyScorer",
            canary_triggered=False,
        )
