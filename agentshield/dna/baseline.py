from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
from loguru import logger

from agentshield.config import AgentShieldConfig
from agentshield.dna.features import (
    SessionFeatureVector,
    SessionObserver,
)
from agentshield.events.models import BaseEvent
from agentshield.exceptions import DNAError


@dataclass
class AgentBaseline:
    """Statistical behavioral baseline for a specific agent.

    Built from multiple clean SessionFeatureVectors.
    Represents what "normal" looks like for this agent.

    Once MIN_SESSIONS clean sessions have been observed,
    the baseline is considered established and Phase 4D
    can use it for anomaly scoring.

    Attributes:
        agent_id: Human-readable agent identifier.
        session_count: Number of clean sessions in baseline.
        mean_vector: Mean feature vector across all sessions.
        std_vector: Standard deviation per feature.
            Used for z-score normalization in Phase 4D.
        min_vector: Minimum observed value per feature.
        max_vector: Maximum observed value per feature.
        established: Whether baseline has enough sessions.
        created_at: When baseline was first created.
        last_updated: When baseline was last updated.
        feature_names: Ordered list of feature names.
    """

    agent_id: str
    session_count: int = 0
    mean_vector: np.ndarray | None = None
    std_vector: np.ndarray | None = None
    min_vector: np.ndarray | None = None
    max_vector: np.ndarray | None = None
    established: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_updated: datetime = field(default_factory=lambda: datetime.now(UTC))
    feature_names: list[str] = field(default_factory=SessionFeatureVector.feature_names)
    _raw_vectors: list[np.ndarray] = field(
        default_factory=list,
        repr=False,
    )

    def update(
        self,
        feature_vector: SessionFeatureVector,
        min_sessions: int,
    ) -> None:
        """Update baseline with a new clean session's features.

        Incrementally updates mean, std, min, and max vectors.
        Marks baseline as established when min_sessions is reached.

        Args:
            feature_vector: Clean session features to add.
            min_sessions: Minimum sessions for establishment.
        """
        vec = feature_vector.to_numpy()
        self._raw_vectors.append(vec)
        self.session_count += 1
        self.last_updated = datetime.now(UTC)

        all_vecs = np.array(self._raw_vectors)
        self.mean_vector = np.mean(all_vecs, axis=0)
        self.std_vector = np.std(all_vecs, axis=0)
        self.min_vector = np.min(all_vecs, axis=0)
        self.max_vector = np.max(all_vecs, axis=0)

        if not self.established and self.session_count >= min_sessions:
            self.established = True
            logger.info(
                "Agent DNA baseline established | agent={} sessions={}",
                self.agent_id,
                self.session_count,
            )

        logger.debug(
            "Baseline updated | agent={} sessions={} established={}",
            self.agent_id,
            self.session_count,
            self.established,
        )

    def get_zscore(self, feature_vector: SessionFeatureVector) -> np.ndarray | None:
        """Compute z-score of a feature vector versus this baseline.

        Args:
            feature_vector: Session to score against baseline.

        Returns:
            Z-score array of same length as feature vector,
            or None if baseline is not ready.
        """
        if not self.established:
            return None
        if self.mean_vector is None or self.std_vector is None:
            return None

        vec = feature_vector.to_numpy()
        std = self.std_vector.copy()
        std[std == 0.0] = 1.0

        zscores = (vec - self.mean_vector) / std
        return np.asarray(zscores, dtype=np.float32)

    def to_dict(self) -> dict[str, object]:
        """Serialize baseline to dictionary for persistence.

        Returns:
            JSON-serializable dictionary.
        """
        return {
            "agent_id": self.agent_id,
            "session_count": self.session_count,
            "established": self.established,
            "created_at": self.created_at.isoformat(),
            "last_updated": self.last_updated.isoformat(),
            "feature_names": self.feature_names,
            "mean_vector": (
                self.mean_vector.tolist() if self.mean_vector is not None else None
            ),
            "std_vector": (
                self.std_vector.tolist() if self.std_vector is not None else None
            ),
            "min_vector": (
                self.min_vector.tolist() if self.min_vector is not None else None
            ),
            "max_vector": (
                self.max_vector.tolist() if self.max_vector is not None else None
            ),
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> AgentBaseline:
        """Deserialize baseline from dictionary.

        Args:
            data: Dictionary from to_dict().

        Returns:
            Reconstructed AgentBaseline.
        """
        baseline = cls(agent_id=str(data["agent_id"]))
        session_count_value = data.get("session_count", 0)
        if isinstance(session_count_value, bool):
            baseline.session_count = int(session_count_value)
        elif isinstance(session_count_value, int):
            baseline.session_count = session_count_value
        elif isinstance(session_count_value, float):
            baseline.session_count = int(session_count_value)
        elif isinstance(session_count_value, str):
            baseline.session_count = int(session_count_value)
        else:
            baseline.session_count = 0
        baseline.established = bool(data.get("established", False))

        created_at_value = data.get("created_at")
        if isinstance(created_at_value, str):
            baseline.created_at = datetime.fromisoformat(created_at_value)

        last_updated_value = data.get("last_updated")
        if isinstance(last_updated_value, str):
            baseline.last_updated = datetime.fromisoformat(last_updated_value)

        feature_names_value = data.get("feature_names")
        if isinstance(feature_names_value, list):
            baseline.feature_names = [str(name) for name in feature_names_value]

        mean = data.get("mean_vector")
        std = data.get("std_vector")
        mn = data.get("min_vector")
        mx = data.get("max_vector")

        if mean is not None:
            baseline.mean_vector = np.array(mean, dtype=np.float32)
        if std is not None:
            baseline.std_vector = np.array(std, dtype=np.float32)
        if mn is not None:
            baseline.min_vector = np.array(mn, dtype=np.float32)
        if mx is not None:
            baseline.max_vector = np.array(mx, dtype=np.float32)

        return baseline


class DNASystem:
    """Manages Agent DNA fingerprinting baseline collection.

    Phase 4C responsibilities:
      - Create SessionObserver per session
      - Feed events to observer as session runs
      - At session close, extract SessionFeatureVector
      - Update AgentBaseline with clean sessions
      - Persist baseline to disk between runs

    Attributes:
        _config: AgentShieldConfig with DNA settings.
        _baselines: AgentBaseline per agent_id.
        _observers: Active SessionObserver per session_id.
        _baseline_path: Optional path for baseline persistence.
    """

    def __init__(
        self,
        config: AgentShieldConfig,
        baseline_path: Path | None = None,
    ) -> None:
        """Initialize the DNASystem.

        Args:
            config: AgentShieldConfig with DNA settings.
            baseline_path: Optional baseline directory path.
        """
        self._config = config
        self._baselines: dict[str, AgentBaseline] = {}
        self._observers: dict[str, SessionObserver] = {}
        self._baseline_path = baseline_path

        if baseline_path is not None:
            self._load_baselines(baseline_path)

        logger.info(
            "DNASystem initialized | min_sessions={} baselines_loaded={}",
            config.dna_min_sessions,
            len(self._baselines),
        )

    def initialize_session(
        self,
        session_id: uuid.UUID,
        agent_id: str,
    ) -> None:
        """Start observing a new agent session.

        Args:
            session_id: UUID of the new session.
            agent_id: Human-readable agent identifier.
        """
        observer = SessionObserver(
            agent_id=agent_id,
            session_id=str(session_id),
        )
        self._observers[str(session_id)] = observer

        logger.debug(
            "DNA session started | session={} agent={}",
            str(session_id)[:8],
            agent_id,
        )

    def process_event(self, event: BaseEvent) -> None:
        """Feed an event to the active session observer.

        Args:
            event: Any BaseEvent from the session.
        """
        session_key = str(event.session_id)
        observer = self._observers.get(session_key)
        if observer is None:
            return

        observer.observe(event)

    def close_session(
        self,
        session_id: uuid.UUID,
        agent_id: str,
    ) -> SessionFeatureVector | None:
        """Close session, extract features, and update baseline.

        Args:
            session_id: UUID of the session to close.
            agent_id: Human-readable agent identifier.

        Returns:
            Computed SessionFeatureVector for this session,
            or None if no observer exists.
        """
        session_key = str(session_id)
        observer = self._observers.pop(session_key, None)

        if observer is None:
            logger.debug(
                "No DNA observer for session={} - skipping",
                session_key[:8],
            )
            return None

        feature_vector = observer.compute()

        logger.info(
            "DNA session features computed | session={} agent={} tools={} llm_calls={} duration={:.1f}s is_clean={}",
            session_key[:8],
            agent_id,
            feature_vector.tool_call_count,
            feature_vector.llm_call_count,
            feature_vector.session_duration_seconds,
            feature_vector.is_clean,
        )

        if feature_vector.is_clean:
            self._update_baseline(agent_id, feature_vector)
        else:
            logger.debug(
                "Session not clean - skipping baseline update | session={} threats={}",
                session_key[:8],
                feature_vector.threat_detector_firings,
            )

        if self._baseline_path is not None:
            self.save_baselines(self._baseline_path)

        return feature_vector

    def get_baseline(self, agent_id: str) -> AgentBaseline | None:
        """Return baseline for agent if available.

        Args:
            agent_id: Agent identifier.

        Returns:
            AgentBaseline if one exists, otherwise None.
        """
        return self._baselines.get(agent_id)

    def is_baseline_established(self, agent_id: str) -> bool:
        """Check if an agent baseline has been established.

        Args:
            agent_id: Agent identifier.

        Returns:
            True if baseline exists and is established.
        """
        baseline = self._baselines.get(agent_id)
        return baseline is not None and baseline.established

    def save_baselines(self, path: Path) -> None:
        """Persist all agent baselines to disk as JSON.

        Args:
            path: Directory path to save baseline files.

        Raises:
            DNAError: If baseline files cannot be persisted.
        """
        try:
            path.mkdir(parents=True, exist_ok=True)
            for agent_id, baseline in self._baselines.items():
                safe_name = agent_id.replace("/", "_").replace(" ", "_")
                file_path = path / f"baseline_{safe_name}.json"
                with file_path.open("w", encoding="utf-8") as file_obj:
                    json.dump(baseline.to_dict(), file_obj, indent=2)
            logger.info(
                "DNA baselines saved | path={} count={}",
                path,
                len(self._baselines),
            )
        except OSError as exc:
            raise DNAError(
                "Failed to save DNA baselines",
                evidence={"path": str(path), "error": str(exc)},
            ) from exc
        except TypeError as exc:
            raise DNAError(
                "Failed to serialize DNA baselines",
                evidence={"path": str(path), "error": str(exc)},
            ) from exc

    def _update_baseline(
        self,
        agent_id: str,
        feature_vector: SessionFeatureVector,
    ) -> None:
        """Update or create baseline for an agent.

        Args:
            agent_id: Agent identifier.
            feature_vector: Clean session features to add.
        """
        if agent_id not in self._baselines:
            self._baselines[agent_id] = AgentBaseline(agent_id=agent_id)
            logger.info("New DNA baseline created | agent={}", agent_id)

        baseline = self._baselines[agent_id]
        baseline.update(feature_vector, self._config.dna_min_sessions)

    def _load_baselines(self, path: Path) -> None:
        """Load persisted baselines from disk.

        Args:
            path: Directory path to load from.

        Raises:
            DNAError: If directory cannot be scanned.
        """
        if not path.exists():
            logger.debug("Baseline directory not found | path={}", path)
            return

        loaded = 0
        try:
            files = list(path.glob("baseline_*.json"))
        except OSError as exc:
            raise DNAError(
                "Failed to read baseline directory",
                evidence={"path": str(path), "error": str(exc)},
            ) from exc

        for file_path in files:
            try:
                with file_path.open("r", encoding="utf-8") as file_obj:
                    data = json.load(file_obj)
                if not isinstance(data, dict):
                    raise ValueError("Baseline JSON root must be an object")
                baseline = AgentBaseline.from_dict(data)
                self._baselines[baseline.agent_id] = baseline
                loaded += 1
            except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
                logger.warning(
                    "Failed to load baseline | file={} error={}",
                    file_path.name,
                    exc,
                )

        logger.info("DNA baselines loaded | path={} loaded={}", path, loaded)
