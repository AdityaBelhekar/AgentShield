from __future__ import annotations

import time
from dataclasses import dataclass

import numpy as np

from agentshield.events.models import (
    BaseEvent,
    EventType,
    LLMEvent,
    MemoryEvent,
    ToolCallEvent,
)


@dataclass
class SessionFeatureVector:
    """Behavioral feature vector extracted from one agent session.

    Captures the statistical signature of how an agent
    behaved during a single session. Multiple SessionFeatureVectors
    are averaged to build the AgentBaseline in Phase 4C.

    Phase 4D compares live session features against the
    baseline to detect behavioral anomalies.

    All features are normalized floats for mathematical
    consistency. Raw counts are converted to rates where
    possible (e.g. tool_call_velocity = calls/minute).

    Attributes:
        agent_id: Human-readable agent identifier.
        session_id: UUID string of the session.
        tool_call_count: Total tool calls in session.
        unique_tools_used: Count of distinct tool names.
        tool_diversity: unique_tools / total_calls.
            1.0 = all different tools, 0.0 = same tool always.
        mean_prompt_length: Average chars per LLM prompt.
        prompt_length_variance: Variance of prompt lengths.
            Low = consistent prompts, High = erratic prompts.
        tool_call_velocity: Tool calls per minute.
        session_duration_seconds: Total session wall time.
        memory_write_count: Memory writes in session.
        memory_read_count: Memory reads in session.
        mean_response_length: Average LLM response chars.
        llm_call_count: Total LLM calls in session.
        max_tool_chain_depth: Longest consecutive tool sequence.
        threat_detector_firings: How many detectors fired.
        is_clean: Whether session had zero confirmed threats.
            Only clean sessions contribute to baseline.
    """

    agent_id: str
    session_id: str
    tool_call_count: int = 0
    unique_tools_used: int = 0
    tool_diversity: float = 0.0
    mean_prompt_length: float = 0.0
    prompt_length_variance: float = 0.0
    tool_call_velocity: float = 0.0
    session_duration_seconds: float = 0.0
    memory_write_count: int = 0
    memory_read_count: int = 0
    mean_response_length: float = 0.0
    llm_call_count: int = 0
    max_tool_chain_depth: int = 0
    threat_detector_firings: int = 0
    is_clean: bool = True

    def to_numpy(self) -> np.ndarray:
        """Convert feature vector to numpy array for math ops.

        Feature order is fixed and must match between
        baseline computation and anomaly scoring.

        Returns:
            1D numpy float32 array of length 13.
        """
        return np.array(
            [
                float(self.tool_call_count),
                float(self.unique_tools_used),
                self.tool_diversity,
                self.mean_prompt_length,
                self.prompt_length_variance,
                self.tool_call_velocity,
                self.session_duration_seconds,
                float(self.memory_write_count),
                float(self.memory_read_count),
                self.mean_response_length,
                float(self.llm_call_count),
                float(self.max_tool_chain_depth),
                float(self.threat_detector_firings),
            ],
            dtype=np.float32,
        )

    def to_dict(self) -> dict[str, float | int | str | bool]:
        """Serialize feature vector to dictionary.

        Used for persistence and audit logging.

        Returns:
            Dictionary of all feature values.
        """
        return {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "tool_call_count": self.tool_call_count,
            "unique_tools_used": self.unique_tools_used,
            "tool_diversity": self.tool_diversity,
            "mean_prompt_length": self.mean_prompt_length,
            "prompt_length_variance": self.prompt_length_variance,
            "tool_call_velocity": self.tool_call_velocity,
            "session_duration_seconds": self.session_duration_seconds,
            "memory_write_count": self.memory_write_count,
            "memory_read_count": self.memory_read_count,
            "mean_response_length": self.mean_response_length,
            "llm_call_count": self.llm_call_count,
            "max_tool_chain_depth": self.max_tool_chain_depth,
            "threat_detector_firings": self.threat_detector_firings,
            "is_clean": self.is_clean,
        }

    @classmethod
    def feature_names(cls) -> list[str]:
        """Return the ordered list of feature names.

        Must match the order in to_numpy() exactly.
        Used for interpretability and logging.

        Returns:
            List of feature name strings.
        """
        _ = cls
        return [
            "tool_call_count",
            "unique_tools_used",
            "tool_diversity",
            "mean_prompt_length",
            "prompt_length_variance",
            "tool_call_velocity",
            "session_duration_seconds",
            "memory_write_count",
            "memory_read_count",
            "mean_response_length",
            "llm_call_count",
            "max_tool_chain_depth",
            "threat_detector_firings",
        ]


class SessionObserver:
    """Observes a single agent session and extracts its features.

    Created at session start and updated as events arrive.
    At session end, compute() produces a SessionFeatureVector.

    One SessionObserver per active session. All state is
    local with no shared mutable state between sessions.

    Attributes:
        _agent_id: Agent identifier.
        _session_id: Session UUID string.
        _start_time: Session wall clock start time.
        _tool_names: All tool names called this session.
        _prompt_lengths: Length of each LLM prompt.
        _response_lengths: Length of each LLM response.
        _memory_writes: Count of memory write operations.
        _memory_reads: Count of memory read operations.
        _current_chain: Current consecutive tool sequence.
        _max_chain_depth: Longest consecutive tool sequence.
        _threat_count: Confirmed threat count.
    """

    def __init__(
        self,
        agent_id: str,
        session_id: str,
    ) -> None:
        """Initialize the SessionObserver.

        Args:
            agent_id: Human-readable agent identifier.
            session_id: Session UUID string.
        """
        self._agent_id = agent_id
        self._session_id = session_id
        self._start_time: float = time.monotonic()
        self._tool_names: list[str] = []
        self._prompt_lengths: list[int] = []
        self._response_lengths: list[int] = []
        self._memory_writes: int = 0
        self._memory_reads: int = 0
        self._current_chain: list[str] = []
        self._max_chain_depth: int = 0
        self._threat_count: int = 0

    def observe(self, event: BaseEvent) -> None:
        """Update observer state from a single event.

        Called by DNASystem.process_event() for every event
        in the session. Updates running tallies and sequences.

        Args:
            event: Any BaseEvent from the session.
        """
        if event.event_type == EventType.TOOL_CALL_START and isinstance(
            event, ToolCallEvent
        ):
            self._tool_names.append(event.tool_name)
            self._current_chain.append(event.tool_name)
            self._max_chain_depth = max(
                self._max_chain_depth,
                len(self._current_chain),
            )
            return

        if event.event_type == EventType.TOOL_CALL_COMPLETE:
            return

        if event.event_type == EventType.LLM_PROMPT and isinstance(event, LLMEvent):
            self._prompt_lengths.append(len(event.prompt))
            self._current_chain = []
            return

        if event.event_type == EventType.LLM_RESPONSE and isinstance(event, LLMEvent):
            if event.response is not None:
                self._response_lengths.append(len(event.response))
            return

        if event.event_type == EventType.MEMORY_WRITE and isinstance(
            event, MemoryEvent
        ):
            self._memory_writes += 1
            return

        if event.event_type == EventType.MEMORY_READ and isinstance(event, MemoryEvent):
            self._memory_reads += 1
            return

        if event.event_type == EventType.THREAT_DETECTED:
            self._threat_count += 1

    def compute(self) -> SessionFeatureVector:
        """Compute the final SessionFeatureVector for this session.

        Called at session close by DNASystem.close_session().
        Computes all derived features from raw observations.

        Returns:
            Completed SessionFeatureVector for this session.
        """
        duration = max(time.monotonic() - self._start_time, 0.001)

        tool_count = len(self._tool_names)
        unique_tools = len(set(self._tool_names))

        tool_diversity = unique_tools / tool_count if tool_count > 0 else 0.0
        tool_velocity = tool_count / (duration / 60.0)

        mean_prompt = (
            float(np.mean(self._prompt_lengths)) if self._prompt_lengths else 0.0
        )

        prompt_variance = (
            float(np.var(self._prompt_lengths))
            if len(self._prompt_lengths) > 1
            else 0.0
        )

        mean_response = (
            float(np.mean(self._response_lengths)) if self._response_lengths else 0.0
        )

        return SessionFeatureVector(
            agent_id=self._agent_id,
            session_id=self._session_id,
            tool_call_count=tool_count,
            unique_tools_used=unique_tools,
            tool_diversity=tool_diversity,
            mean_prompt_length=mean_prompt,
            prompt_length_variance=prompt_variance,
            tool_call_velocity=tool_velocity,
            session_duration_seconds=duration,
            memory_write_count=self._memory_writes,
            memory_read_count=self._memory_reads,
            mean_response_length=mean_response,
            llm_call_count=len(self._prompt_lengths),
            max_tool_chain_depth=self._max_chain_depth,
            threat_detector_firings=self._threat_count,
            is_clean=self._threat_count == 0,
        )
