from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import numpy as np
from loguru import logger

from agentshield.canary.system import CanarySystem
from agentshield.config import AgentShieldConfig
from agentshield.detection.base_detector import BaseDetector, DetectionContext
from agentshield.detection.embedding_service import EmbeddingService
from agentshield.detection.goal_drift import GoalDriftDetector
from agentshield.detection.inter_agent import AgentTrustGraph, InterAgentMonitor
from agentshield.detection.memory_poison import MemoryPoisonDetector
from agentshield.detection.prompt_injection import PromptInjectionDetector
from agentshield.detection.tool_chain import ToolChainDetector
from agentshield.dna.baseline import DNASystem
from agentshield.events.emitter import EventEmitter
from agentshield.events.models import (
    BaseEvent,
    CanaryEvent,
    EventType,
    MemoryEvent,
    RecommendedAction,
    ThreatEvent,
    ThreatType,
    ToolCallEvent,
    TrustLevel,
)
from agentshield.exceptions import (
    GoalDriftError,
    InterAgentInjectionError,
    MemoryPoisonError,
    PolicyViolationError,
    PrivilegeEscalationError,
    PromptInjectionError,
    ToolCallBlockedError,
)
from agentshield.policy import (
    CompiledPolicy,
    PolicyAction,
    PolicyCompiler,
    PolicyDecision,
    PolicyEvaluator,
)
from agentshield.policy.models import PolicyConfig
from agentshield.provenance.tracker import ProvenanceTracker

if TYPE_CHECKING:
    from agentshield.dna.baseline import AgentBaseline

SINGLE_DETECTOR_MAX_ACTION = RecommendedAction.ALERT
MULTI_DETECTOR_ESCALATE_THRESHOLD = 2
ALWAYS_BLOCK_THRESHOLD = 3
MEMORY_DISTANCE_EPSILON = 1e-8


@dataclass
class CorrelationResult:
    """Result of cross-detector correlation analysis.

    Produced by DetectionEngine._correlate_threats() after
    all detectors have analyzed a single event.

    Attributes:
        threats: All ThreatEvents produced by detectors.
        final_action: Correlated action after escalation rules.
        should_block: Whether to raise PolicyViolationError.
        escalated: Whether correlation escalated any actions.
        detector_count: Number of detectors that fired.
    """

    threats: list[ThreatEvent]
    final_action: RecommendedAction
    should_block: bool
    escalated: bool
    detector_count: int


class DetectionEngine:
    """Orchestrates all AgentShield threat detectors.

    Central coordinator that:
      - Manages DetectionContext per active session
      - Routes events to relevant detectors efficiently
      - Applies cross-detector correlation before acting
      - Updates context state after each event
      - Emits ThreatEvents and raises PolicyViolationErrors

    Cross-detector correlation rules:
      1 detector fires  -> cap action at ALERT (no BLOCK)
      2 detectors fire  -> escalate FLAG->ALERT, ALERT->BLOCK
      3+ detectors fire -> BLOCK regardless

    Exception: canary-triggered threats always BLOCK
    immediately (implemented in Phase 4B).

    One DetectionEngine instance is shared across all
    sessions via AgentShieldRuntime. Session isolation
    is maintained through DetectionContext keyed by
    session_id.

    Attributes:
        _config: AgentShieldConfig with all thresholds.
        _emitter: EventEmitter for publishing ThreatEvents.
        _embedding_service: Shared sentence-transformer model.
        _detectors: All detector instances.
        _detector_routing: Maps EventType to detector list.
        _contexts: Active session contexts by session_id.
    """

    _config: AgentShieldConfig
    _emitter: EventEmitter
    _embedding_service: EmbeddingService
    _injection_detector: PromptInjectionDetector
    _drift_detector: GoalDriftDetector
    _chain_detector: ToolChainDetector
    _poison_detector: MemoryPoisonDetector
    _detectors: list[BaseDetector]
    _detector_routing: dict[EventType, list[BaseDetector]]
    _contexts: dict[str, DetectionContext]
    _provenance_tracker: ProvenanceTracker
    _canary_system: CanarySystem
    _dna_system: DNASystem
    _trust_graph: AgentTrustGraph
    _inter_agent_monitor: InterAgentMonitor
    _policy_evaluator: PolicyEvaluator | None

    def __init__(
        self,
        config: AgentShieldConfig,
        emitter: EventEmitter | None = None,
    ) -> None:
        """Initialize the DetectionEngine.

        Creates all detector instances sharing one
        EmbeddingService. Builds the event routing table.

        Args:
            config: AgentShieldConfig with all thresholds.
            emitter: EventEmitter for publishing ThreatEvents.
                If None, an EventEmitter is created.
        """
        self._config = config
        self._emitter = emitter or EventEmitter(config)
        self._contexts = {}

        self._embedding_service = EmbeddingService(config)

        self._injection_detector = PromptInjectionDetector(
            config, self._embedding_service
        )
        self._drift_detector = GoalDriftDetector(config, self._embedding_service)
        self._chain_detector = ToolChainDetector(config, self._embedding_service)
        self._poison_detector = MemoryPoisonDetector(config, self._embedding_service)

        self._detectors = [
            self._injection_detector,
            self._drift_detector,
            self._chain_detector,
            self._poison_detector,
        ]
        self._provenance_tracker = ProvenanceTracker(config)
        self._canary_system = CanarySystem(config)
        self._dna_system = DNASystem(config)
        self._trust_graph = AgentTrustGraph()
        self._inter_agent_monitor = InterAgentMonitor(config, self._trust_graph)
        self._policy_evaluator = None

        self._detector_routing = self._build_routing_table()

        logger.info(
            "DetectionEngine initialized | detectors={} detection_enabled={} blocking_enabled={}",
            len(self._detectors),
            config.detection_enabled,
            config.blocking_enabled,
        )

    def set_policy(
        self,
        policy: PolicyConfig | str | None,
    ) -> None:
        """Attach a compiled policy evaluator to this engine.

        Compiles the given policy and attaches a PolicyEvaluator.
        Pass None to remove any active policy (engine will use
        correlation result only).

        Args:
            policy: A PolicyConfig object, a built-in policy
                name string ("no_exfiltration", "strict",
                "monitor_only"), a path to a YAML policy
                file, or None to disable policy evaluation.
        """
        if policy is None:
            self._policy_evaluator = None
            logger.info("Policy detached from DetectionEngine")
            return

        compiler = PolicyCompiler(self._config)
        compiled: CompiledPolicy = compiler.compile(policy)
        self._policy_evaluator = PolicyEvaluator(self._config, compiled)
        logger.info(
            "Policy attached to DetectionEngine | policy={} rules={}",
            compiled.name,
            len(compiled.enabled_rules),
        )

    def initialize_session(
        self,
        session_id: uuid.UUID,
        agent_id: str,
        original_task: str,
    ) -> None:
        """Initialize detection context for a new agent session.

        Creates a DetectionContext, embeds the original task
        for GoalDriftDetector, and registers the session.

        Called by AgentShieldRuntime.wrap() immediately after
        the session is created.

        Args:
            session_id: UUID of the new session.
            agent_id: Human-readable agent identifier.
            original_task: The user's original task string.
        """
        task_embedding: np.ndarray | None = None

        if original_task.strip():
            task_embedding = self._embedding_service.embed(original_task)
            if task_embedding is not None:
                logger.info(
                    "Original task embedded | session={} task_len={}",
                    str(session_id)[:8],
                    len(original_task),
                )
            else:
                logger.warning(
                    "Could not embed original task - goal drift detection disabled | session={}",
                    str(session_id)[:8],
                )

        context = DetectionContext(
            session_id=session_id,
            agent_id=agent_id,
            original_task=original_task,
            original_task_embedding=task_embedding,
        )

        self._contexts[str(session_id)] = context
        self._provenance_tracker.initialize_session(session_id=session_id)
        self._canary_system.initialize_session(session_id)
        self._dna_system.initialize_session(
            session_id=session_id,
            agent_id=agent_id,
        )
        self._trust_graph.register_agent(agent_id)
        exposure_threat = self._inter_agent_monitor.check_receiver_exposure(
            agent_id=agent_id,
            session_id=session_id,
        )
        if exposure_threat is not None:
            self._emitter.emit(exposure_threat)

        logger.info(
            "Detection session initialized | session={} agent={} has_embedding={}",
            str(session_id)[:8],
            agent_id,
            task_embedding is not None,
        )

    def process_event(
        self,
        event: BaseEvent,
    ) -> list[ThreatEvent]:
        """Process a single event through all relevant detectors.

        Routes the event to detectors based on event_type.
        Applies cross-detector correlation to results.
        Emits all ThreatEvents via the EventEmitter.
        Raises PolicyViolationError if blocking is warranted
        and blocking is enabled in config.

        Also updates DetectionContext state after analysis
        so context reflects the latest session state.

        Args:
            event: Any BaseEvent to analyze.

        Returns:
            List of ThreatEvents produced (may be empty).

        Raises:
            PromptInjectionError: If injection detected and
                correlation warrants BLOCK.
            GoalDriftError: If drift detected and BLOCK.
            ToolCallBlockedError: If chain escalation and BLOCK.
            PrivilegeEscalationError: Subclass of above.
            MemoryPoisonError: If poisoning detected and BLOCK.
        """
        if not self._config.detection_enabled:
            return []

        session_key = str(event.session_id)
        context = self._contexts.get(session_key)

        if context is None:
            logger.debug(
                "No context for session {} - skipping detection",
                session_key[:8],
            )
            return []

        canary_threat = self._canary_system.process_event(event)
        if canary_threat is not None:
            canary_id = str(canary_threat.evidence.get("canary_id", "unknown"))
            canary_hash = str(canary_threat.evidence.get("canary_hash", "unknown"))
            trigger_context = str(canary_threat.evidence.get("trigger_context", ""))
            canary_event = CanaryEvent(
                session_id=event.session_id,
                agent_id=event.agent_id,
                event_type=EventType.CANARY_TRIGGERED,
                severity=canary_threat.severity,
                canary_id=canary_id,
                canary_hash=canary_hash,
                triggered=True,
                trigger_context=trigger_context,
            )
            self._emitter.emit(canary_event)
            self._emitter.emit(canary_threat)
            context.threat_count += 1
            context.blocked_count += 1
            self._raise_policy_violation([canary_threat])

        self._dna_system.process_event(event)

        provenance_event = self._provenance_tracker.process_event(event)
        if provenance_event is not None:
            self._emitter.emit(provenance_event)

        relevant_detectors = self._detector_routing.get(event.event_type, [])

        raw_threats: list[ThreatEvent] = []

        for detector in relevant_detectors:
            try:
                threat = detector.analyze(event, context)
                if threat is not None:
                    raw_threats.append(threat)
            except PolicyViolationError:
                raise
            except (RuntimeError, ValueError, TypeError) as exc:
                logger.error(
                    "Detector error | detector={} event_type={} error={}",
                    detector.detector_name,
                    event.event_type,
                    exc,
                )

        self._update_context(context, event)

        if not relevant_detectors:
            return []

        if not raw_threats:
            return []

        correlation = self._correlate_threats(raw_threats)
        threat_events = correlation.threats
        final_action = correlation.final_action
        should_block = correlation.should_block

        # -- Policy evaluation (Phase 5C) --------------------
        policy_decision: PolicyDecision | None = None
        if self._policy_evaluator is not None:
            policy_decision = self._policy_evaluator.evaluate(
                event=event,
                threats=threat_events,
                context=context,
            )

            if policy_decision.should_suppress:
                logger.info(
                    "Policy ALLOW: event suppressed | event_id={} rule={}",
                    event.id,
                    (
                        policy_decision.matched_rule.id
                        if policy_decision.matched_rule
                        else "default"
                    ),
                )
                return []

            if policy_decision.action == PolicyAction.BLOCK:
                final_action = RecommendedAction.BLOCK
                should_block = True
                logger.warning(
                    "Policy BLOCK override | event_id={} rule={}",
                    event.id,
                    (
                        policy_decision.matched_rule.id
                        if policy_decision.matched_rule
                        else "default"
                    ),
                )
            elif (
                policy_decision.action == PolicyAction.ALERT
                and final_action == RecommendedAction.FLAG
            ):
                final_action = RecommendedAction.ALERT
                logger.debug(
                    "Policy escalated FLAG -> ALERT | event_id={}",
                    event.id,
                )
        # -- End policy evaluation ----------------------------

        if final_action == RecommendedAction.BLOCK:
            threat_events = [
                threat.model_copy(
                    update={"recommended_action": RecommendedAction.BLOCK}
                )
                for threat in threat_events
            ]
        elif final_action == RecommendedAction.ALERT:
            threat_events = [
                threat.model_copy(
                    update={
                        "recommended_action": (
                            RecommendedAction.ALERT
                            if threat.recommended_action == RecommendedAction.FLAG
                            else threat.recommended_action
                        )
                    }
                )
                for threat in threat_events
            ]

        for threat in threat_events:
            self._emitter.emit(threat)
            context.threat_count += 1

        if correlation.escalated:
            logger.warning(
                "Threats escalated by correlation | detector_count={} final_action={} session={}",
                correlation.detector_count,
                final_action,
                session_key[:8],
            )

        if should_block and self._config.blocking_enabled:
            context.blocked_count += 1
            self._raise_policy_violation(threat_events)

        return threat_events

    def close_session(self, session_id: uuid.UUID) -> None:
        """Close a detection session and free resources.

        Cleans up DetectionContext and clears GoalDriftDetector
        history for this session to prevent memory leaks.

        Called by AgentShieldRuntime._close_session().

        Args:
            session_id: UUID of the session to close.
        """
        session_key = str(session_id)

        context = self._contexts.get(session_key)
        if context is None:
            return

        self._drift_detector.clear_session(session_key)
        self._provenance_tracker.close_session(session_id)
        self._canary_system.close_session(session_id)
        feature_vector = self._dna_system.close_session(
            session_id=session_id,
            agent_id=context.agent_id,
        )

        if feature_vector is not None:
            report = self._dna_system.score_session(
                feature_vector=feature_vector,
                agent_id=context.agent_id,
            )
            if report is not None and report.is_anomalous:
                from agentshield.dna.scorer import DNAAnomalyScorer

                scorer = DNAAnomalyScorer(self._config)
                threat = scorer.build_threat_event(
                    report=report,
                    session_id_str=str(session_id),
                    agent_id=context.agent_id,
                )
                self._emitter.emit(threat)
                logger.warning(
                    "Behavioral anomaly threat emitted | agent={} score={:.3f} session={}",
                    context.agent_id,
                    report.composite_score,
                    str(session_id)[:8],
                )

        prov_ctx = self._provenance_tracker.get_context(session_id)
        untrusted_count = prov_ctx.untrusted_content_count if prov_ctx else 0
        self._trust_graph.update_agent_trust(
            agent_id=context.agent_id,
            untrusted_count=untrusted_count,
            threat_count=context.threat_count,
        )

        del self._contexts[session_key]

        logger.info("Detection session closed | session={}", session_key[:8])

    def get_agent_baseline(self, agent_id: str) -> AgentBaseline | None:
        """Return the DNA baseline for an agent if available.

        Args:
            agent_id: Agent identifier to look up.

        Returns:
            AgentBaseline if available, None otherwise.
        """
        return self._dna_system.get_baseline(agent_id)

    def is_dna_established(self, agent_id: str) -> bool:
        """Check if DNA baseline is ready for this agent.

        Args:
            agent_id: Agent identifier.

        Returns:
            True if baseline has enough clean sessions.
        """
        return self._dna_system.is_baseline_established(agent_id)

    def get_trust_level(
        self,
        session_id: uuid.UUID,
        content: str,
    ) -> TrustLevel:
        """Get the trust level for content in a session.

        Delegates to ProvenanceTracker. Used by detectors
        that want to apply extra scrutiny to untrusted content.

        Args:
            session_id: UUID of the session.
            content: Content string to look up.

        Returns:
            TrustLevel for this content.
        """
        return self._provenance_tracker.get_trust_level(session_id, content)

    def get_canary_instruction(self, session_id: uuid.UUID) -> str | None:
        """Get canary instruction for injection into LLM context.

        Returns the canary instruction string that should be
        injected into the system prompt before each LLM call.
        Returns None if canary is disabled.

        Called by Phase 10 adapters before LLM invocation.

        Args:
            session_id: UUID of the current session.

        Returns:
            Canary instruction string or None.
        """

        return self._canary_system.get_canary_instruction(session_id)

    def record_inter_agent_message(
        self,
        sender_agent_id: str,
        receiver_agent_id: str,
        content: str,
        receiver_session_id: uuid.UUID,
    ) -> ThreatEvent | None:
        """Record and analyze a message between agents.

        Called by multi-agent framework adapters (Phase 10)
        when one agent passes output to another.

        Args:
            sender_agent_id: Sending agent identifier.
            receiver_agent_id: Receiving agent identifier.
            content: Message content string.
            receiver_session_id: Receiver's session UUID.

        Returns:
            ThreatEvent if inter-agent injection detected.
            None if message appears clean.
        """
        from agentshield.provenance.models import hash_content

        content_hash = hash_content(content)

        trust_level = self._provenance_tracker.get_trust_level(
            receiver_session_id,
            content,
        )

        message = self._trust_graph.record_message(
            sender_id=sender_agent_id,
            receiver_id=receiver_agent_id,
            content_hash=content_hash,
            trust_level=trust_level,
        )

        threat = self._inter_agent_monitor.check_message(
            message=message,
            receiver_session_id=receiver_session_id,
        )

        if threat is not None:
            self._emitter.emit(threat)

        return threat

    def get_trust_graph(self) -> AgentTrustGraph:
        """Return the current agent trust graph.

        Returns:
            AgentTrustGraph instance.
        """
        return self._trust_graph

    @property
    def active_sessions(self) -> int:
        """Number of currently active detection sessions."""
        return len(self._contexts)

    def _build_routing_table(self) -> dict[EventType, list[BaseDetector]]:
        """Build a mapping from EventType to relevant detectors.

        Each detector declares its supported_event_types.
        This method inverts that to build an efficient
        lookup table: EventType -> [detector, detector, ...].

        Called once at init. O(1) lookup at runtime.

        Returns:
            Dict mapping EventType to list of detectors.
        """
        routing: dict[EventType, list[BaseDetector]] = {}

        for detector in self._detectors:
            for event_type in detector.supported_event_types:
                if event_type not in routing:
                    routing[event_type] = []
                routing[event_type].append(detector)

        logger.debug(
            "Detector routing table built | routes={}",
            {
                key.value: [detector.detector_name for detector in value]
                for key, value in routing.items()
            },
        )

        return routing

    def _correlate_threats(self, threats: list[ThreatEvent]) -> CorrelationResult:
        """Apply cross-detector correlation rules to threats.

        Correlation rules:
          1 detector  -> cap action at ALERT, no BLOCK
                        (unless canary_triggered=True)
          2 detectors -> escalate: FLAG->ALERT, ALERT->BLOCK
          3+ detectors-> always BLOCK

        This is the core false-positive reduction mechanism.
        A single detector firing alone (e.g. read->email which
        the user explicitly requested) gets flagged but not
        blocked. Multiple detectors firing together signals
        a real attack.

        Args:
            threats: List of ThreatEvents from all detectors.

        Returns:
            CorrelationResult with final action and block flag.
        """
        if not threats:
            return CorrelationResult(
                threats=[],
                final_action=RecommendedAction.LOG_ONLY,
                should_block=False,
                escalated=False,
                detector_count=0,
            )

        detector_count = len(threats)
        any_canary = any(threat.canary_triggered for threat in threats)

        if any_canary:
            logger.warning(
                "Canary trigger detected - immediate block | threats={}",
                detector_count,
            )
            canary_blocked = [
                threat.model_copy(
                    update={"recommended_action": RecommendedAction.BLOCK}
                )
                for threat in threats
            ]
            return CorrelationResult(
                threats=canary_blocked,
                final_action=RecommendedAction.BLOCK,
                should_block=True,
                escalated=True,
                detector_count=detector_count,
            )

        highest_action = max(
            threats,
            key=lambda threat: self._action_priority(threat.recommended_action),
        ).recommended_action

        final_action = highest_action

        if detector_count >= ALWAYS_BLOCK_THRESHOLD:
            final_action = RecommendedAction.BLOCK
        elif detector_count >= MULTI_DETECTOR_ESCALATE_THRESHOLD:
            final_action = self._escalate_action(highest_action)
        elif highest_action == RecommendedAction.BLOCK:
            final_action = SINGLE_DETECTOR_MAX_ACTION

        escalated_threats: list[ThreatEvent] = []
        any_escalated = False

        for threat in threats:
            updated_action = threat.recommended_action
            if detector_count >= ALWAYS_BLOCK_THRESHOLD:
                updated_action = RecommendedAction.BLOCK
            elif detector_count >= MULTI_DETECTOR_ESCALATE_THRESHOLD:
                updated_action = self._escalate_action(threat.recommended_action)
            elif threat.recommended_action == RecommendedAction.BLOCK:
                updated_action = SINGLE_DETECTOR_MAX_ACTION

            if updated_action != threat.recommended_action:
                any_escalated = True

            escalated_threats.append(
                threat.model_copy(update={"recommended_action": updated_action})
            )

        should_block = final_action == RecommendedAction.BLOCK

        return CorrelationResult(
            threats=escalated_threats,
            final_action=final_action,
            should_block=should_block,
            escalated=any_escalated,
            detector_count=detector_count,
        )

    def _action_priority(self, action: RecommendedAction) -> int:
        """Map RecommendedAction to numeric priority for sorting.

        Higher number = higher priority / more severe action.

        Args:
            action: RecommendedAction enum value.

        Returns:
            Integer priority from 0 (lowest) to 3 (highest).
        """
        priorities: dict[RecommendedAction, int] = {
            RecommendedAction.LOG_ONLY: 0,
            RecommendedAction.FLAG: 1,
            RecommendedAction.ALERT: 2,
            RecommendedAction.BLOCK: 3,
        }
        return priorities[action]

    def _escalate_action(self, action: RecommendedAction) -> RecommendedAction:
        """Escalate an action by one level.

        LOG_ONLY -> FLAG
        FLAG     -> ALERT
        ALERT    -> BLOCK
        BLOCK    -> BLOCK (already maximum)

        Args:
            action: Current RecommendedAction to escalate.

        Returns:
            Escalated RecommendedAction.
        """
        escalation_map: dict[RecommendedAction, RecommendedAction] = {
            RecommendedAction.LOG_ONLY: RecommendedAction.FLAG,
            RecommendedAction.FLAG: RecommendedAction.ALERT,
            RecommendedAction.ALERT: RecommendedAction.BLOCK,
            RecommendedAction.BLOCK: RecommendedAction.BLOCK,
        }
        return escalation_map[action]

    def _update_context(self, context: DetectionContext, event: BaseEvent) -> None:
        """Update DetectionContext state after processing an event.

        Called after detectors have analyzed the event so
        the current event is not included in its own analysis
        (prevents circular dependency).

        Updates:
          ToolCallEvent(START/COMPLETE) -> tool_call_history
          MemoryEvent(WRITE) -> memory_embeddings + distances
          All events -> all_events

        Args:
            context: The session context to update.
            event: The event that was just processed.
        """
        context.all_events.append(event)

        if isinstance(event, ToolCallEvent) and event.event_type in (
            EventType.TOOL_CALL_START,
            EventType.TOOL_CALL_COMPLETE,
        ):
            context.tool_call_history.append(event)

        if (
            isinstance(event, MemoryEvent)
            and event.event_type == EventType.MEMORY_WRITE
            and self._embedding_service.is_available()
        ):
            embedding = self._embedding_service.embed(event.content_preview)
            if embedding is not None:
                if context.memory_embeddings:
                    centroid = np.mean(np.array(context.memory_embeddings), axis=0)
                    numerator = float(np.dot(embedding, centroid))
                    denominator = float(
                        np.linalg.norm(embedding) * np.linalg.norm(centroid)
                        + MEMORY_DISTANCE_EPSILON
                    )
                    distance = float(1.0 - numerator / denominator)
                    context.memory_distances.append(distance)

                context.memory_embeddings.append(embedding)

    def _raise_policy_violation(self, threats: list[ThreatEvent]) -> None:
        """Raise the appropriate PolicyViolationError subclass.

        Selects the highest-confidence threat and raises
        the matching exception type with full context.

        Args:
            threats: List of ThreatEvents that triggered block.

        Raises:
            PromptInjectionError: Prompt injection was primary threat.
            GoalDriftError: Goal drift was primary threat.
            ToolCallBlockedError: Tool chain escalation was primary threat.
            PrivilegeEscalationError: Alias for severe tool escalation.
            MemoryPoisonError: Memory poisoning was primary threat.
            PolicyViolationError: Fallback when threat type is unknown.
        """
        primary = max(threats, key=lambda threat: threat.confidence)

        evidence: dict[str, Any] = {
            "detector": primary.detector_name,
            "confidence": primary.confidence,
            "all_threats": [
                {
                    "type": threat.threat_type.value,
                    "confidence": threat.confidence,
                    "detector": threat.detector_name,
                }
                for threat in threats
            ],
        }

        kwargs: dict[str, Any] = {
            "message": primary.explanation,
            "threat_type": primary.threat_type.value,
            "confidence": primary.confidence,
            "evidence": evidence,
            "session_id": str(primary.session_id),
        }

        exception_map: dict[ThreatType, type[PolicyViolationError]] = {
            ThreatType.PROMPT_INJECTION: PromptInjectionError,
            ThreatType.GOAL_DRIFT: GoalDriftError,
            ThreatType.TOOL_CHAIN_ESCALATION: PrivilegeEscalationError,
            ThreatType.MEMORY_POISONING: MemoryPoisonError,
            ThreatType.TOOL_POISONING: ToolCallBlockedError,
            ThreatType.INTER_AGENT_INJECTION: InterAgentInjectionError,
        }

        exception_cls = exception_map.get(primary.threat_type, PolicyViolationError)
        raise exception_cls(**kwargs)
