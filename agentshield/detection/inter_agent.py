from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from loguru import logger

from agentshield.config import AgentShieldConfig
from agentshield.events.models import (
    EventType,
    RecommendedAction,
    SeverityLevel,
    ThreatEvent,
    ThreatType,
    TrustLevel,
)
from agentshield.exceptions import InterAgentInjectionError

INTER_AGENT_MIN_CONFIDENCE = 0.30
COMPROMISED_EXPOSURE_CONFIDENCE = 0.85
COMPROMISED_BASE_CONFIDENCE = 0.90
COMPROMISED_BOOSTED_CONFIDENCE = 0.95
SUSPICIOUS_BASE_CONFIDENCE = 0.55
SUSPICIOUS_BOOSTED_CONFIDENCE = 0.70
UNKNOWN_SENDER_CONFIDENCE = 0.35
UNTRUSTED_CONTENT_CONFIDENCE = 0.40
LOW_CONFIDENCE_FLOOR = 0.30
HIGH_ALERT_THRESHOLD = 0.85
FLAG_THRESHOLD = 0.50
SUSPICIOUS_UNTRUSTED_ESCALATION_COUNT = 3
COMPROMISED_HIGH_THREAT_COUNT = 1


class AgentTrustState(StrEnum):
    """Trust state of an agent in the multi-agent pipeline.

    Assigned by AgentTrustGraph based on observed behavior
    and the provenance of content the agent has processed.

    CLEAN: No threats detected, no untrusted content.
    SUSPICIOUS: Processed untrusted content or had detections.
    COMPROMISED: Confirmed threat detected in this agent.
    UNKNOWN: Agent registered but not yet profiled.
    """

    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    COMPROMISED = "COMPROMISED"
    UNKNOWN = "UNKNOWN"


@dataclass
class AgentNode:
    """Represents a single agent in the trust graph.

    Tracks the agent's current trust state, what untrusted
    content it has processed, and what threats were detected.

    Attributes:
        agent_id: Human-readable agent identifier.
        trust_state: Current AgentTrustState.
        untrusted_content_count: UNTRUSTED items processed.
        threat_count: Confirmed threats detected.
        suspicious_outputs: Content flagged as suspicious.
        registered_at: When agent was added to graph.
        last_updated: Last state change timestamp.
    """

    agent_id: str
    trust_state: AgentTrustState = AgentTrustState.UNKNOWN
    untrusted_content_count: int = 0
    threat_count: int = 0
    suspicious_outputs: list[str] = field(default_factory=list)
    registered_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_updated: datetime = field(default_factory=lambda: datetime.now(UTC))

    def mark_suspicious(self, reason: str) -> None:
        """Mark this agent as suspicious.

        Args:
            reason: Human-readable reason for suspicion.
        """
        if self.trust_state != AgentTrustState.COMPROMISED:
            self.trust_state = AgentTrustState.SUSPICIOUS
        self.suspicious_outputs.append(reason)
        self.last_updated = datetime.now(UTC)

    def mark_compromised(self) -> None:
        """Mark this agent as confirmed compromised."""
        self.trust_state = AgentTrustState.COMPROMISED
        self.last_updated = datetime.now(UTC)

    def mark_clean(self) -> None:
        """Mark this agent as clean."""
        self.trust_state = AgentTrustState.CLEAN
        self.last_updated = datetime.now(UTC)

    def to_dict(self) -> dict[str, object]:
        """Serialize node to dictionary.

        Returns:
            JSON-serializable dictionary.
        """
        return {
            "agent_id": self.agent_id,
            "trust_state": self.trust_state.value,
            "untrusted_content_count": self.untrusted_content_count,
            "threat_count": self.threat_count,
            "suspicious_outputs_count": len(self.suspicious_outputs),
            "registered_at": self.registered_at.isoformat(),
            "last_updated": self.last_updated.isoformat(),
        }


@dataclass
class InterAgentMessage:
    """Represents a message or data passing between agents.

    Created when one agent's output becomes another agent's
    input. The trust level of the message is determined by
    the sender's current trust state and the provenance of
    the content being passed.

    Attributes:
        message_id: Unique identifier for this message.
        sender_agent_id: Agent that produced this content.
        receiver_agent_id: Agent that will consume it.
        content_hash: SHA-256 hash of message content.
        trust_level: Assigned trust level for this message.
        sender_trust_state: Trust state of sender at send time.
        timestamp: When message was created.
        flagged: Whether message was flagged as suspicious.
        flag_reason: Why it was flagged if flagged=True.
    """

    message_id: str
    sender_agent_id: str
    receiver_agent_id: str
    content_hash: str
    trust_level: TrustLevel
    sender_trust_state: AgentTrustState
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    flagged: bool = False
    flag_reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize message to dictionary.

        Returns:
            JSON-serializable dictionary.
        """
        return {
            "message_id": self.message_id,
            "sender_agent_id": self.sender_agent_id,
            "receiver_agent_id": self.receiver_agent_id,
            "content_hash": self.content_hash,
            "trust_level": self.trust_level.value,
            "sender_trust_state": self.sender_trust_state.value,
            "timestamp": self.timestamp.isoformat(),
            "flagged": self.flagged,
            "flag_reason": self.flag_reason,
        }


class AgentTrustGraph:
    """Trust graph tracking relationships between agents.

    Maintains AgentNode for each registered agent and
    InterAgentMessage for each cross-agent communication.
    Provides trust state lookups for the InterAgentMonitor.

    One AgentTrustGraph per AgentShieldRuntime.
    Shared across all active sessions.

    Attributes:
        _nodes: AgentNode per agent_id.
        _messages: All InterAgentMessages seen.
        _edges: Directed edges sender -> set of receivers.
        _incoming_edges: Receiver -> set of senders.
    """

    _nodes: dict[str, AgentNode]
    _messages: list[InterAgentMessage]
    _edges: dict[str, set[str]]
    _incoming_edges: dict[str, set[str]]

    def __init__(self) -> None:
        """Initialize empty trust graph."""
        self._nodes = {}
        self._messages = []
        self._edges = {}
        self._incoming_edges = {}

        logger.debug("AgentTrustGraph initialized")

    def register_agent(self, agent_id: str) -> AgentNode:
        """Register an agent in the trust graph.

        Idempotent and returns existing node if already
        registered.

        Args:
            agent_id: Agent identifier to register.

        Returns:
            AgentNode for this agent.

        Raises:
            InterAgentInjectionError: If agent_id is empty.
        """
        if not agent_id.strip():
            raise InterAgentInjectionError(
                message="Agent identifier cannot be empty when registering trust graph node.",
                evidence={"agent_id": agent_id},
            )

        if agent_id not in self._nodes:
            node = AgentNode(agent_id=agent_id)
            self._nodes[agent_id] = node
            self._edges[agent_id] = set()
            self._incoming_edges[agent_id] = set()
            logger.debug("Agent registered in trust graph | agent={}", agent_id)
        return self._nodes[agent_id]

    def get_node(self, agent_id: str) -> AgentNode | None:
        """Get the AgentNode for an agent.

        Args:
            agent_id: Agent identifier to look up.

        Returns:
            AgentNode or None if not registered.
        """
        return self._nodes.get(agent_id)

    def update_agent_trust(
        self,
        agent_id: str,
        untrusted_count: int = 0,
        threat_count: int = 0,
    ) -> None:
        """Update an agent's trust state based on session results.

        Called when a session closes to update the graph
        with what happened during that session.

        Rules:
            threat_count > 0 -> COMPROMISED
            untrusted_count > 0 -> SUSPICIOUS (if not compromised)
            both 0 -> CLEAN

        Args:
            agent_id: Agent to update.
            untrusted_count: UNTRUSTED content items processed.
            threat_count: Confirmed threats detected.

        Raises:
            InterAgentInjectionError: If counts are negative.
        """
        if untrusted_count < 0 or threat_count < 0:
            raise InterAgentInjectionError(
                message="Trust update counts must be non-negative.",
                evidence={
                    "agent_id": agent_id,
                    "untrusted_count": untrusted_count,
                    "threat_count": threat_count,
                },
            )

        node = self._nodes.get(agent_id)
        if node is None:
            node = self.register_agent(agent_id)

        node.untrusted_content_count += untrusted_count
        node.threat_count += threat_count

        if threat_count > 0:
            node.mark_compromised()
            logger.warning(
                "Agent marked COMPROMISED | agent={} threats={}",
                agent_id,
                threat_count,
            )
        elif untrusted_count > 0:
            node.mark_suspicious(f"processed {untrusted_count} untrusted content items")
            logger.info(
                "Agent marked SUSPICIOUS | agent={} untrusted_items={}",
                agent_id,
                untrusted_count,
            )
        else:
            node.mark_clean()

    def record_message(
        self,
        sender_id: str,
        receiver_id: str,
        content_hash: str,
        trust_level: TrustLevel,
    ) -> InterAgentMessage:
        """Record a message passing between two agents.

        Determines the effective trust level of the message
        based on sender trust state and content trust level.

        Args:
            sender_id: Sending agent identifier.
            receiver_id: Receiving agent identifier.
            content_hash: Hash of message content.
            trust_level: Provenance trust level of content.

        Returns:
            InterAgentMessage with effective trust assessment.

        Raises:
            InterAgentInjectionError: If sender/receiver/hash are invalid.
        """
        if not sender_id.strip() or not receiver_id.strip() or not content_hash.strip():
            raise InterAgentInjectionError(
                message="Inter-agent message requires non-empty sender, receiver, and content hash.",
                evidence={
                    "sender_id": sender_id,
                    "receiver_id": receiver_id,
                    "content_hash_empty": not bool(content_hash.strip()),
                },
            )

        sender_node = self._nodes.get(sender_id)
        sender_state = (
            sender_node.trust_state if sender_node else AgentTrustState.UNKNOWN
        )

        effective_trust = self._compute_effective_trust(
            content_trust=trust_level,
            sender_state=sender_state,
        )

        flagged = effective_trust == TrustLevel.UNTRUSTED
        flag_reason: str | None = None
        if flagged:
            if sender_state == AgentTrustState.COMPROMISED:
                flag_reason = f"sender {sender_id} is COMPROMISED"
            elif sender_state == AgentTrustState.SUSPICIOUS:
                flag_reason = f"sender {sender_id} is SUSPICIOUS"
            else:
                flag_reason = "content has UNTRUSTED provenance"

        message = InterAgentMessage(
            message_id=str(uuid.uuid4()),
            sender_agent_id=sender_id,
            receiver_agent_id=receiver_id,
            content_hash=content_hash,
            trust_level=effective_trust,
            sender_trust_state=sender_state,
            flagged=flagged,
            flag_reason=flag_reason,
        )

        self._messages.append(message)

        self.register_agent(sender_id)
        self.register_agent(receiver_id)
        self._edges[sender_id].add(receiver_id)
        self._incoming_edges[receiver_id].add(sender_id)

        if flagged:
            logger.warning(
                "Suspicious inter-agent message | sender={} receiver={} reason={}",
                sender_id,
                receiver_id,
                flag_reason,
            )

        return message

    def get_senders_for_agent(self, agent_id: str) -> set[str]:
        """Get all agents that have sent messages to agent_id.

        Args:
            agent_id: Receiver agent identifier.

        Returns:
            Set of sender agent identifiers.
        """
        return set(self._incoming_edges.get(agent_id, set()))

    def has_compromised_sender(self, agent_id: str) -> bool:
        """Check if any sender to agent_id is compromised.

        Args:
            agent_id: Receiver agent to check.

        Returns:
            True if any sender is in compromised state.
        """
        for sender_id in self.get_senders_for_agent(agent_id):
            node = self._nodes.get(sender_id)
            if node is not None and node.trust_state == AgentTrustState.COMPROMISED:
                return True
        return False

    def get_flagged_messages(self) -> list[InterAgentMessage]:
        """Return all flagged inter-agent messages.

        Returns:
            List of flagged InterAgentMessage instances.
        """
        return [message for message in self._messages if message.flagged]

    def to_dict(self) -> dict[str, object]:
        """Serialize trust graph to dictionary.

        Returns:
            Dictionary with nodes, messages, and edges.
        """
        return {
            "nodes": {
                agent_id: node.to_dict() for agent_id, node in self._nodes.items()
            },
            "total_messages": len(self._messages),
            "flagged_messages": len(self.get_flagged_messages()),
            "edges": {
                sender: sorted(receivers) for sender, receivers in self._edges.items()
            },
        }

    def _compute_effective_trust(
        self,
        content_trust: TrustLevel,
        sender_state: AgentTrustState,
    ) -> TrustLevel:
        """Compute effective trust level for a message.

        Rules (most restrictive wins):
            Sender COMPROMISED -> always UNTRUSTED
            Sender SUSPICIOUS -> downgrade by one level
            Content UNTRUSTED -> always UNTRUSTED
            Otherwise -> use content trust level

        Args:
            content_trust: Provenance trust of the content.
            sender_state: Current trust state of the sender.

        Returns:
            Effective TrustLevel for this message.
        """
        if sender_state == AgentTrustState.COMPROMISED:
            return TrustLevel.UNTRUSTED

        if content_trust == TrustLevel.UNTRUSTED:
            return TrustLevel.UNTRUSTED

        if sender_state == AgentTrustState.SUSPICIOUS:
            downgrade_map: dict[TrustLevel, TrustLevel] = {
                TrustLevel.TRUSTED: TrustLevel.EXTERNAL,
                TrustLevel.INTERNAL: TrustLevel.EXTERNAL,
                TrustLevel.EXTERNAL: TrustLevel.UNTRUSTED,
                TrustLevel.UNTRUSTED: TrustLevel.UNTRUSTED,
            }
            return downgrade_map[content_trust]

        return content_trust


class InterAgentMonitor:
    """Monitors inter-agent communications for injection attacks.

    Uses AgentTrustGraph to detect suspicious patterns.
    Produces ThreatEvents with INTER_AGENT_INJECTION type.

    Attributes:
        _config: AgentShieldConfig.
        _trust_graph: Shared AgentTrustGraph instance.
    """

    _config: AgentShieldConfig
    _trust_graph: AgentTrustGraph

    def __init__(
        self,
        config: AgentShieldConfig,
        trust_graph: AgentTrustGraph,
    ) -> None:
        """Initialize the InterAgentMonitor.

        Args:
            config: AgentShieldConfig.
            trust_graph: Shared AgentTrustGraph to monitor.
        """
        self._config = config
        self._trust_graph = trust_graph
        logger.debug("InterAgentMonitor initialized")

    def check_message(
        self,
        message: InterAgentMessage,
        receiver_session_id: uuid.UUID,
    ) -> ThreatEvent | None:
        """Check an inter-agent message for injection threats.

        Analyzes the message against trust graph state and
        returns a ThreatEvent if suspicious patterns are detected.

        Args:
            message: The InterAgentMessage to check.
            receiver_session_id: Session UUID of receiver.

        Returns:
            ThreatEvent if threat detected, None if clean.
        """
        if not message.flagged:
            return None

        sender_node = self._trust_graph.get_node(message.sender_agent_id)

        confidence = self._compute_confidence(message=message, sender_node=sender_node)

        if confidence < INTER_AGENT_MIN_CONFIDENCE:
            return None

        action = self._determine_action(confidence)
        severity = self._determine_severity(message, sender_node)

        explanation = self._build_explanation(
            message=message,
            sender_node=sender_node,
            confidence=confidence,
        )

        evidence: dict[str, object] = {
            "sender_agent": message.sender_agent_id,
            "receiver_agent": message.receiver_agent_id,
            "sender_trust_state": message.sender_trust_state.value,
            "message_trust_level": message.trust_level.value,
            "flag_reason": message.flag_reason,
            "message_id": message.message_id,
            "trust_graph_summary": self._trust_graph.to_dict(),
        }

        logger.warning(
            "Inter-agent injection threat | sender={} receiver={} confidence={:.3f}",
            message.sender_agent_id,
            message.receiver_agent_id,
            confidence,
        )

        return ThreatEvent(
            session_id=receiver_session_id,
            agent_id=message.receiver_agent_id,
            event_type=EventType.THREAT_DETECTED,
            severity=severity,
            threat_type=ThreatType.INTER_AGENT_INJECTION,
            confidence=confidence,
            explanation=explanation,
            recommended_action=action,
            evidence=evidence,
            detector_name="InterAgentMonitor",
            canary_triggered=False,
        )

    def check_receiver_exposure(
        self,
        agent_id: str,
        session_id: uuid.UUID,
    ) -> ThreatEvent | None:
        """Check whether an agent was exposed to compromised senders.

        Called when a new session starts for an agent that
        has received messages from other agents. If any
        sender is compromised, raises an immediate alert.

        Args:
            agent_id: Agent to check for exposure.
            session_id: Current session UUID.

        Returns:
            ThreatEvent if compromised sender found.
            None if no exposure detected.
        """
        if not self._trust_graph.has_compromised_sender(agent_id):
            return None

        compromised_senders = [
            sender_id
            for sender_id in self._trust_graph.get_senders_for_agent(agent_id)
            if (
                (node := self._trust_graph.get_node(sender_id)) is not None
                and node.trust_state == AgentTrustState.COMPROMISED
            )
        ]

        explanation = (
            f"Agent {agent_id} has received messages from compromised agent(s): "
            f"{', '.join(compromised_senders)}. All content from these agents should "
            "be treated as potentially injected."
        )

        evidence: dict[str, object] = {
            "exposed_agent": agent_id,
            "compromised_senders": compromised_senders,
            "total_senders": len(self._trust_graph.get_senders_for_agent(agent_id)),
        }

        logger.warning(
            "Agent exposed to compromised sender | agent={} compromised_senders={}",
            agent_id,
            compromised_senders,
        )

        return ThreatEvent(
            session_id=session_id,
            agent_id=agent_id,
            event_type=EventType.THREAT_DETECTED,
            severity=SeverityLevel.HIGH,
            threat_type=ThreatType.INTER_AGENT_INJECTION,
            confidence=COMPROMISED_EXPOSURE_CONFIDENCE,
            explanation=explanation,
            recommended_action=RecommendedAction.ALERT,
            evidence=evidence,
            detector_name="InterAgentMonitor",
            canary_triggered=False,
        )

    def _compute_confidence(
        self,
        message: InterAgentMessage,
        sender_node: AgentNode | None,
    ) -> float:
        """Compute detection confidence for a flagged message.

        Args:
            message: The flagged message.
            sender_node: Sender's AgentNode or None.

        Returns:
            Confidence score from 0.0 to 1.0.
        """
        if sender_node is None:
            return UNKNOWN_SENDER_CONFIDENCE

        if sender_node.trust_state == AgentTrustState.COMPROMISED:
            if sender_node.threat_count > COMPROMISED_HIGH_THREAT_COUNT:
                return COMPROMISED_BOOSTED_CONFIDENCE
            return COMPROMISED_BASE_CONFIDENCE

        if sender_node.trust_state == AgentTrustState.SUSPICIOUS:
            if (
                sender_node.untrusted_content_count
                > SUSPICIOUS_UNTRUSTED_ESCALATION_COUNT
            ):
                return SUSPICIOUS_BOOSTED_CONFIDENCE
            return SUSPICIOUS_BASE_CONFIDENCE

        if message.trust_level == TrustLevel.UNTRUSTED:
            return UNTRUSTED_CONTENT_CONFIDENCE

        return LOW_CONFIDENCE_FLOOR

    def _determine_action(self, confidence: float) -> RecommendedAction:
        """Determine recommended action from confidence.

        Args:
            confidence: Detection confidence from 0.0 to 1.0.

        Returns:
            RecommendedAction enum value.
        """
        if confidence >= HIGH_ALERT_THRESHOLD:
            return RecommendedAction.ALERT
        if confidence >= FLAG_THRESHOLD:
            return RecommendedAction.FLAG
        return RecommendedAction.LOG_ONLY

    def _determine_severity(
        self,
        message: InterAgentMessage,
        sender_node: AgentNode | None,
    ) -> SeverityLevel:
        """Determine severity level for the threat.

        Args:
            message: The flagged message.
            sender_node: Sender's AgentNode or None.

        Returns:
            SeverityLevel enum value.
        """
        if (
            sender_node is not None
            and sender_node.trust_state == AgentTrustState.COMPROMISED
        ):
            return SeverityLevel.HIGH

        if message.trust_level == TrustLevel.UNTRUSTED:
            return SeverityLevel.MEDIUM

        return SeverityLevel.LOW

    def _build_explanation(
        self,
        message: InterAgentMessage,
        sender_node: AgentNode | None,
        confidence: float,
    ) -> str:
        """Build a human-readable explanation for a threat.

        Args:
            message: The flagged message.
            sender_node: Sender's AgentNode or None.
            confidence: Detection confidence.

        Returns:
            Explanation string.
        """
        parts: list[str] = [
            f"Inter-agent injection threat detected ({confidence:.0%} confidence)."
        ]

        if sender_node is not None:
            parts.append(
                f"Sender agent {message.sender_agent_id} is in "
                f"{sender_node.trust_state.value} state."
            )

        if message.flag_reason:
            parts.append(f"Reason: {message.flag_reason}.")

        parts.append(
            f"Content passed from {message.sender_agent_id} to "
            f"{message.receiver_agent_id} has effective trust level "
            f"{message.trust_level.value}."
        )

        return " ".join(parts)
