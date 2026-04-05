from __future__ import annotations

from datetime import datetime

_CEF_VERSION: str = "0"
_DEVICE_VENDOR: str = "AgentShield"
_DEVICE_PRODUCT: str = "AgentShield SDK"

_SEVERITY_MAP: dict[str, int] = {
    "INFO": 1,
    "LOW": 3,
    "MEDIUM": 5,
    "HIGH": 7,
    "CRITICAL": 10,
}
_THREAT_NAMES: dict[str, str] = {
    "PROMPT_INJECTION": "Prompt Injection Attack Detected",
    "GOAL_DRIFT": "Agent Goal Drift Detected",
    "TOOL_CHAIN_ESCALATION": "Tool Chain Escalation Detected",
    "MEMORY_POISONING": "Memory Poisoning Attempt Detected",
    "BEHAVIORAL_ANOMALY": "Behavioral Anomaly Detected",
    "INTER_AGENT_INJECTION": "Inter-Agent Injection Detected",
}
_SYSLOG_SEVERITY_MAP: dict[int, int] = {
    10: 2,
    7: 3,
    5: 4,
    3: 5,
    1: 6,
}
_FACILITY: int = 1


class CEFFormatter:
    """Formatter for AgentShield CEF and syslog message encoding."""

    @staticmethod
    def _escape(value: str) -> str:
        """Escape CEF header field separators.

        Args:
            value: Header value to escape.

        Returns:
            Escaped header value.
        """
        return value.replace("\\", "\\\\").replace("|", "\\|")

    @staticmethod
    def _escape_extension(value: str) -> str:
        """Escape CEF extension field values.

        Args:
            value: Extension value to escape.

        Returns:
            Escaped extension value.
        """
        return str(value).replace("\\", "\\\\").replace("=", "\\=").replace("|", "\\|")

    @staticmethod
    def format(
        agent_id: str,
        session_id: str,
        threat_type: str,
        severity: str,
        recommended_action: str,
        threat_score: float,
        canary_triggered: bool,
        timestamp_ms: int,
        version: str,
    ) -> str:
        """Format a threat event as a CEF log line.

        Args:
            agent_id: Agent identifier.
            session_id: Session identifier.
            threat_type: Threat type value.
            severity: AgentShield severity value.
            recommended_action: Recommended policy action.
            threat_score: Threat confidence score.
            canary_triggered: Canary-trigger status.
            timestamp_ms: Event timestamp in epoch milliseconds.
            version: AgentShield version string.

        Returns:
            Complete CEF-formatted line.
        """
        normalized_severity = severity.upper()
        cef_severity = 10 if canary_triggered else _SEVERITY_MAP.get(normalized_severity, 5)
        name = _THREAT_NAMES.get(threat_type, threat_type)

        extensions = (
            f"src={CEFFormatter._escape_extension(agent_id)} "
            f"suid={CEFFormatter._escape_extension(session_id)} "
            f"act={CEFFormatter._escape_extension(recommended_action)} "
            f"cs1={CEFFormatter._escape_extension(threat_type)} cs1Label=ThreatType "
            f"cs2={CEFFormatter._escape_extension(normalized_severity)} cs2Label=Severity "
            f"cfp1={threat_score:.4f} cfp1Label=ThreatScore "
            f"cs3={str(canary_triggered).lower()} cs3Label=CanaryTriggered "
            f"end={timestamp_ms}"
        )

        header = (
            f"CEF:{_CEF_VERSION}"
            f"|{CEFFormatter._escape(_DEVICE_VENDOR)}"
            f"|{CEFFormatter._escape(_DEVICE_PRODUCT)}"
            f"|{CEFFormatter._escape(version)}"
            f"|{CEFFormatter._escape(threat_type)}"
            f"|{CEFFormatter._escape(name)}"
            f"|{cef_severity}"
            f"|"
        )

        return header + extensions

    @staticmethod
    def to_syslog_bytes(cef_line: str, syslog_severity: int, hostname: str) -> bytes:
        """Wrap CEF in RFC-3164 syslog framing and encode to bytes.

        Args:
            cef_line: CEF payload line.
            syslog_severity: Syslog severity value.
            hostname: Hostname for syslog header.

        Returns:
            Encoded syslog message bytes, truncated for UDP safety when needed.
        """
        priority = (_FACILITY * 8) + syslog_severity
        timestamp = datetime.utcnow().strftime("%b %d %H:%M:%S")
        message = f"<{priority}>{timestamp} {hostname} agentshield: {cef_line}"

        encoded = message.encode("utf-8", errors="replace")
        if len(encoded) <= 65507:
            return encoded

        suffix = "..."
        max_payload_bytes = 65507 - len(suffix.encode("utf-8"))
        truncated = message

        while len(truncated.encode("utf-8", errors="replace")) > max_payload_bytes:
            truncated = truncated[:-1]

        return (truncated + suffix).encode("utf-8", errors="replace")
