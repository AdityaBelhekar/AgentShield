"""Report models and serialization helpers for red team runs."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError

from agentshield.cli.runner import AttackOutcome, AttackResult
from agentshield.exceptions import AgentShieldError


class RedTeamReport(BaseModel):
    """Full red team run report.

    Attributes:
        version: Report schema version, always "1.0".
        agent_module: Import path of the agent under test.
        policy: Policy applied during the run.
        run_timestamp: ISO 8601 UTC timestamp of run start.
        total_attacks: Total attacks attempted.
        detected_count: Attacks that raised PolicyViolationError.
        bypassed_count: Attacks that completed without detection.
        simulated_count: Attacks that were simulation-only.
        error_count: Attacks that raised unexpected exceptions.
        detection_rate_pct: detected / (total - simulated) * 100,
            rounded to 2 decimal places.
        results: Per-attack results.
    """

    model_config = ConfigDict(frozen=True)

    version: str = "1.0"
    agent_module: str
    policy: str
    run_timestamp: str
    total_attacks: int
    detected_count: int
    bypassed_count: int
    simulated_count: int
    error_count: int
    detection_rate_pct: float
    results: list[AttackResult]


class ReportBuilder:
    """Builds a RedTeamReport from a list of AttackResults.

    Args:
        agent_module: Import path used during the run.
        policy: Policy name used during the run.
        run_timestamp: ISO 8601 UTC string for when the run started.
    """

    _agent_module: str
    _policy: str
    _run_timestamp: str

    def __init__(
        self,
        agent_module: str,
        policy: str,
        run_timestamp: str,
    ) -> None:
        """Initialize report builder.

        Args:
            agent_module: Import path used for target agent factory.
            policy: Policy used for the run.
            run_timestamp: Run start timestamp in ISO format.
        """
        self._agent_module = agent_module
        self._policy = policy
        self._run_timestamp = run_timestamp

    def build(self, results: list[AttackResult]) -> RedTeamReport:
        """Construct and return a RedTeamReport from results.

        Args:
            results: Per-attack results from the runner.

        Returns:
            Aggregated red team report.
        """
        total_attacks = len(results)
        detected_count = self._count_outcome(results, AttackOutcome.DETECTED)
        bypassed_count = self._count_outcome(results, AttackOutcome.BYPASSED)
        simulated_count = self._count_outcome(results, AttackOutcome.SIMULATED)
        error_count = self._count_outcome(results, AttackOutcome.ERROR)

        live_attacks = total_attacks - simulated_count
        if live_attacks <= 0:
            detection_rate_pct = 0.0
        else:
            detection_rate_pct = round((detected_count / live_attacks) * 100.0, 2)

        return RedTeamReport(
            agent_module=self._agent_module,
            policy=self._policy,
            run_timestamp=self._run_timestamp,
            total_attacks=total_attacks,
            detected_count=detected_count,
            bypassed_count=bypassed_count,
            simulated_count=simulated_count,
            error_count=error_count,
            detection_rate_pct=detection_rate_pct,
            results=results,
        )

    @staticmethod
    def _count_outcome(results: list[AttackResult], outcome: AttackOutcome) -> int:
        """Count result rows that match one outcome.

        Args:
            results: Results to count.
            outcome: Outcome value to match.

        Returns:
            Count of rows with the matching outcome.
        """
        return sum(1 for item in results if item.outcome == outcome)


class ReportSerializer:
    """Handles JSON serialization of RedTeamReport."""

    @staticmethod
    def to_json(report: RedTeamReport, indent: int = 2) -> str:
        """Serialize report to a JSON string.

        Args:
            report: Report model to serialize.
            indent: Pretty-print indentation.

        Returns:
            JSON string representation.
        """
        return report.model_dump_json(indent=indent)

    @staticmethod
    def save(report: RedTeamReport, path: Path) -> None:
        """Write report JSON to a file path.

        Args:
            report: Report to persist.
            path: Destination JSON file path.

        Raises:
            AgentShieldError: If the file cannot be written.
        """
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            json_payload = ReportSerializer.to_json(report)
            path.write_text(f"{json_payload}\n", encoding="utf-8")
        except OSError as exc:
            raise AgentShieldError(f"Failed to write report to '{path}': {exc}") from exc

    @staticmethod
    def load(path: Path) -> RedTeamReport:
        """Load and validate a RedTeamReport from a JSON file.

        Args:
            path: Source report file path.

        Returns:
            Parsed and validated report.

        Raises:
            AgentShieldError: If read fails or validation fails.
        """
        try:
            payload = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise AgentShieldError(f"Failed to read report '{path}': {exc}") from exc

        try:
            return RedTeamReport.model_validate_json(payload)
        except ValidationError as exc:
            raise AgentShieldError(f"Invalid report format in '{path}': {exc}") from exc
