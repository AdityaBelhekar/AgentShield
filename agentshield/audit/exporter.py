from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentshield.audit.chain import AuditChainStore
from agentshield.audit.models import ChainedAuditEntry
from agentshield.audit.verifier import AuditChainVerifier
from agentshield.config import AgentShieldConfig
from agentshield.exceptions import AuditChainError


class AuditChainExporter:
    """Exports AuditChainStore entries to file outputs.

    Exports include verification metadata so downstream consumers can
    quickly determine whether the chain was intact at export time.
    """

    _config: AgentShieldConfig
    _verifier: AuditChainVerifier

    def __init__(
        self,
        config: AgentShieldConfig | None = None,
        verifier: AuditChainVerifier | None = None,
    ) -> None:
        """Initialize the exporter.

        Args:
            config: Optional AgentShield configuration.
            verifier: Optional verifier instance.
        """
        self._config = config or AgentShieldConfig()
        self._verifier = verifier or AuditChainVerifier()

    def export_jsonl(
        self,
        store: AuditChainStore,
        output_path: Path,
        *,
        include_verification: bool = True,
    ) -> int:
        """Write entries as JSONL to output_path.

        Args:
            store: Audit chain store to export.
            output_path: Destination JSONL path.
            include_verification: Whether to prepend a header comment line.

        Returns:
            Number of entries written.

        Raises:
            AuditChainError: If file I/O fails.
        """
        entries = store.get_all_entries()
        verification = self._verifier.verify(store)

        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open("w", encoding="utf-8") as file_handle:
                if include_verification:
                    file_handle.write(
                        "# AgentShield Audit Chain Export | "
                        f"entries={len(entries)} | valid={verification.is_valid}\n"
                    )

                for entry in entries:
                    file_handle.write(entry.model_dump_json())
                    file_handle.write("\n")
        except OSError as exc:
            raise AuditChainError(f"Failed to export JSONL audit chain: {exc}") from exc

        return len(entries)

    def export_json_report(
        self,
        store: AuditChainStore,
        output_path: Path,
    ) -> dict[str, Any]:
        """Write a full JSON report for the complete chain.

        Args:
            store: Audit chain store to export.
            output_path: Destination JSON path.

        Returns:
            The report dictionary that was written to disk.

        Raises:
            AuditChainError: If file I/O or serialization fails.
        """
        entries = store.get_all_entries()
        verification = self._verifier.verify(store)

        report: dict[str, Any] = {
            "metadata": {
                "exported_at": datetime.now(UTC).isoformat(),
                "agentshield_version": self._config.agentshield_version,
                "chain_length": len(entries),
                "is_valid": verification.is_valid,
                "first_broken_sequence": verification.first_broken_sequence,
            },
            "entries": self._serialize_entries(entries),
        }

        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open("w", encoding="utf-8") as file_handle:
                json.dump(report, file_handle, indent=2, sort_keys=True)
                file_handle.write("\n")
        except (OSError, TypeError, ValueError) as exc:
            raise AuditChainError(f"Failed to export JSON audit report: {exc}") from exc

        return report

    def export_session_report(
        self,
        store: AuditChainStore,
        session_id: str,
        output_path: Path,
    ) -> dict[str, Any]:
        """Write a filtered JSON report for one session.

        Args:
            store: Audit chain store to export.
            session_id: Session identifier used to filter entries.
            output_path: Destination JSON path.

        Returns:
            The report dictionary that was written to disk.

        Raises:
            AuditChainError: If file I/O or serialization fails.
        """
        entries = store.get_entries_by_session(session_id)
        verification = self._verifier.verify(store)

        report: dict[str, Any] = {
            "metadata": {
                "exported_at": datetime.now(UTC).isoformat(),
                "agentshield_version": self._config.agentshield_version,
                "chain_length": len(entries),
                "is_valid": verification.is_valid,
                "first_broken_sequence": verification.first_broken_sequence,
                "session_id": session_id,
            },
            "entries": self._serialize_entries(entries),
        }

        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open("w", encoding="utf-8") as file_handle:
                json.dump(report, file_handle, indent=2, sort_keys=True)
                file_handle.write("\n")
        except (OSError, TypeError, ValueError) as exc:
            raise AuditChainError(
                f"Failed to export session audit report: {exc}"
            ) from exc

        return report

    def _serialize_entries(
        self,
        entries: list[ChainedAuditEntry],
    ) -> list[dict[str, Any]]:
        """Serialize chain entries to plain dictionaries.

        Args:
            entries: Entries to serialize.

        Returns:
            List of JSON-serializable dictionaries.
        """
        return [entry.model_dump(mode="json") for entry in entries]
