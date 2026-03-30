from __future__ import annotations

from dataclasses import dataclass

from loguru import logger

from agentshield.audit.chain import AuditChainStore
from agentshield.audit.models import ChainedAuditEntry
from agentshield.exceptions import AuditChainError


@dataclass
class VerificationResult:
    """Result of a full chain verification pass.

    Attributes:
        is_valid: Whether verification passed.
        total_entries: Total number of entries examined.
        first_broken_sequence: First sequence number where validation failed.
        broken_entry: Entry that failed validation, if any.
        error_message: Human-readable validation error if failed.
    """

    is_valid: bool
    total_entries: int
    first_broken_sequence: int | None
    broken_entry: ChainedAuditEntry | None
    error_message: str | None


class AuditChainVerifier:
    """Verifies integrity of an AuditChainStore."""

    def verify(self, store: AuditChainStore) -> VerificationResult:
        """Run full linear chain verification.

        Args:
            store: Audit chain store to verify.

        Returns:
            VerificationResult for the full in-memory chain.
        """
        try:
            entries = store.get_all_entries()
            result = self._verify_entries(
                entries=entries,
                start_sequence=0,
                verify_start_anchor=True,
            )
            self._log_result(result)
            return result
        except Exception as exc:  # pragma: no cover - defensive guard
            result = VerificationResult(
                is_valid=False,
                total_entries=0,
                first_broken_sequence=None,
                broken_entry=None,
                error_message=f"Verification failed unexpectedly: {exc}",
            )
            logger.warning(
                "Audit chain verification failed unexpectedly | error={}", exc
            )
            return result

    def verify_range(
        self,
        store: AuditChainStore,
        start: int,
        end: int,
    ) -> VerificationResult:
        """Verify only entries[start:end+1].

        The first entry in the range is not anchored against any prior entry
        unless start == 0. This is useful for spot checks.

        Args:
            store: Audit chain store to verify.
            start: Inclusive start index.
            end: Inclusive end index.

        Returns:
            VerificationResult for the selected range.

        Raises:
            AuditChainError: If indices are out of bounds.
        """
        entries = store.get_all_entries()
        if not entries:
            raise AuditChainError("Cannot verify range on an empty audit chain")

        if start < 0 or end < 0:
            raise AuditChainError("start and end must be non-negative")
        if start > end:
            raise AuditChainError("start must be less than or equal to end")
        if start >= len(entries) or end >= len(entries):
            raise AuditChainError(
                f"Range [{start}, {end}] out of bounds for chain length {len(entries)}"
            )

        subset = entries[start : end + 1]
        result = self._verify_entries(
            entries=subset,
            start_sequence=start,
            verify_start_anchor=(start == 0),
        )
        self._log_result(result)
        return result

    def _verify_entries(
        self,
        entries: list[ChainedAuditEntry],
        start_sequence: int,
        verify_start_anchor: bool,
    ) -> VerificationResult:
        """Verify an ordered list of chained entries.

        Args:
            entries: Entries to verify in sequence order.
            start_sequence: Expected sequence number for entries[0].
            verify_start_anchor: Whether to validate GENESIS anchor.

        Returns:
            VerificationResult for the provided entries.
        """
        if not entries:
            return VerificationResult(
                is_valid=True,
                total_entries=0,
                first_broken_sequence=None,
                broken_entry=None,
                error_message=None,
            )

        for index, entry in enumerate(entries):
            expected_sequence = start_sequence + index

            if entry.sequence_number != expected_sequence:
                return VerificationResult(
                    is_valid=False,
                    total_entries=len(entries),
                    first_broken_sequence=expected_sequence,
                    broken_entry=entry,
                    error_message=(
                        f"Expected sequence_number={expected_sequence}, "
                        f"got {entry.sequence_number}"
                    ),
                )

            if not self._is_sha256_hex(entry.event_payload_hash):
                return VerificationResult(
                    is_valid=False,
                    total_entries=len(entries),
                    first_broken_sequence=expected_sequence,
                    broken_entry=entry,
                    error_message="Invalid event_payload_hash format",
                )

            if not self._is_sha256_hex(entry.chain_hash):
                return VerificationResult(
                    is_valid=False,
                    total_entries=len(entries),
                    first_broken_sequence=expected_sequence,
                    broken_entry=entry,
                    error_message="Invalid chain_hash format",
                )

            if index == 0:
                if verify_start_anchor and entry.prev_chain_hash != "GENESIS":
                    return VerificationResult(
                        is_valid=False,
                        total_entries=len(entries),
                        first_broken_sequence=expected_sequence,
                        broken_entry=entry,
                        error_message=("First entry must be anchored to GENESIS"),
                    )
            else:
                prior_entry = entries[index - 1]
                if entry.prev_chain_hash != prior_entry.chain_hash:
                    return VerificationResult(
                        is_valid=False,
                        total_entries=len(entries),
                        first_broken_sequence=expected_sequence,
                        broken_entry=entry,
                        error_message=(
                            "prev_chain_hash does not match previous chain_hash"
                        ),
                    )

            expected_chain_hash = ChainedAuditEntry.compute_chain_hash(
                entry.prev_chain_hash,
                entry.event_payload_hash,
            )
            if entry.chain_hash != expected_chain_hash:
                return VerificationResult(
                    is_valid=False,
                    total_entries=len(entries),
                    first_broken_sequence=expected_sequence,
                    broken_entry=entry,
                    error_message="chain_hash does not match recomputed hash",
                )

        return VerificationResult(
            is_valid=True,
            total_entries=len(entries),
            first_broken_sequence=None,
            broken_entry=None,
            error_message=None,
        )

    def _is_sha256_hex(self, value: str) -> bool:
        """Check whether a value is a valid SHA-256 hex digest.

        Args:
            value: Candidate hex string.

        Returns:
            True if the value is a 64-char lowercase/uppercase hex digest.
        """
        if len(value) != 64:
            return False
        return all(char in "0123456789abcdefABCDEF" for char in value)

    def _log_result(self, result: VerificationResult) -> None:
        """Log verification result with INFO or WARNING severity.

        Args:
            result: Verification result to log.
        """
        if result.is_valid:
            logger.info(
                "Audit chain verification passed | entries={}",
                result.total_entries,
            )
            return

        logger.warning(
            "Audit chain verification failed | entries={} first_broken_sequence={} error={}",
            result.total_entries,
            result.first_broken_sequence,
            result.error_message,
        )
