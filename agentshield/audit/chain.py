from __future__ import annotations

import asyncio
import threading
from pathlib import Path

from loguru import logger

from agentshield.audit.models import ChainedAuditEntry
from agentshield.config import AgentShieldConfig
from agentshield.events.models import BaseEvent
from agentshield.exceptions import AuditChainError


class AuditChainStore:
    """Append-only cryptographic audit chain store.

    Maintains an in-memory list of ChainedAuditEntry objects and optionally
    persists each entry to JSONL. Appends are protected with both async and
    sync locks so callers can safely use async and sync paths.
    """

    _entries: list[ChainedAuditEntry]
    _persist_path: Path | None
    _async_lock: asyncio.Lock
    _sync_lock: threading.Lock
    _max_memory_entries: int
    _next_sequence_number: int

    def __init__(
        self,
        persist_path: Path | None = None,
        *,
        max_memory_entries: int | None = None,
    ) -> None:
        """Initialize the audit chain store.

        Args:
            persist_path: Optional JSONL path for persistence.
            max_memory_entries: Optional in-memory retention limit.
                If omitted, AgentShieldConfig.audit_chain_max_memory_entries
                is used.

        Raises:
            AuditChainError: If max_memory_entries is not positive.
        """
        config = AgentShieldConfig()

        resolved_path = persist_path
        if resolved_path is None and config.audit_chain_path is not None:
            resolved_path = config.audit_chain_path

        resolved_max_entries = max_memory_entries
        if resolved_max_entries is None:
            resolved_max_entries = config.audit_chain_max_memory_entries

        if resolved_max_entries <= 0:
            raise AuditChainError("audit_chain_max_memory_entries must be positive")

        self._entries = []
        self._persist_path = resolved_path
        self._async_lock = asyncio.Lock()
        self._sync_lock = threading.Lock()
        self._max_memory_entries = resolved_max_entries
        self._next_sequence_number = 0

        logger.debug(
            "AuditChainStore initialized | persist_path={} max_memory_entries={}",
            self._persist_path,
            self._max_memory_entries,
        )

    @property
    def chain_length(self) -> int:
        """Return the current in-memory chain length."""
        with self._sync_lock:
            return len(self._entries)

    @property
    def last_hash(self) -> str:
        """Return the hash of the most recent entry, or GENESIS if empty."""
        with self._sync_lock:
            if not self._entries:
                return "GENESIS"
            return self._entries[-1].chain_hash

    @property
    def is_empty(self) -> bool:
        """Return True if there are no entries in memory."""
        with self._sync_lock:
            return not self._entries

    async def append(self, event: BaseEvent) -> ChainedAuditEntry:
        """Build and append a ChainedAuditEntry for the given event.

        Args:
            event: Source event to append.

        Returns:
            Newly appended chained audit entry.

        Raises:
            AuditChainError: If hashing or persistence fails.
        """
        async with self._async_lock:
            with self._sync_lock:
                return self._append_locked(event)

    def append_sync(self, event: BaseEvent) -> ChainedAuditEntry:
        """Synchronously build and append a ChainedAuditEntry.

        Args:
            event: Source event to append.

        Returns:
            Newly appended chained audit entry.

        Raises:
            AuditChainError: If hashing or persistence fails.
        """
        with self._sync_lock:
            return self._append_locked(event)

    def get_entry(self, sequence_number: int) -> ChainedAuditEntry:
        """Get a single entry by sequence number.

        Args:
            sequence_number: Sequence number of the requested entry.

        Returns:
            Matching chained audit entry.

        Raises:
            AuditChainError: If no entry with that sequence number exists.
        """
        with self._sync_lock:
            for entry in self._entries:
                if entry.sequence_number == sequence_number:
                    return entry

        raise AuditChainError(
            f"Audit chain entry not found for sequence_number={sequence_number}"
        )

    def get_all_entries(self) -> list[ChainedAuditEntry]:
        """Return a shallow copy of all current in-memory entries."""
        with self._sync_lock:
            return list(self._entries)

    def get_entries_by_session(self, session_id: str) -> list[ChainedAuditEntry]:
        """Return all in-memory entries for a given session.

        Args:
            session_id: Session identifier to filter by.

        Returns:
            Matching entries in insertion order.
        """
        with self._sync_lock:
            return [entry for entry in self._entries if entry.session_id == session_id]

    def get_entries_by_agent(self, agent_id: str) -> list[ChainedAuditEntry]:
        """Return all in-memory entries for a given agent.

        Args:
            agent_id: Agent identifier to filter by.

        Returns:
            Matching entries in insertion order.
        """
        with self._sync_lock:
            return [entry for entry in self._entries if entry.agent_id == agent_id]

    def _append_locked(self, event: BaseEvent) -> ChainedAuditEntry:
        """Append a new entry while holding the sync lock.

        Args:
            event: Source event to append.

        Returns:
            Newly appended chained audit entry.

        Raises:
            AuditChainError: If hashing or persistence fails.
        """
        try:
            sequence_number = self._next_sequence_number
            prev_chain_hash = (
                self._entries[-1].chain_hash if self._entries else "GENESIS"
            )
            event_payload_hash = ChainedAuditEntry.compute_payload_hash(event)
            chain_hash = ChainedAuditEntry.compute_chain_hash(
                prev_chain_hash,
                event_payload_hash,
            )

            entry = ChainedAuditEntry(
                sequence_number=sequence_number,
                event_id=str(event.id),
                event_type=event.event_type.value,
                agent_id=event.agent_id,
                session_id=str(event.session_id),
                timestamp=event.timestamp,
                event_payload_hash=event_payload_hash,
                prev_chain_hash=prev_chain_hash,
                chain_hash=chain_hash,
                severity=event.severity.value,
            )

            self._entries.append(entry)
            self._next_sequence_number += 1
            self._trim_locked()
            self._persist_locked(entry)
            return entry
        except AuditChainError:
            raise
        except Exception as exc:
            raise AuditChainError(f"Failed to append audit chain entry: {exc}") from exc

    def _trim_locked(self) -> None:
        """Trim in-memory entries to retention limit while holding lock."""
        overflow = len(self._entries) - self._max_memory_entries
        if overflow > 0:
            del self._entries[:overflow]

    def _persist_locked(self, entry: ChainedAuditEntry) -> None:
        """Persist one entry to JSONL while holding lock.

        Args:
            entry: Entry to persist.

        Raises:
            AuditChainError: If file persistence fails.
        """
        if self._persist_path is None:
            return

        try:
            self._persist_path.parent.mkdir(parents=True, exist_ok=True)
            with self._persist_path.open("a", encoding="utf-8") as file_handle:
                file_handle.write(entry.model_dump_json())
                file_handle.write("\n")
        except OSError as exc:
            raise AuditChainError(
                f"Failed to persist audit chain entry to {self._persist_path}: {exc}"
            ) from exc
