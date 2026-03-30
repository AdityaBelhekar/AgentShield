from __future__ import annotations

import hashlib
import json
from datetime import datetime

from pydantic import BaseModel, Field

from agentshield.events.models import BaseEvent
from agentshield.exceptions import AuditChainError


class ChainedAuditEntry(BaseModel):
    """Single entry in the cryptographic audit chain.

    Attributes:
        sequence_number: Monotonically increasing sequence number.
        event_id: UUID of the source event.
        event_type: Event type value string.
        agent_id: Agent identifier from the source event.
        session_id: Session identifier from the source event.
        timestamp: Event timestamp.
        event_payload_hash: SHA-256 hash of canonical event JSON payload.
        prev_chain_hash: Chain hash of the previous entry.
        chain_hash: SHA-256 hash of prev_chain_hash + event_payload_hash.
        severity: Event severity value string.
    """

    sequence_number: int = Field(..., ge=0)
    event_id: str = Field(...)
    event_type: str = Field(...)
    agent_id: str = Field(...)
    session_id: str = Field(...)
    timestamp: datetime = Field(...)
    event_payload_hash: str = Field(...)
    prev_chain_hash: str = Field(default="GENESIS")
    chain_hash: str = Field(...)
    severity: str = Field(...)

    @classmethod
    def compute_chain_hash(cls, prev_chain_hash: str, event_payload_hash: str) -> str:
        """Compute SHA-256 of concatenated prev_chain_hash + event_payload_hash.

        Args:
            prev_chain_hash: Chain hash from the previous entry.
            event_payload_hash: SHA-256 hash of the current event payload.

        Returns:
            Deterministic SHA-256 hex digest for this chain entry.

        Raises:
            AuditChainError: If hash computation fails.
        """
        try:
            payload = f"{prev_chain_hash}{event_payload_hash}".encode()
            return hashlib.sha256(payload).hexdigest()
        except Exception as exc:  # pragma: no cover - defensive guard
            raise AuditChainError(f"Failed to compute chain hash: {exc}") from exc

    @classmethod
    def compute_payload_hash(cls, event: BaseEvent) -> str:
        """Compute SHA-256 of the event serialized as sorted-key JSON.

        Args:
            event: Source event to hash.

        Returns:
            Deterministic SHA-256 hex digest of the canonical event payload.

        Raises:
            AuditChainError: If payload serialization or hashing fails.
        """
        try:
            raw_json = event.model_dump_json()
            canonical_json = json.dumps(
                json.loads(raw_json),
                sort_keys=True,
                separators=(",", ":"),
            )
            return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
        except Exception as exc:  # pragma: no cover - defensive guard
            raise AuditChainError(
                f"Failed to compute event payload hash: {exc}"
            ) from exc
