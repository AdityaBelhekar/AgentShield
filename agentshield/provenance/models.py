from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from agentshield.events.models import TrustLevel


@dataclass
class ContentRecord:
    """Provenance record for a single piece of content.

    Tracks where content came from, how much to trust it,
    and metadata about its origin. Created by ProvenanceTracker
    whenever new content enters the agent's context.

    The content itself is NEVER stored - only its hash.
    This prevents the provenance system from becoming
    a secondary leakage surface.

    Attributes:
        content_hash: SHA-256 hash of the content string.
            Used to identify content without storing it.
        trust_level: How much to trust this content.
        source_type: Category of source (user/tool/memory/web).
        source_tool: Tool name if content came from a tool.
        source_url: URL if content came from web scraping.
        session_id: Session this content appeared in.
        created_at: UTC timestamp when content was tagged.
        metadata: Additional source metadata.
        flagged: Whether this content was flagged suspicious.
        flag_reason: Why it was flagged if flagged=True.
    """

    content_hash: str
    trust_level: TrustLevel
    source_type: str
    session_id: uuid.UUID
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    source_tool: str | None = None
    source_url: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    flagged: bool = False
    flag_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize record to dictionary for audit logging.

        Returns:
            Dictionary with all non-sensitive fields.
        """
        return {
            "content_hash": self.content_hash,
            "trust_level": self.trust_level.value,
            "source_type": self.source_type,
            "source_tool": self.source_tool,
            "source_url": self.source_url,
            "session_id": str(self.session_id),
            "created_at": self.created_at.isoformat(),
            "flagged": self.flagged,
            "flag_reason": self.flag_reason,
        }


@dataclass
class ProvenanceContext:
    """Per-session provenance state maintained by ProvenanceTracker.

    Holds all ContentRecords for a session and provides
    lookup methods for the DetectionEngine.

    Attributes:
        session_id: UUID of the session.
        records: All ContentRecords keyed by content_hash.
        tool_trust_overrides: Per-tool trust level overrides.
            Allows declaring specific tools as TRUSTED or
            UNTRUSTED regardless of default classification.
        untrusted_content_count: Count of UNTRUSTED items seen.
        flagged_count: Count of flagged content items.
    """

    session_id: uuid.UUID
    records: dict[str, ContentRecord] = field(default_factory=dict)
    tool_trust_overrides: dict[str, TrustLevel] = field(default_factory=dict)
    untrusted_content_count: int = 0
    flagged_count: int = 0

    def get_trust_level(self, content_hash: str) -> TrustLevel | None:
        """Look up the trust level for a piece of content by hash.

        Args:
            content_hash: SHA-256 hash of the content.

        Returns:
            TrustLevel if content is known, None if unseen.
        """
        record = self.records.get(content_hash)
        return record.trust_level if record else None

    def get_record(self, content_hash: str) -> ContentRecord | None:
        """Look up the full ContentRecord for a content hash.

        Args:
            content_hash: SHA-256 hash of the content.

        Returns:
            ContentRecord if found, None if unseen.
        """
        return self.records.get(content_hash)

    def has_untrusted_content(self) -> bool:
        """Whether any UNTRUSTED content has been seen this session.

        Returns:
            True if any UNTRUSTED ContentRecord exists.
        """
        return self.untrusted_content_count > 0

    def get_untrusted_records(self) -> list[ContentRecord]:
        """Return all ContentRecords with UNTRUSTED trust level.

        Returns:
            List of UNTRUSTED ContentRecords.
        """
        return [
            record for record in self.records.values() if record.trust_level == TrustLevel.UNTRUSTED
        ]


def hash_content(content: str) -> str:
    """Compute SHA-256 hash of content string.

    Used to identify content without storing it.
    All ContentRecords store only the hash.

    Args:
        content: The content string to hash.

    Returns:
        Lowercase hex SHA-256 digest string.
    """
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
