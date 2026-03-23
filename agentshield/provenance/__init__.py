"""AgentShield prompt provenance tracking.

Tags every piece of content entering the LLM context
with its origin and trust level. Enables trust-aware
detection - untrusted content gets extra scrutiny.

Public API:
        ProvenanceTracker  : main tracker class
        ContentRecord      : single content provenance record
        ProvenanceContext  : per-session provenance state
        hash_content       : SHA-256 content hashing utility
"""

from agentshield.provenance.models import (
    ContentRecord,
    ProvenanceContext,
    hash_content,
)
from agentshield.provenance.tracker import ProvenanceTracker

__all__ = [
    "ContentRecord",
    "ProvenanceContext",
    "ProvenanceTracker",
    "hash_content",
]
