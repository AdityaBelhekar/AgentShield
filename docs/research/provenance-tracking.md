# Prompt Provenance Tracking

## 1. The Problem

In agent pipelines, model context is composed from many sources, but most systems lose source trust information before inference. Without provenance, dangerous content can blend into trusted instructions and evade policy intent.

## 2. How AgentShield Solves It

AgentShield tags content entering context with trust metadata and emits provenance events for every tagged artifact. Detection and inter-agent monitoring then use trust levels to prioritize and escalate suspicious paths.

## 3. Technical Detail

- Core class: `ProvenanceTracker`
- Trust levels: `TRUSTED`, `INTERNAL`, `EXTERNAL`, `UNTRUSTED`
- Source classification:
  - user-origin prompt segments -> `TRUSTED`
  - memory reads -> `INTERNAL`
  - known internal tools -> `INTERNAL`
  - generic external tools -> `EXTERNAL`
  - URL-bearing or unknown content -> `UNTRUSTED`
- URL detection regex includes `http(s)` and `www.` patterns
- Stored representation uses `content_hash` (SHA-256), not raw content

## 4. Code Example

```python
from uuid import uuid4

from agentshield.config import AgentShieldConfig
from agentshield.provenance.tracker import ProvenanceTracker

tracker = ProvenanceTracker(AgentShieldConfig())
session_id = uuid4()
tracker.initialize_session(session_id)

# During runtime, pass BaseEvent objects to tracker.process_event(event)
# to produce PROVENANCE_TAGGED events with trust metadata.
```

## 5. Limitations and Future Work

- Provenance quality depends on event completeness from adapters/interceptors.
- Complex derived content can require segment-level trust splitting.
- Future work includes graph-level provenance replay and policy-native trust predicates.