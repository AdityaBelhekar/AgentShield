# Cryptographic Audit Trail

## 1. The Problem

Standard logs are mutable and can be altered after an incident, which weakens forensic confidence and compliance reporting. Security teams need tamper-evident event history with deterministic verification.

## 2. How AgentShield Solves It

AgentShield writes every emitted security event into an append-only hash chain (`AuditChainStore`). Each entry references the previous chain hash, so any mutation breaks verification.

## 3. Technical Detail

### Hash-Chain Structure

For entry $n$:

$$
\text{event\_payload\_hash}_n = \mathrm{SHA256}(\text{canonical event JSON})
$$

$$
\text{chain\_hash}_n = \mathrm{SHA256}(\text{prev\_chain\_hash}_{n-1} + \text{event\_payload\_hash}_n)
$$

Entry `0` anchors to `GENESIS`.

### JSONL Export Format

```json
# AgentShield Audit Chain Export | entries=3 | valid=true
{"sequence_number":0,"event_id":"...","event_type":"SESSION_START","prev_chain_hash":"GENESIS","chain_hash":"..."}
{"sequence_number":1,"event_id":"...","event_type":"LLM_PROMPT","prev_chain_hash":"...","chain_hash":"..."}
{"sequence_number":2,"event_id":"...","event_type":"THREAT_DETECTED","prev_chain_hash":"...","chain_hash":"..."}
```

## 4. Code Example

```python
from pathlib import Path

from agentshield.runtime import AgentShieldRuntime
from agentshield.config import AgentShieldConfig

runtime = AgentShieldRuntime(AgentShieldConfig(audit_chain_enabled=True))

# ... run protected sessions ...

verification = runtime.verify_audit_chain()
print(verification.is_valid)
runtime.export_audit_chain(Path("audit-chain.jsonl"), format="jsonl")
```

## 5. Limitations and Future Work

- In-memory retention limits can evict old entries unless persistent export is configured.
- Verification protects integrity, not confidentiality; pair with access controls.
- Future work includes remote attestations and signed chain checkpoints.

## Tamper Detection

`AuditChainVerifier` recomputes linkage and payload hashes across entries. Any mismatch reports `is_valid=False`, plus the first broken sequence index and an error reason, giving immediate forensic locality.