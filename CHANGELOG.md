# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com).
Versions follow [Semantic Versioning](https://semver.org).

## [Unreleased]

### Phase 1A - Event Models
- `EventType` enum: 14 event categories
- `SeverityLevel` enum: 5 severity levels
- `ThreatType` enum: 7 attack vectors including BEHAVIORAL_ANOMALY
- `RecommendedAction` enum: 4 response actions
- `TrustLevel` enum: 4 provenance trust levels (new in v2)
- `BaseEvent`: core event model with auto UUID + UTC timestamp
- `ToolCallEvent`: tool invocation with trust_level field
- `LLMEvent`: LLM prompt/response with prompt_trust_levels
- `MemoryEvent`: memory read/write with 200-char preview cap
- `ThreatEvent`: threat detection with canary_triggered field
- `SessionEvent`: session lifecycle with full metrics
- `CanaryEvent`: canary injection/trigger tracking (new in v2)
- `ProvenanceEvent`: content provenance tagging (new in v2)
- `AuditLog`: session aggregation with chain_hash placeholder
- `deserialize_event()`: type-safe routing utility

## [0.1.0] — In Development

### Phase 0 — Project Foundation
- Professional repo scaffold with all submodule stubs
- AgentShieldConfig: full Pydantic Settings config system
- Exception hierarchy: 18 typed exceptions across 2 categories
- Tooling: ruff, black, mypy strict, pytest, docker-compose
- SECURITY.md: vulnerability reporting policy