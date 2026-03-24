# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com).
Versions follow [Semantic Versioning](https://semver.org).

## [Unreleased]

### Pre-Phase 4 Fixes
- Fixed PolicyViolationError propagation in LLM/memory hooks
- Added EventType.CANARY_INJECTED, CANARY_TRIGGERED,
	PROVENANCE_TAGGED values
- Mapped new event types to CanaryEvent/ProvenanceEvent
	in deserialize_event()

### Phase 4A — Prompt Provenance Tracker
- `ProvenanceTracker`: tags all content with trust level
- `ContentRecord`: provenance record (hash only, no raw content)
- `ProvenanceContext`: per-session provenance state
- `hash_content()`: SHA-256 content hashing utility
- Trust classification: TRUSTED/INTERNAL/EXTERNAL/UNTRUSTED
- URL detection in tool outputs -> UNTRUSTED classification
- Per-tool trust level overrides via tool_trust_overrides
- ProvenanceEvent emitted for every tagged content piece
- Integrated into DetectionEngine.process_event()
- DetectionEngine.get_trust_level() public API
- shield() accepts tool_trust_overrides parameter
- Original research: taint analysis for LLM agent contexts

### Phase 4B — Canary Injection System
- `CanarySystem`: honeypot token management
- `CanaryToken`: cryptographic token with safe serialization
- `CanarySessionState`: per-session token tracking
- `generate_canary_token()`: secrets.token_hex based generator
- `build_canary_instruction()`: context injection string
- Scans LLM_RESPONSE and TOOL_CALL_COMPLETE for echoes
- Canary trigger -> confidence=1.0, BLOCK, CRITICAL
- Bypasses correlation - canary triggers are immediate block
- Token rotation via canary_rotation_sessions config
- Historical token tracking for delayed echo detection
- get_canary_instruction() API for Phase 10 adapters
- Original research: active honeypot detection for LLM agents

### Phase 4C — Agent DNA Fingerprinting (Baseline)
- `SessionFeatureVector`: 13-feature behavioral vector per session
- `SessionObserver`: live event observer, extracts features
- `AgentBaseline`: statistical baseline (mean/std/min/max)
- `DNASystem`: orchestrates baseline collection
- Features: tool_call_count, unique_tools, tool_diversity,
	prompt_length stats, tool_velocity, session_duration,
	memory ops, response_length, llm_calls, chain_depth, threats
- Only clean sessions (zero threats) contribute to baseline
- Baseline established after dna_min_sessions (default 10)
- JSON persistence for baselines between runtime restarts
- get_zscore() on baseline for Phase 4D anomaly scoring
- Integrated into DetectionEngine session lifecycle

### Phase 4D — Agent DNA Anomaly Scoring
- `DNAAnomalyScorer`: scores sessions vs established baseline
- `AnomalyReport`: per-feature anomaly breakdown
- Composite score = weighted mean of z-score contributions
- Feature weights: threat_firings(3x), velocity/chain(2x),
	diversity/memory(1.5x), others(1x)
- Anomaly scored at session end with full feature vector
- BEHAVIORAL_ANOMALY threat type - FLAG/ALERT never BLOCK alone
- Correlation with other detectors required for BLOCK
- score_session() added to DNASystem
- DetectionEngine emits threat on anomalous session close
- Interpretable: anomalous_features list in evidence
- Original research: unsupervised behavioral anomaly detection

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

### Phase 1B - Event Emitter
- `EventEmitter.emit()`: sync publish with 3-retry backoff
- `EventEmitter.emit_async()`: async publish via redis.asyncio
- `EventEmitter.emit_batch()`: batched pipeline publish
- `EventEmitter.flush()`: clean shutdown with stats logging
- `EventEmitter.stats()`: emission statistics for monitoring
- Lazy Redis initialization - no connection at import time
- Graceful degradation - never raises to caller under any failure
- JSONL audit log - append-only, one parseable JSON per line
- Auto-creates log directory if it does not exist
- Exponential backoff: 1s -> 2s -> 4s between retry attempts

### Phase 2A — Base Interceptor + LLM Interceptor
- `BaseInterceptor`: abstract base with attach/detach/is_attached
- `BaseInterceptor._emit()`: safe emit wrapper, never raises
- `BaseInterceptor._make_base_kwargs()`: shared event constructor
- `LLMInterceptor`: hooks LangChain callback system
- `LLMInterceptor.on_llm_start()`: emits LLM_PROMPT event
- `LLMInterceptor.on_llm_end()`: emits LLM_RESPONSE with tokens
- `LLMInterceptor.on_llm_error()`: emits HIGH severity event
- `LLMInterceptor.on_chain_start()`: emits CHAIN_START event
- `LLMInterceptor.on_chain_end()`: emits CHAIN_END event
- `LLMInterceptor.on_chain_error()`: emits HIGH severity CHAIN_END
- Pending prompt storage by run_id for response correlation

### Phase 2B — Tool Interceptor
- `ToolInterceptor`: monkey-patches tool _run and _arun
- `ToolInterceptor.attach()`: patches all tools in list
- `ToolInterceptor.detach()`: restores all original methods
- `HookResult`: dataclass for pre-call hook return values
- `PatchedTool`: dataclass storing original methods per tool
- Pre-call hook system: blocks tool calls before execution
- Post-call hook system: analyzes tool output after execution
- TOOL_CALL_START emitted before every tool execution
- TOOL_CALL_COMPLETE emitted after with output + timing
- TOOL_CALL_BLOCKED emitted when pre-call hook blocks
- ToolCallBlockedError raised on block with full evidence
- execution_time_ms measured via time.monotonic()
- Async wrapper for _arun methods

### Phase 2C — Memory Interceptor + Runtime
- `MemoryInterceptor`: monkey-patches BaseMemory methods
- `MemoryInterceptor.attach()`: wraps save_context + load_memory_vars
- `MemoryInterceptor.detach()`: restores originals cleanly
- MEMORY_WRITE emitted before save_context execution
- MEMORY_READ emitted after load_memory_vars execution
- `AgentShieldRuntime`: session orchestrator
- `AgentShieldRuntime.wrap()`: creates session, attaches all interceptors
- `AgentShieldRuntime._close_session()`: SESSION_END + cleanup
- `WrappedAgent`: context manager with run() and invoke()
- `WrappedAgent.close()`: explicit cleanup without context manager
- `shield()`: 4-line public API, policy param ready for Phase 5
- SESSION_START emitted on wrap(), SESSION_END on close()

### Phase 3A — Base Detector + Detection Context
- `EmbeddingService`: lazy-loads sentence-transformers model
- `EmbeddingService.embed()`: single text embedding
- `EmbeddingService.embed_batch()`: batched embedding
- `EmbeddingService._detect_device()`: ROCm→CUDA→CPU fallback
- `DetectionContext`: session state dataclass for all detectors
- `BaseDetector`: abstract base with shared detection utilities
- `BaseDetector._build_threat()`: ThreatEvent constructor helper
- `BaseDetector._cosine_similarity()`: safe cosine similarity
- `BaseDetector._cosine_distance()`: 1 - cosine similarity
- `BaseDetector._compute_zscore()`: z-score for anomaly detection
- `BaseDetector._confidence_to_severity()`: confidence → severity
- `BaseDetector._confidence_to_action()`: confidence → action
- `supported_event_types` abstract property for routing

### Phase 3B — Prompt Injection Detector
- `PromptInjectionDetector`: 3-layer injection detection
- Layer 1: Pattern matching — 50+ injection signatures
- Layer 2: Semantic similarity against 10 injection templates
- Layer 3: Structural analysis — regex-based marker detection
- Lazy template embedding — computed once on first use
- Analyzes LLM_PROMPT and TOOL_CALL_COMPLETE events
- Confidence scoring: weighted combination of all 3 layers
- Evidence dict includes pattern matches + structural markers

### Phase 3C — Goal Drift Detector
- `GoalDriftDetector`: cosine distance drift detection
- Analyzes LLM_PROMPT events only
- Requires original_task_embedding in DetectionContext
- Rolling average smoothing over last 3 prompts
- Early session protection — no BLOCK before 2 prompts
- Thresholds: flag=0.35, block=0.55 (from AgentShieldConfig)
- Per-session drift history keyed by session_id
- `clear_session()`: frees memory when session closes
- Evidence includes full distance history for forensics

### Phase 3D — Tool Chain Escalation Detector
- `ToolChainDetector`: two-layer tool sequence detection
- 25+ forbidden sequence patterns across 6 attack categories
- Layer 1: suffix matching against FORBIDDEN_SEQUENCES
- Layer 2: heuristic category-based escalation scoring
- Tool categories: READ, WRITE, SEND, EXECUTE patterns
- Hooks into TOOL_CALL_START — blocks before execution
- No embedding dependency — pure structural analysis
- Confidence 0.95 on forbidden sequence match
- Evidence includes matched pattern and full call history

### Phase 3E — Memory Poison Detector
- `MemoryPoisonDetector`: 3-layer memory poisoning detection
- 35+ memory-specific poison patterns
- Layer 1: pattern matching on memory content
- Layer 2: semantic z-score anomaly vs session baseline
- Layer 3: content length anomaly detection
- Requires MIN_BASELINE_SIZE (3) writes before stat layers
- Analyzes MEMORY_WRITE events only
- Centroid-based distance computation for baseline
- Evidence includes z-scores, baseline size, pattern matches

### Phase 3F — Detection Engine
- `DetectionEngine`: orchestrates all 4 detectors
- `CorrelationResult`: cross-detector analysis result
- Cross-detector correlation rules implemented:
	- 1 detector: capped at ALERT, never BLOCK alone
	- 2 detectors: escalate FLAG→ALERT, ALERT→BLOCK
	- 3+ detectors: always BLOCK
	- canary_triggered: immediate BLOCK always
- Event routing table: O(1) lookup by EventType
- `initialize_session()`: embeds original task at start
- `process_event()`: routes, correlates, emits, raises
- `close_session()`: cleans up context + drift history
- `_update_context()`: tool history + memory embeddings
- `_raise_policy_violation()`: typed exception per threat
- `AgentShieldRuntime` wired to DetectionEngine
- `_make_pre_call_hook()`: bridges tool interceptor + engine
- Phase 3 COMPLETE - full detection pipeline operational

## [0.1.0] — In Development

### Phase 0 — Project Foundation
- Professional repo scaffold with all submodule stubs
- AgentShieldConfig: full Pydantic Settings config system
- Exception hierarchy: 18 typed exceptions across 2 categories
- Tooling: ruff, black, mypy strict, pytest, docker-compose
- SECURITY.md: vulnerability reporting policy