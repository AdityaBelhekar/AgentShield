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

## [0.1.0] — In Development

### Phase 0 — Project Foundation
- Professional repo scaffold with all submodule stubs
- AgentShieldConfig: full Pydantic Settings config system
- Exception hierarchy: 18 typed exceptions across 2 categories
- Tooling: ruff, black, mypy strict, pytest, docker-compose
- SECURITY.md: vulnerability reporting policy