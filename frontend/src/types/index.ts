// -- Enums ---------------------------------------------------------------

export type EventType =
  | "LLM_START"
  | "LLM_END"
  | "TOOL_CALL"
  | "TOOL_RESULT"
  | "MEMORY_READ"
  | "MEMORY_WRITE"
  | "SESSION_START"
  | "SESSION_END"
  | "THREAT_DETECTED"
  | "POLICY_VIOLATION"
  | "AGENT_COMMUNICATION"
  | "CANARY_INJECTED"
  | "CANARY_TRIGGERED"
  | "PROVENANCE_TAGGED";

export type SeverityLevel = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type ThreatType =
  | "PROMPT_INJECTION"
  | "GOAL_DRIFT"
  | "TOOL_CHAIN_ESCALATION"
  | "MEMORY_POISONING"
  | "BEHAVIORAL_ANOMALY"
  | "INTER_AGENT_INJECTION";

export type RecommendedAction = "BLOCK" | "FLAG" | "ALERT" | "LOG_ONLY";

export type TrustLevel = "TRUSTED" | "INTERNAL" | "EXTERNAL" | "UNTRUSTED";

export type PolicyAction = "BLOCK" | "ALERT" | "FLAG" | "LOG" | "ALLOW";

// -- Base Event ----------------------------------------------------------

export interface BaseEvent {
  event_id: string;
  event_type: EventType;
  agent_id: string;
  session_id: string;
  timestamp: string;
  severity: SeverityLevel;
  metadata: Record<string, unknown>;
}

// -- Specialized Events --------------------------------------------------

export interface ThreatEvent extends BaseEvent {
  event_type: "THREAT_DETECTED";
  threat_type: ThreatType;
  confidence: number;
  recommended_action: RecommendedAction;
  description: string;
  affected_component: string;
  canary_triggered: boolean;
}

export interface ToolCallEvent extends BaseEvent {
  event_type: "TOOL_CALL";
  tool_name: string;
  tool_input_hash: string;
  trust_level: TrustLevel;
}

export interface LLMEvent extends BaseEvent {
  event_type: "LLM_START" | "LLM_END";
  prompt_hash: string;
  trust_level: TrustLevel;
  token_count?: number;
}

export interface SessionEvent extends BaseEvent {
  event_type: "SESSION_START" | "SESSION_END";
  tool_calls_count: number;
  llm_calls_count: number;
  threats_detected: number;
  duration_seconds?: number;
}

export type AnyEvent =
  | ThreatEvent
  | ToolCallEvent
  | LLMEvent
  | SessionEvent
  | BaseEvent;

// -- Agent Node (for graph) ---------------------------------------------

export type AgentStatus = "clean" | "suspicious" | "compromised" | "unknown";

export interface AgentNode {
  agent_id: string;
  status: AgentStatus;
  trust_level: TrustLevel;
  session_count: number;
  threat_count: number;
  last_seen: string;
}

export interface AgentEdge {
  source_agent_id: string;
  target_agent_id: string;
  message_count: number;
  last_trust_level: TrustLevel;
}

// -- Alert ---------------------------------------------------------------

export interface Alert {
  alert_id: string;
  threat_event: ThreatEvent;
  acknowledged: boolean;
  acknowledged_at?: string;
}

// -- REST API response types --------------------------------------------

export interface StatsResponse {
  total_events: number;
  threat_count: number;
  blocked_count: number;
  active_sessions: number;
  agents_monitored: number;
}

export interface EventsResponse {
  events: AnyEvent[];
  total: number;
  offset: number;
  limit: number;
}

// -- WebSocket message ---------------------------------------------------

export type WSMessageType = "event" | "connected" | "ping" | "error";

export interface WSMessage {
  type: WSMessageType;
  data?: AnyEvent;
  message?: string;
  timestamp?: string;
}