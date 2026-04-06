import { useShieldStore } from "../store/useShieldStore";
import type {
  AgentNode,
  AnyEvent,
  EventType,
  RecommendedAction,
  SeverityLevel,
  ThreatEvent,
  ThreatType,
  TrustLevel,
  WSMessage,
} from "../types";

type RawWsEvent = Record<string, unknown>;

const EVENT_TYPE_MAP: Record<string, EventType> = {
  SESSION_START: "SESSION_START",
  SESSION_END: "SESSION_END",
  TOOL_CALL_START: "TOOL_CALL",
  TOOL_CALL_COMPLETE: "TOOL_CALL",
  TOOL_CALL_BLOCKED: "TOOL_CALL",
  LLM_PROMPT: "LLM_START",
  LLM_RESPONSE: "LLM_END",
  CHAIN_START: "AGENT_COMMUNICATION",
  CHAIN_END: "AGENT_COMMUNICATION",
  MEMORY_READ: "MEMORY_READ",
  MEMORY_WRITE: "MEMORY_WRITE",
  THREAT_DETECTED: "THREAT_DETECTED",
  THREAT_CLEARED: "AGENT_COMMUNICATION",
  POLICY_VIOLATION: "POLICY_VIOLATION",
  CANARY_INJECTED: "CANARY_INJECTED",
  CANARY_TRIGGERED: "CANARY_TRIGGERED",
  PROVENANCE_TAGGED: "PROVENANCE_TAGGED",
};

const TRUST_LEVEL_VALUES: TrustLevel[] = ["TRUSTED", "INTERNAL", "EXTERNAL", "UNTRUSTED"];
const SEVERITY_VALUES: SeverityLevel[] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const THREAT_TYPE_VALUES: ThreatType[] = [
  "PROMPT_INJECTION",
  "GOAL_DRIFT",
  "TOOL_CHAIN_ESCALATION",
  "MEMORY_POISONING",
  "BEHAVIORAL_ANOMALY",
  "INTER_AGENT_INJECTION",
];
const RECOMMENDED_ACTION_VALUES: RecommendedAction[] = ["BLOCK", "FLAG", "ALERT", "LOG_ONLY"];

const isThreatEvent = (event: AnyEvent): event is ThreatEvent =>
  event.event_type === "THREAT_DETECTED";

const isSessionBoundaryEvent = (event: AnyEvent): boolean =>
  event.event_type === "SESSION_START" || event.event_type === "SESSION_END";

const isTrustLevel = (value: unknown): value is TrustLevel =>
  typeof value === "string" && TRUST_LEVEL_VALUES.includes(value as TrustLevel);

const isSeverityLevel = (value: unknown): value is SeverityLevel =>
  typeof value === "string" && SEVERITY_VALUES.includes(value as SeverityLevel);

const isThreatType = (value: unknown): value is ThreatType =>
  typeof value === "string" && THREAT_TYPE_VALUES.includes(value as ThreatType);

const isRecommendedAction = (value: unknown): value is RecommendedAction =>
  typeof value === "string" && RECOMMENDED_ACTION_VALUES.includes(value as RecommendedAction);

const isRawWsEvent = (value: unknown): value is RawWsEvent =>
  typeof value === "object" && value !== null;

const asString = (value: unknown): string | null =>
  typeof value === "string" && value.length > 0 ? value : null;

const asNumber = (value: unknown): number | null =>
  typeof value === "number" && Number.isFinite(value) ? value : null;

const asBoolean = (value: unknown): boolean | null => (typeof value === "boolean" ? value : null);

const asRecord = (value: unknown): Record<string, unknown> =>
  typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};

const mapEventType = (value: string): EventType | null => {
  if (value in EVENT_TYPE_MAP) {
    return EVENT_TYPE_MAP[value];
  }

  if (value === "AGENT_COMMUNICATION") {
    return value;
  }

  return null;
};

const normalizeWsEvent = (input: unknown): AnyEvent | null => {
  if (!isRawWsEvent(input)) {
    return null;
  }

  const metadata = asRecord(input.metadata);
  const eventId = asString(input.event_id) ?? asString(input.id);
  const rawType = asString(input.event_type);
  const agentId = asString(input.agent_id);
  const sessionId = asString(input.session_id);
  const timestamp = asString(input.timestamp);
  const severity: SeverityLevel = isSeverityLevel(input.severity) ? input.severity : "INFO";

  if (!eventId || !rawType || !agentId || !sessionId || !timestamp) {
    return null;
  }

  const mappedType = mapEventType(rawType);
  if (!mappedType) {
    return null;
  }

  const baseEvent: AnyEvent = {
    event_id: eventId,
    event_type: mappedType,
    agent_id: agentId,
    session_id: sessionId,
    timestamp,
    severity,
    metadata,
  };

  if (mappedType !== "THREAT_DETECTED") {
    return baseEvent;
  }

  const threatType = isThreatType(input.threat_type)
    ? input.threat_type
    : isThreatType(metadata.threat_type)
      ? metadata.threat_type
      : "BEHAVIORAL_ANOMALY";

  const recommendedAction = isRecommendedAction(input.recommended_action)
    ? input.recommended_action
    : isRecommendedAction(metadata.recommended_action)
      ? metadata.recommended_action
      : "ALERT";

  const confidenceRaw = asNumber(input.confidence) ?? asNumber(metadata.confidence) ?? 0.5;
  const confidence = Math.max(0, Math.min(confidenceRaw, 1));

  const description =
    asString(input.description) ??
    asString(input.explanation) ??
    asString(metadata.description) ??
    asString(metadata.explanation) ??
    "Threat detected";

  const affectedComponent =
    asString(input.affected_component) ?? asString(metadata.affected_component) ?? "agent-runtime";

  const canaryTriggered = asBoolean(input.canary_triggered) ?? asBoolean(metadata.canary_triggered) ?? false;

  const threatEvent: ThreatEvent = {
    ...baseEvent,
    event_type: "THREAT_DETECTED",
    threat_type: threatType,
    confidence,
    recommended_action: recommendedAction,
    description,
    affected_component: affectedComponent,
    canary_triggered: canaryTriggered,
  };

  return threatEvent;
};

const applyIncomingEvent = (event: AnyEvent): void => {
  const store = useShieldStore.getState();
  const alreadyExists = store.events.some((existing) => existing.event_id === event.event_id);
  if (alreadyExists) {
    return;
  }

  store.addEvent(event);

  if (isThreatEvent(event)) {
    const alertExists = store.alerts.some((alert) => alert.threat_event.event_id === event.event_id);
    if (!alertExists) {
      store.addAlert({
        alert_id: crypto.randomUUID(),
        threat_event: event,
        acknowledged: false,
      });
    }
  }

  if (isSessionBoundaryEvent(event)) {
    const existing = store.agents[event.agent_id];
    const trustCandidate = event.metadata["trust_level"];
    const trustLevel = isTrustLevel(trustCandidate) ? trustCandidate : existing?.trust_level ?? "INTERNAL";

    const nextAgent: AgentNode = {
      agent_id: event.agent_id,
      status: existing?.status ?? "unknown",
      trust_level: trustLevel,
      session_count: (existing?.session_count ?? 0) + (event.event_type === "SESSION_START" ? 1 : 0),
      threat_count: existing?.threat_count ?? 0,
      last_seen: event.timestamp,
    };

    store.upsertAgent(nextAgent);
  }
};

class WSManager {
  private ws: WebSocket | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private reconnectDelay = 2000;
  private maxDelay = 30000;
  private readonly url: string;
  private shouldReconnect = true;

  constructor(url: string) {
    this.url = url;
  }

  connect(): void {
    this.shouldReconnect = true;

    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    this.ws = new WebSocket(this.url);
    this.ws.onopen = () => this.onOpen();
    this.ws.onmessage = (event) => {
      if (typeof event.data === "string") {
        this.onMessage(event.data);
        return;
      }

      useShieldStore.getState().setWsError("Received non-text WebSocket payload.");
    };
    this.ws.onclose = () => this.onClose();
    this.ws.onerror = () => this.onError();
  }

  disconnect(): void {
    this.shouldReconnect = false;

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.ws) {
      this.ws.onopen = null;
      this.ws.onmessage = null;
      this.ws.onclose = null;
      this.ws.onerror = null;
      this.ws.close();
      this.ws = null;
    }

    useShieldStore.getState().setWsConnected(false);
  }

  private onOpen(): void {
    const store = useShieldStore.getState();
    store.setWsConnected(true);
    store.setWsError(null);
    this.reconnectDelay = 2000;
  }

  private onMessage(raw: string): void {
    let message: WSMessage;

    try {
      message = JSON.parse(raw) as WSMessage;
    } catch {
      useShieldStore.getState().setWsError("Failed to parse WebSocket message.");
      return;
    }

    const store = useShieldStore.getState();

    switch (message.type) {
      case "connected":
        store.setWsConnected(true);
        store.setWsError(null);
        break;
      case "history": {
        if (!Array.isArray(message.events)) {
          return;
        }

        const normalized = message.events
          .map((entry) => normalizeWsEvent(entry))
          .filter((entry): entry is AnyEvent => entry !== null);

        normalized.reverse().forEach((event) => {
          applyIncomingEvent(event);
        });
        break;
      }
      case "event": {
        const event = normalizeWsEvent(message.data);
        if (!event) {
          return;
        }

        applyIncomingEvent(event);

        break;
      }
      case "ping":
        break;
      case "error":
        store.setWsError(message.message ?? "WebSocket error received.");
        break;
      default:
        break;
    }
  }

  private onClose(): void {
    this.ws = null;
    useShieldStore.getState().setWsConnected(false);
    this.scheduleReconnect();
  }

  private onError(): void {
    useShieldStore.getState().setWsError("WebSocket connection error.");
  }

  private scheduleReconnect(): void {
    if (!this.shouldReconnect || this.reconnectTimer) {
      return;
    }

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
      this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxDelay);
    }, this.reconnectDelay);
  }
}

export const wsManager = new WSManager(
  import.meta.env.VITE_WS_URL ?? "ws://localhost:8000/ws/events",
);