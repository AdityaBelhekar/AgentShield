import { useShieldStore } from "../store/useShieldStore";
import type { AgentNode, AnyEvent, ThreatEvent, TrustLevel, WSMessage } from "../types";

const TRUST_LEVEL_VALUES: TrustLevel[] = ["TRUSTED", "INTERNAL", "EXTERNAL", "UNTRUSTED"];

const isThreatEvent = (event: AnyEvent): event is ThreatEvent =>
  event.event_type === "THREAT_DETECTED";

const isSessionBoundaryEvent = (event: AnyEvent): boolean =>
  event.event_type === "SESSION_START" || event.event_type === "SESSION_END";

const isTrustLevel = (value: unknown): value is TrustLevel =>
  typeof value === "string" && TRUST_LEVEL_VALUES.includes(value as TrustLevel);

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
        break;
      case "event": {
        const event = message.data;
        if (!event) {
          return;
        }

        store.addEvent(event);

        if (isThreatEvent(event)) {
          store.addAlert({
            alert_id: crypto.randomUUID(),
            threat_event: event,
            acknowledged: false,
          });
        }

        if (isSessionBoundaryEvent(event)) {
          const latestState = useShieldStore.getState();
          const existing = latestState.agents[event.agent_id];
          const trustCandidate = event.metadata["trust_level"];
          const trustLevel = isTrustLevel(trustCandidate)
            ? trustCandidate
            : existing?.trust_level ?? "INTERNAL";

          const nextAgent: AgentNode = {
            agent_id: event.agent_id,
            status: existing?.status ?? "unknown",
            trust_level: trustLevel,
            session_count:
              (existing?.session_count ?? 0) + (event.event_type === "SESSION_START" ? 1 : 0),
            threat_count: existing?.threat_count ?? 0,
            last_seen: event.timestamp,
          };

          store.upsertAgent(nextAgent);
        }

        break;
      }
      case "ping":
        break;
      case "error":
        store.setWsError(message.message ?? "WebSocket error received.");
        break;
      default:
        store.setWsError("Received unknown WebSocket message type.");
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
  import.meta.env.VITE_WS_URL ?? "ws://localhost:8000/ws/dashboard",
);