import { create } from "zustand";
import type {
  AgentEdge,
  AgentNode,
  Alert,
  AnyEvent,
  SeverityLevel,
  StatsResponse,
  ThreatType,
} from "../types";

interface ShieldState {
  wsConnected: boolean;
  wsError: string | null;
  events: AnyEvent[];
  agents: Record<string, AgentNode>;
  edges: AgentEdge[];
  alerts: Alert[];
  stats: StatsResponse | null;
  selectedAgentId: string | null;
  selectedEventId: string | null;
  filterSeverity: SeverityLevel | "ALL";
  filterThreatType: ThreatType | "ALL";
  setWsConnected: (v: boolean) => void;
  setWsError: (e: string | null) => void;
  addEvent: (event: AnyEvent) => void;
  upsertAgent: (agent: AgentNode) => void;
  addEdge: (edge: AgentEdge) => void;
  addAlert: (alert: Alert) => void;
  acknowledgeAlert: (alert_id: string) => void;
  setStats: (stats: StatsResponse) => void;
  setSelectedAgent: (id: string | null) => void;
  setSelectedEvent: (id: string | null) => void;
  setFilterSeverity: (s: SeverityLevel | "ALL") => void;
  setFilterThreatType: (t: ThreatType | "ALL") => void;
  clearEvents: () => void;
}

const MAX_EVENTS = 500;

export const useShieldStore = create<ShieldState>((set) => ({
  wsConnected: false,
  wsError: null,
  events: [],
  agents: {},
  edges: [],
  alerts: [],
  stats: null,
  selectedAgentId: null,
  selectedEventId: null,
  filterSeverity: "ALL",
  filterThreatType: "ALL",

  setWsConnected: (v) => set({ wsConnected: v }),
  setWsError: (e) => set({ wsError: e }),

  addEvent: (event) =>
    set((state) => ({
      events: [event, ...state.events].slice(0, MAX_EVENTS),
    })),

  upsertAgent: (agent) =>
    set((state) => ({
      agents: {
        ...state.agents,
        [agent.agent_id]: agent,
      },
    })),

  addEdge: (edge) =>
    set((state) => ({
      edges: [edge, ...state.edges],
    })),

  addAlert: (alert) =>
    set((state) => ({
      alerts: [alert, ...state.alerts],
    })),

  acknowledgeAlert: (alert_id) =>
    set((state) => ({
      alerts: state.alerts.map((alert) =>
        alert.alert_id === alert_id
          ? {
              ...alert,
              acknowledged: true,
              acknowledged_at: new Date().toISOString(),
            }
          : alert,
      ),
    })),

  setStats: (stats) => set({ stats }),
  setSelectedAgent: (id) => set({ selectedAgentId: id }),
  setSelectedEvent: (id) => set({ selectedEventId: id }),
  setFilterSeverity: (s) => set({ filterSeverity: s }),
  setFilterThreatType: (t) => set({ filterThreatType: t }),
  clearEvents: () => set({ events: [] }),
}));