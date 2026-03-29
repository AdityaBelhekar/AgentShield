import { useCallback, useEffect, useState } from "react";
import { useShieldStore } from "../../store/useShieldStore";

interface DemoAction {
  id: string;
  label: string;
  description: string;
  path: string;
}

interface EventStoreStats {
  total_events: number;
  total_threats: number;
  total_sessions: number;
  store_capacity: number;
}

const STATS_REFRESH_MS = 10_000;

const DEMO_ACTIONS: DemoAction[] = [
  {
    id: "clean",
    label: "Clean Workflow",
    description: "Inject a benign end-to-end agent run.",
    path: "/api/demo/scenario/clean",
  },
  {
    id: "injection",
    label: "Prompt Injection",
    description: "Inject a scenario with active instruction override attempts.",
    path: "/api/demo/scenario/injection",
  },
  {
    id: "exfiltration",
    label: "Exfiltration Chain",
    description: "Inject a staged read and outbound transfer escalation attempt.",
    path: "/api/demo/scenario/exfiltration",
  },
  {
    id: "threat",
    label: "Threat Pulse",
    description: "Inject a high-severity synthetic threat event.",
    path: "/api/demo/event/threat",
  },
  {
    id: "blocked",
    label: "Blocked Tool Call",
    description: "Inject a blocked action to validate policy enforcement flow.",
    path: "/api/demo/event/blocked",
  },
  {
    id: "memory",
    label: "Memory Mutation",
    description: "Inject a synthetic memory write event.",
    path: "/api/demo/event/memory",
  },
];

const API_BASE = (import.meta.env.VITE_API_URL ?? "").replace(/\/$/, "");

const buildApiUrl = (path: string): string => `${API_BASE}${path}`;

const isObjectRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;

const isEventStoreStats = (value: unknown): value is EventStoreStats => {
  if (!isObjectRecord(value)) {
    return false;
  }

  return (
    typeof value.total_events === "number" &&
    typeof value.total_threats === "number" &&
    typeof value.total_sessions === "number" &&
    typeof value.store_capacity === "number"
  );
};

const getErrorDetail = (value: unknown): string | null => {
  if (!isObjectRecord(value)) {
    return null;
  }

  const detail = value.detail;
  if (typeof detail === "string") {
    return detail;
  }

  return null;
};

const parseResponseBody = async (response: Response): Promise<unknown> => {
  const bodyText = await response.text();
  if (bodyText.length === 0) {
    return null;
  }

  try {
    return JSON.parse(bodyText) as unknown;
  } catch {
    return bodyText;
  }
};

export function DemoControlPanel(): JSX.Element {
  const setStats = useShieldStore((state) => state.setStats);
  const setWsError = useShieldStore((state) => state.setWsError);

  const [stats, setLocalStats] = useState<EventStoreStats | null>(null);
  const [runningActionId, setRunningActionId] = useState<string | null>(null);
  const [isFireAllRunning, setIsFireAllRunning] = useState(false);
  const [isResetting, setIsResetting] = useState(false);
  const [lastRefreshAt, setLastRefreshAt] = useState<string>("--:--:--");
  const [statusMessage, setStatusMessage] = useState<string>("Ready");

  const refreshStats = useCallback(async (): Promise<void> => {
    try {
      const response = await fetch(buildApiUrl("/api/events/stats"));
      const payload = await parseResponseBody(response);

      if (!response.ok) {
        throw new Error(getErrorDetail(payload) ?? "Failed to fetch stats.");
      }

      if (!isEventStoreStats(payload)) {
        throw new Error("Unexpected stats payload from backend.");
      }

      setLocalStats(payload);
      setLastRefreshAt(new Date().toLocaleTimeString());
      setStats({
        total_events: payload.total_events,
        threat_count: payload.total_threats,
        blocked_count: 0,
        active_sessions: payload.total_sessions,
        agents_monitored: Object.keys(useShieldStore.getState().agents).length,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Failed to refresh stats.";
      setWsError(message);
      setStatusMessage(`Stats error: ${message}`);
    }
  }, [setStats, setWsError]);

  const runDemoAction = useCallback(
    async (action: DemoAction): Promise<boolean> => {
      setRunningActionId(action.id);
      setStatusMessage(`Running ${action.label}...`);

      try {
        const response = await fetch(buildApiUrl(action.path), { method: "POST" });
        const payload = await parseResponseBody(response);

        if (!response.ok) {
          throw new Error(getErrorDetail(payload) ?? `Failed to run ${action.label}.`);
        }

        setStatusMessage(`${action.label} completed.`);
        await refreshStats();
        return true;
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : `Failed to run ${action.label}.`;
        setWsError(message);
        setStatusMessage(`${action.label} failed: ${message}`);
        return false;
      } finally {
        setRunningActionId(null);
      }
    },
    [refreshStats, setWsError],
  );

  const handleFireAll = useCallback(async (): Promise<void> => {
    setIsFireAllRunning(true);
    let succeeded = 0;

    for (const action of DEMO_ACTIONS) {
      const ok = await runDemoAction(action);
      if (ok) {
        succeeded += 1;
      }
    }

    setStatusMessage(`Fire All complete (${succeeded}/${DEMO_ACTIONS.length})`);
    setIsFireAllRunning(false);
  }, [runDemoAction]);

  const handleReset = useCallback(async (): Promise<void> => {
    setIsResetting(true);

    try {
      const response = await fetch(buildApiUrl("/api/demo/reset"), { method: "POST" });
      const payload = await parseResponseBody(response);

      if (!response.ok) {
        throw new Error(getErrorDetail(payload) ?? "Failed to reset demo state.");
      }

      setStatusMessage("Demo state reset.");
      await refreshStats();
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Failed to reset demo state.";
      setWsError(message);
      setStatusMessage(`Reset failed: ${message}`);
    } finally {
      setIsResetting(false);
    }
  }, [refreshStats, setWsError]);

  useEffect(() => {
    void refreshStats();

    const timer = setInterval(() => {
      void refreshStats();
    }, STATS_REFRESH_MS);

    return () => {
      clearInterval(timer);
    };
  }, [refreshStats]);

  return (
    <aside className="flex h-full w-full flex-col bg-shield-bg">
      <header className="border-b border-shield-border px-4 py-3">
        <h2 className="text-sm font-semibold tracking-wide text-cyan-400">Demo Controls</h2>
        <p className="mt-1 text-xs text-gray-500">Trigger synthetic events and attack scenarios.</p>
      </header>

      <div className="grid grid-cols-2 gap-2 border-b border-shield-border px-4 py-3 text-xs">
        <div className="rounded border border-shield-border bg-shield-surface px-2 py-1">
          <div className="text-gray-500">events</div>
          <div className="font-mono text-gray-200">{stats?.total_events ?? 0}</div>
        </div>
        <div className="rounded border border-shield-border bg-shield-surface px-2 py-1">
          <div className="text-gray-500">threats</div>
          <div className="font-mono text-gray-200">{stats?.total_threats ?? 0}</div>
        </div>
        <div className="rounded border border-shield-border bg-shield-surface px-2 py-1">
          <div className="text-gray-500">sessions</div>
          <div className="font-mono text-gray-200">{stats?.total_sessions ?? 0}</div>
        </div>
        <div className="rounded border border-shield-border bg-shield-surface px-2 py-1">
          <div className="text-gray-500">capacity</div>
          <div className="font-mono text-gray-200">{stats?.store_capacity ?? 0}</div>
        </div>
      </div>

      <div className="border-b border-shield-border px-4 py-2 text-[11px] text-gray-500">
        Refreshes every 10s - last update {lastRefreshAt}
      </div>

      <div className="flex-1 overflow-y-auto px-4 py-3 [&::-webkit-scrollbar-track]:bg-transparent [&::-webkit-scrollbar-thumb]:bg-gray-700 [&::-webkit-scrollbar]:w-1">
        <div className="space-y-2">
          {DEMO_ACTIONS.map((action) => {
            const isRunning = runningActionId === action.id;

            return (
              <div key={action.id} className="rounded border border-shield-border bg-shield-surface p-2">
                <div className="flex items-center justify-between gap-2">
                  <h3 className="text-xs font-semibold text-gray-200">{action.label}</h3>
                  <button
                    type="button"
                    className="rounded border border-gray-600 bg-gray-900 px-2 py-1 text-xs text-gray-200 transition hover:border-cyan-500 disabled:cursor-not-allowed disabled:opacity-60"
                    disabled={isFireAllRunning || isRunning || isResetting}
                    onClick={() => {
                      void runDemoAction(action);
                    }}
                  >
                    {isRunning ? "Running..." : "Run"}
                  </button>
                </div>
                <p className="mt-1 text-xs text-gray-500">{action.description}</p>
              </div>
            );
          })}
        </div>
      </div>

      <footer className="space-y-2 border-t border-shield-border px-4 py-3">
        <div className="grid grid-cols-2 gap-2">
          <button
            type="button"
            className="rounded border border-cyan-700 bg-cyan-950 px-3 py-2 text-xs font-semibold text-cyan-300 transition hover:border-cyan-500 disabled:cursor-not-allowed disabled:opacity-60"
            disabled={isFireAllRunning || isResetting}
            onClick={() => {
              void handleFireAll();
            }}
          >
            {isFireAllRunning ? "Running all..." : "Fire All"}
          </button>

          <button
            type="button"
            className="rounded border border-red-800 bg-red-950 px-3 py-2 text-xs font-semibold text-red-300 transition hover:border-red-600 disabled:cursor-not-allowed disabled:opacity-60"
            disabled={isResetting || isFireAllRunning}
            onClick={() => {
              void handleReset();
            }}
          >
            {isResetting ? "Resetting..." : "Reset"}
          </button>
        </div>

        <div className="truncate text-xs text-gray-500" title={statusMessage}>
          {statusMessage}
        </div>
      </footer>
    </aside>
  );
}