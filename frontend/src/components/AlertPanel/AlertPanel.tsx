import { useMemo, useState } from "react";
import { useShieldStore } from "../../store/useShieldStore";
import type { Alert, SeverityLevel, ThreatType } from "../../types";

interface AlertPanelProps {
  maxHeight?: string;
  className?: string;
}

const SEVERITY_COLORS: Record<SeverityLevel, string> = {
  INFO: "bg-gray-700 text-gray-300",
  LOW: "bg-blue-900 text-blue-300",
  MEDIUM: "bg-yellow-900 text-yellow-300",
  HIGH: "bg-orange-900 text-orange-300",
  CRITICAL: "bg-red-900 text-red-300",
};

const THREAT_LABELS: Record<ThreatType, string> = {
  PROMPT_INJECTION: "INJ",
  GOAL_DRIFT: "DRIFT",
  TOOL_CHAIN_ESCALATION: "ESC",
  MEMORY_POISONING: "MEM",
  BEHAVIORAL_ANOMALY: "DNA",
  INTER_AGENT_INJECTION: "IAI",
};

const BADGE_BASE_CLASSES = "text-xs px-1.5 py-0.5 rounded font-mono font-medium";

const formatTimestamp = (iso: string): string => {
  const eventTime = new Date(iso).getTime();
  if (Number.isNaN(eventTime)) {
    return "unknown time";
  }

  const diffSeconds = Math.floor((Date.now() - eventTime) / 1000);
  if (diffSeconds < 60) {
    return "just now";
  }

  if (diffSeconds < 3600) {
    return `${Math.floor(diffSeconds / 60)}m ago`;
  }

  return new Date(iso).toLocaleTimeString();
};

const sortAlerts = (alerts: Alert[]): Alert[] =>
  [...alerts].sort((a, b) => {
    if (a.acknowledged !== b.acknowledged) {
      return a.acknowledged ? 1 : -1;
    }

    return (
      new Date(b.threat_event.timestamp).getTime() - new Date(a.threat_event.timestamp).getTime()
    );
  });

export function AlertPanel({
  maxHeight = "400px",
  className = "",
}: AlertPanelProps): JSX.Element {
  const alerts = useShieldStore((state) => state.alerts);
  const acknowledgeAlert = useShieldStore((state) => state.acknowledgeAlert);
  const [filterSeverity, setFilterSeverity] = useState<SeverityLevel | "ALL">("ALL");
  const [showAcked, setShowAcked] = useState(true);

  const unacknowledgedCount = useMemo(
    () => alerts.filter((alert) => !alert.acknowledged).length,
    [alerts],
  );

  const displayed = useMemo(() => {
    return sortAlerts(
      alerts
        .filter((alert) => (showAcked ? true : !alert.acknowledged))
        .filter((alert) =>
          filterSeverity === "ALL" ? true : alert.threat_event.severity === filterSeverity,
        ),
    );
  }, [alerts, filterSeverity, showAcked]);

  return (
    <section
      className={`flex w-full flex-col overflow-hidden rounded-md border border-shield-border bg-shield-bg ${className}`}
    >
      <header className="flex items-center gap-3 border-b border-shield-border px-3 py-2">
        <div className="flex items-center gap-2">
          <h2 className="text-sm font-medium text-gray-300">Alerts</h2>
          {unacknowledgedCount > 0 ? (
            <span className="inline-flex items-center gap-1 rounded-full border border-red-700 bg-red-950 px-2 py-0.5 text-xs text-red-300">
              <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
              {unacknowledgedCount}
            </span>
          ) : null}
        </div>

        <div className="ml-auto flex items-center gap-2">
          <select
            className="rounded border border-gray-700 bg-gray-900 px-2 py-1 text-xs text-gray-200 outline-none transition focus:border-cyan-500"
            value={filterSeverity}
            onChange={(event) => {
              setFilterSeverity(event.target.value as SeverityLevel | "ALL");
            }}
          >
            <option value="ALL">ALL</option>
            <option value="INFO">INFO</option>
            <option value="LOW">LOW</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="HIGH">HIGH</option>
            <option value="CRITICAL">CRITICAL</option>
          </select>

          <button
            type="button"
            className="rounded border border-gray-600 bg-gray-800 px-2 py-1 text-xs text-gray-200 transition hover:border-cyan-500"
            onClick={() => {
              setShowAcked((previous) => !previous);
            }}
          >
            {showAcked ? "Clear acked" : "Show acked"}
          </button>
        </div>
      </header>

      <div
        className="flex-1 overflow-y-auto [&::-webkit-scrollbar-track]:bg-transparent [&::-webkit-scrollbar-thumb]:bg-gray-700 [&::-webkit-scrollbar]:w-1"
        style={{ maxHeight }}
      >
        {displayed.length === 0 ? (
          <div className="flex h-full min-h-24 items-center justify-center px-3 py-8">
            <p className="text-sm text-gray-500">No threats detected in this session.</p>
          </div>
        ) : (
          displayed.map((alert) => (
            <article
              key={alert.alert_id}
              className="flex items-start gap-3 border-b border-shield-border px-3 py-3"
            >
              <div className="min-w-0 flex-1 space-y-1">
                <div className="flex items-center gap-1.5">
                  <span
                    className={`${BADGE_BASE_CLASSES} border border-gray-600 bg-gray-800 text-cyan-400`}
                  >
                    {THREAT_LABELS[alert.threat_event.threat_type]}
                  </span>
                  <span
                    className={`${BADGE_BASE_CLASSES} ${SEVERITY_COLORS[alert.threat_event.severity]}`}
                  >
                    {alert.threat_event.severity}
                  </span>
                  <span className="truncate text-xs text-gray-400">
                    {alert.threat_event.agent_id}
                  </span>
                </div>

                <p
                  className="overflow-hidden text-sm text-gray-200"
                  style={{
                    display: "-webkit-box",
                    WebkitBoxOrient: "vertical",
                    WebkitLineClamp: 2,
                  }}
                >
                  {alert.threat_event.description}
                </p>

                <p className="text-xs text-gray-500">
                  {formatTimestamp(alert.threat_event.timestamp)}
                </p>
              </div>

              <div className="shrink-0">
                {!alert.acknowledged ? (
                  <button
                    type="button"
                    className="rounded border border-gray-600 bg-gray-800 px-2 py-1 text-xs text-gray-200 transition hover:border-cyan-500"
                    onClick={() => {
                      acknowledgeAlert(alert.alert_id);
                    }}
                  >
                    Ack
                  </button>
                ) : (
                  <span className="text-xs text-gray-600">✓ acked</span>
                )}
              </div>
            </article>
          ))
        )}
      </div>
    </section>
  );
}