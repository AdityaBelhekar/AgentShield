import { useMemo } from "react";
import { useShieldStore } from "../../store/useShieldStore";
import type { AnyEvent, LLMEvent, SessionEvent, ThreatEvent, ToolCallEvent } from "../../types";

interface TraceField {
  label: string;
  value: string;
}

const isThreatEvent = (event: AnyEvent): event is ThreatEvent =>
  event.event_type === "THREAT_DETECTED" && "description" in event;

const isToolCallEvent = (event: AnyEvent): event is ToolCallEvent =>
  event.event_type === "TOOL_CALL" && "tool_name" in event;

const isLlmEvent = (event: AnyEvent): event is LLMEvent =>
  (event.event_type === "LLM_START" || event.event_type === "LLM_END") && "prompt_hash" in event;

const isSessionEvent = (event: AnyEvent): event is SessionEvent =>
  (event.event_type === "SESSION_START" || event.event_type === "SESSION_END") &&
  "tool_calls_count" in event;

const asText = (value: unknown): string => {
  if (value === null || value === undefined) {
    return "-";
  }

  if (typeof value === "string") {
    return value;
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }

  return JSON.stringify(value);
};

const getTraceFields = (event: AnyEvent): TraceField[] => {
  const baseFields: TraceField[] = [
    { label: "Event ID", value: event.event_id },
    { label: "Type", value: event.event_type },
    { label: "Agent", value: event.agent_id },
    { label: "Session", value: event.session_id },
    { label: "Severity", value: event.severity },
    { label: "Timestamp", value: new Date(event.timestamp).toLocaleString() },
  ];

  if (isThreatEvent(event)) {
    return [
      ...baseFields,
      { label: "Threat", value: event.threat_type },
      { label: "Confidence", value: event.confidence.toFixed(2) },
      { label: "Action", value: event.recommended_action },
      { label: "Component", value: event.affected_component },
      { label: "Canary", value: event.canary_triggered ? "triggered" : "clear" },
    ];
  }

  if (isToolCallEvent(event)) {
    return [
      ...baseFields,
      { label: "Tool", value: event.tool_name },
      { label: "Input Hash", value: event.tool_input_hash },
      { label: "Trust", value: event.trust_level },
    ];
  }

  if (isLlmEvent(event)) {
    return [
      ...baseFields,
      { label: "Prompt Hash", value: event.prompt_hash },
      { label: "Trust", value: event.trust_level },
      {
        label: "Token Count",
        value: event.token_count !== undefined ? String(event.token_count) : "-",
      },
    ];
  }

  if (isSessionEvent(event)) {
    return [
      ...baseFields,
      { label: "Tool Calls", value: String(event.tool_calls_count) },
      { label: "LLM Calls", value: String(event.llm_calls_count) },
      { label: "Threats", value: String(event.threats_detected) },
      {
        label: "Duration",
        value: event.duration_seconds !== undefined ? `${event.duration_seconds}s` : "-",
      },
    ];
  }

  return baseFields;
};

export function ForensicTrace(): JSX.Element {
  const events = useShieldStore((state) => state.events);
  const selectedEventId = useShieldStore((state) => state.selectedEventId);
  const setSelectedEvent = useShieldStore((state) => state.setSelectedEvent);

  const selectedEvent = useMemo(() => {
    if (!selectedEventId) {
      return null;
    }

    return events.find((event) => event.event_id === selectedEventId) ?? null;
  }, [events, selectedEventId]);

  const fields = useMemo(() => {
    if (!selectedEvent) {
      return [];
    }

    return getTraceFields(selectedEvent);
  }, [selectedEvent]);

  return (
    <aside className={`forensic-panel ${selectedEvent !== null ? "open" : ""}`.trim()}>
      <div className="h-full border-t border-shield-border bg-[#0b1120]/95 shadow-2xl backdrop-blur-sm">
        <div className="flex h-full flex-col">
          <header className="flex items-center justify-between border-b border-shield-border px-4 py-2">
            <div>
              <h3 className="text-sm font-medium text-gray-200">Forensic Trace</h3>
              <p className="text-xs text-gray-500">
                {selectedEvent
                  ? `${selectedEvent.event_type} - ${selectedEvent.agent_id.slice(0, 12)}`
                  : "Select an event to inspect forensic details"}
              </p>
            </div>

            <button
              type="button"
              onClick={() => {
                setSelectedEvent(null);
              }}
              className="rounded border border-gray-600 bg-gray-900 px-2 py-1 text-xs text-gray-200 transition hover:border-cyan-500"
            >
              Close
            </button>
          </header>

          <div className="grid flex-1 grid-cols-2 gap-4 overflow-hidden p-4">
            <section className="overflow-y-auto rounded border border-shield-border bg-[#090f1c] p-3 [&::-webkit-scrollbar-track]:bg-transparent [&::-webkit-scrollbar-thumb]:bg-gray-700 [&::-webkit-scrollbar]:w-1">
              {selectedEvent ? (
                <dl className="grid grid-cols-[130px_1fr] gap-x-3 gap-y-2 text-sm">
                  {fields.map((field) => (
                    <div key={field.label} className="contents">
                      <dt className="text-gray-500">
                        {field.label}
                      </dt>
                      <dd className="truncate font-mono text-xs text-gray-200" title={field.value}>
                        {field.value}
                      </dd>
                    </div>
                  ))}
                </dl>
              ) : (
                <div className="flex h-full items-center justify-center text-sm text-gray-500">
                  No event selected
                </div>
              )}
            </section>

            <section className="overflow-y-auto rounded border border-shield-border bg-[#090f1c] p-3 [&::-webkit-scrollbar-track]:bg-transparent [&::-webkit-scrollbar-thumb]:bg-gray-700 [&::-webkit-scrollbar]:w-1">
              <h4 className="mb-2 text-xs uppercase tracking-wide text-gray-500">Metadata</h4>
              <pre className="whitespace-pre-wrap break-words text-xs text-gray-300">
                {selectedEvent ? JSON.stringify(selectedEvent.metadata, null, 2) : "{}"}
              </pre>
              {selectedEvent && isThreatEvent(selectedEvent) ? (
                <div className="mt-3 rounded border border-red-900/60 bg-red-950/40 p-2 text-xs text-red-200">
                  {asText(selectedEvent.description)}
                </div>
              ) : null}
            </section>
          </div>
        </div>
      </div>
    </aside>
  );
}