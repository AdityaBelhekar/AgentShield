import { useMemo } from "react";
import { useShieldStore } from "../../store/useShieldStore";
import type { AnyEvent, LLMEvent, SessionEvent, SeverityLevel, ThreatEvent, ToolCallEvent } from "../../types";

interface EventFeedProps {
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

const BADGE_BASE_CLASSES = "rounded px-1.5 py-0.5 text-xs font-mono font-medium";

const isThreatEvent = (event: AnyEvent): event is ThreatEvent =>
  event.event_type === "THREAT_DETECTED" && "description" in event;

const isToolCallEvent = (event: AnyEvent): event is ToolCallEvent =>
  event.event_type === "TOOL_CALL" && "tool_name" in event;

const isLlmEvent = (event: AnyEvent): event is LLMEvent =>
  (event.event_type === "LLM_START" || event.event_type === "LLM_END") && "prompt_hash" in event;

const isSessionEvent = (event: AnyEvent): event is SessionEvent =>
  (event.event_type === "SESSION_START" || event.event_type === "SESSION_END") &&
  "tool_calls_count" in event;

const formatEventTime = (iso: string): string => {
  const timestamp = new Date(iso).getTime();
  if (Number.isNaN(timestamp)) {
    return "unknown time";
  }

  const elapsedSeconds = Math.floor((Date.now() - timestamp) / 1000);
  if (elapsedSeconds < 60) {
    return "just now";
  }

  if (elapsedSeconds < 3600) {
    return `${Math.floor(elapsedSeconds / 60)}m ago`;
  }

  return new Date(iso).toLocaleTimeString();
};

const getEventSummary = (event: AnyEvent): string => {
  if (isThreatEvent(event)) {
    return event.description;
  }

  if (isToolCallEvent(event)) {
    return `Tool call: ${event.tool_name}`;
  }

  if (isLlmEvent(event)) {
    if (event.event_type === "LLM_END") {
      return event.token_count !== undefined
        ? `LLM invocation completed (${event.token_count} tokens)`
        : "LLM invocation completed";
    }

    return "LLM invocation started";
  }

  if (isSessionEvent(event)) {
    if (event.event_type === "SESSION_END") {
      return event.duration_seconds !== undefined
        ? `Session ended (${event.duration_seconds}s)`
        : "Session ended";
    }

    return "Session started";
  }

  return `Event: ${event.event_type}`;
};

export function EventFeed({
  maxHeight = "400px",
  className = "",
}: EventFeedProps): JSX.Element {
  const events = useShieldStore((state) => state.events);
  const selectedEventId = useShieldStore((state) => state.selectedEventId);
  const selectedAgentId = useShieldStore((state) => state.selectedAgentId);
  const setSelectedEvent = useShieldStore((state) => state.setSelectedEvent);

  const displayedEvents = useMemo(() => {
    if (!selectedAgentId) {
      return events;
    }

    return events.filter((event) => event.agent_id === selectedAgentId);
  }, [events, selectedAgentId]);

  return (
    <section
      className={`flex h-full w-full flex-col border border-shield-border bg-shield-bg ${className}`}
    >
      <header className="flex items-center justify-between border-b border-shield-border px-3 py-2">
        <div className="flex items-center gap-2">
          <h2 className="text-sm font-medium text-gray-300">Event Feed</h2>
          <span className="rounded-full border border-shield-border bg-shield-surface px-2 py-0.5 text-xs text-shield-subtext">
            {displayedEvents.length}
          </span>
        </div>
        {selectedAgentId ? (
          <span className="text-xs text-gray-500">agent: {selectedAgentId.slice(0, 10)}</span>
        ) : (
          <span className="text-xs text-gray-500">all agents</span>
        )}
      </header>

      {/* TODO: add virtual scrolling if event volume exceeds current list rendering limits. */}
      <div
        className="flex-1 overflow-y-auto [&::-webkit-scrollbar-track]:bg-transparent [&::-webkit-scrollbar-thumb]:bg-gray-700 [&::-webkit-scrollbar]:w-1"
        style={{ maxHeight }}
      >
        {displayedEvents.length === 0 ? (
          <div className="flex h-full min-h-24 items-center justify-center px-3 py-8">
            <p className="text-sm text-gray-500">
              {selectedAgentId ? "No events for selected agent" : "Waiting for live events"}
            </p>
          </div>
        ) : (
          displayedEvents.map((event) => {
            const isSelected = event.event_id === selectedEventId;

            return (
              <button
                key={event.event_id}
                type="button"
                onClick={() => {
                  setSelectedEvent(event.event_id);
                }}
                className={`flex w-full items-start gap-3 border-b border-shield-border px-3 py-2 text-left transition ${
                  isSelected ? "bg-gray-900/80" : "hover:bg-gray-900/40"
                }`}
              >
                <div className="mt-0.5 h-2 w-2 shrink-0 rounded-full bg-shield-accent" />

                <div className="min-w-0 flex-1 space-y-1">
                  <div className="flex items-center gap-1.5">
                    <span className={`${BADGE_BASE_CLASSES} border border-gray-600 bg-gray-800 text-cyan-400`}>
                      {event.event_type}
                    </span>
                    <span className={`${BADGE_BASE_CLASSES} ${SEVERITY_COLORS[event.severity]}`}>
                      {event.severity}
                    </span>
                    <span className="truncate text-xs text-gray-500">{event.agent_id}</span>
                  </div>

                  <p className="truncate text-sm text-gray-200">{getEventSummary(event)}</p>

                  <div className="flex items-center justify-between text-xs text-gray-500">
                    <span>{formatEventTime(event.timestamp)}</span>
                    <span className="font-mono">{event.event_id.slice(0, 12)}</span>
                  </div>
                </div>
              </button>
            );
          })
        )}
      </div>
    </section>
  );
}