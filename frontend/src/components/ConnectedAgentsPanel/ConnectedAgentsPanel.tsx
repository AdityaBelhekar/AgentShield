import { useCallback, useEffect, useState } from "react";

interface ConnectedAgent {
  name: string;
  framework: string;
  policy: string;
  status: string;
  active: boolean;
}

interface ConnectedAgentsPanelProps {
  className?: string;
}

const API_BASE = (import.meta.env.VITE_API_URL ?? "").replace(/\/$/, "");

const buildApiUrl = (path: string): string => `${API_BASE}${path}`;

export function ConnectedAgentsPanel({ className = "" }: ConnectedAgentsPanelProps): JSX.Element {
  const [agents, setAgents] = useState<ConnectedAgent[]>([]);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const fetchConnectedAgents = useCallback(async (): Promise<void> => {
    try {
      const response = await fetch(buildApiUrl("/agents"));
      if (!response.ok) {
        throw new Error(`Failed to fetch connected agents (${response.status}).`);
      }

      const payload = (await response.json()) as unknown;
      if (!Array.isArray(payload)) {
        throw new Error("Connected agents response must be an array.");
      }

      const nextAgents: ConnectedAgent[] = payload
        .map((entry) => {
          if (typeof entry !== "object" || entry === null) {
            return null;
          }

          const candidate = entry as Record<string, unknown>;
          if (
            typeof candidate.name !== "string" ||
            typeof candidate.framework !== "string" ||
            typeof candidate.policy !== "string" ||
            typeof candidate.status !== "string" ||
            typeof candidate.active !== "boolean"
          ) {
            return null;
          }

          return {
            name: candidate.name,
            framework: candidate.framework,
            policy: candidate.policy,
            status: candidate.status,
            active: candidate.active,
          };
        })
        .filter((entry): entry is ConnectedAgent => entry !== null);

      setAgents(nextAgents);
      setErrorMessage(null);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to load connected agents.";
      setErrorMessage(message);
    }
  }, []);

  useEffect(() => {
    void fetchConnectedAgents();
    const timer = window.setInterval(() => {
      void fetchConnectedAgents();
    }, 5000);

    return () => {
      window.clearInterval(timer);
    };
  }, [fetchConnectedAgents]);

  return (
    <section className={`flex h-full w-full flex-col border border-shield-border bg-shield-bg ${className}`}>
      <header className="flex items-center justify-between border-b border-shield-border px-3 py-2">
        <h2 className="text-sm font-medium text-gray-300">Connected Agents</h2>
        <span className="rounded-full border border-shield-border bg-shield-surface px-2 py-0.5 text-xs text-shield-subtext">
          {agents.length}
        </span>
      </header>

      {errorMessage ? (
        <div className="border-b border-shield-border bg-red-950/40 px-3 py-2 text-xs text-red-300">
          {errorMessage}
        </div>
      ) : null}

      <div className="flex-1 overflow-y-auto [&::-webkit-scrollbar-track]:bg-transparent [&::-webkit-scrollbar-thumb]:bg-gray-700 [&::-webkit-scrollbar]:w-1">
        {agents.length === 0 ? (
          <div className="flex h-full min-h-24 items-center justify-center px-3 py-8">
            <p className="text-sm text-gray-500">No connected agents yet.</p>
          </div>
        ) : (
          agents.map((agent) => (
            <article key={`${agent.name}:${agent.framework}:${agent.policy}`} className="border-b border-shield-border px-3 py-3">
              <div className="flex items-center gap-2">
                <span
                  className={`h-2 w-2 rounded-full ${agent.active ? "bg-emerald-400" : "bg-gray-500"}`}
                />
                <p className="truncate text-sm font-medium text-gray-200">{agent.name}</p>
              </div>

              <div className="mt-2 grid grid-cols-2 gap-x-2 gap-y-1 text-xs text-gray-400">
                <span>framework</span>
                <span className="truncate text-gray-300">{agent.framework}</span>
                <span>policy</span>
                <span className="truncate text-gray-300">{agent.policy}</span>
                <span>status</span>
                <span className="truncate text-gray-300">{agent.status}</span>
              </div>
            </article>
          ))
        )}
      </div>
    </section>
  );
}
