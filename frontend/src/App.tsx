import { useEffect } from "react";
import { AgentGraph } from "./components/AgentGraph";
import { AlertPanel } from "./components/AlertPanel";
import { EventFeed } from "./components/EventFeed";
import { ForensicTrace } from "./components/ForensicTrace";
import { wsManager } from "./services/wsManager";
import { useShieldStore } from "./store/useShieldStore";

export default function App(): JSX.Element {
  const wsConnected = useShieldStore((s) => s.wsConnected);

  useEffect(() => {
    wsManager.connect();
    return () => wsManager.disconnect();
  }, []);

  return (
    <div className="flex min-h-screen flex-col bg-shield-bg text-gray-100">
      <header className="flex h-12 items-center gap-3 border-b border-shield-border px-4">
        <span className="text-sm font-semibold tracking-wide text-shield-accent">
          AgentShield
        </span>
        <span className="text-xs text-shield-subtext">Security Dashboard</span>
        <div className="ml-auto flex items-center gap-1.5">
          <div
            className={`h-2 w-2 rounded-full ${wsConnected ? "bg-shield-accent" : "bg-shield-danger"}`}
          />
          <span className="text-xs text-shield-subtext">
            {wsConnected ? "Live" : "Disconnected"}
          </span>
        </div>
      </header>

      <div className="relative flex flex-1 overflow-hidden">
        <div className="flex flex-1 flex-col overflow-hidden">
          <div className="flex-1 overflow-hidden p-4">
            <AgentGraph height="100%" />
          </div>
          <div className="flex-1 overflow-hidden border-t border-[#1f2937]">
            <EventFeed maxHeight="100%" />
          </div>
        </div>

        <div className="w-[380px] overflow-hidden border-l border-[#1f2937]">
          <AlertPanel maxHeight="100%" />
        </div>
      </div>

      <ForensicTrace />
    </div>
  );
}
