import { useEffect } from "react";
import { AgentGraph } from "./components/AgentGraph";
import { AlertPanel } from "./components/AlertPanel";
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

      <div className="flex flex-1 gap-0 overflow-hidden">
        <div className="flex-1 p-4">
          <AgentGraph height="calc(100vh - 112px)" />
        </div>
        <div className="w-[380px] border-l border-shield-border p-4">
          <AlertPanel maxHeight="calc(100vh - 112px)" />
        </div>
      </div>
    </div>
  );
}
