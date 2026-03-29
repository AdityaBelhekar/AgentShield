import { useEffect } from "react";
import { AgentGraph } from "./components/AgentGraph";
import { AlertPanel } from "./components/AlertPanel";
import { EventFeed } from "./components/EventFeed";
import { ForensicTrace } from "./components/ForensicTrace";
import { DemoControlPanel } from "./components/DemoControlPanel";
import { wsManager } from "./services/wsManager";
import { useShieldStore } from "./store/useShieldStore";

export default function App(): JSX.Element {
  const wsConnected = useShieldStore((s) => s.wsConnected);
  const wsError = useShieldStore((s) => s.wsError);

  useEffect(() => {
    wsManager.connect();
    return () => wsManager.disconnect();
  }, []);

  return (
    <div className="flex h-screen flex-col overflow-hidden bg-[#0a0e1a] text-gray-100">
      <header className="flex h-12 shrink-0 items-center gap-3 border-b border-[#1f2937] px-4">
        <span className="text-sm font-semibold uppercase tracking-widest text-cyan-400">
          AgentShield
        </span>
        <span className="text-xs text-gray-600">Security Dashboard</span>

        <div className="flex-1" />

        {wsError ? (
          <span className="rounded border border-red-800 bg-red-950 px-2 py-0.5 text-[10px] text-red-400">
            {wsError}
          </span>
        ) : null}

        <div className="flex items-center gap-1.5">
          <div
            className={`h-2 w-2 rounded-full transition-colors ${
              wsConnected ? "bg-cyan-400" : "bg-red-500"
            }`}
          />
          <span className="text-xs text-gray-500">
            {wsConnected ? "Live" : "Disconnected"}
          </span>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        <div className="flex flex-1 flex-col overflow-hidden">
          <div style={{ flex: "0 0 60%" }} className="overflow-hidden p-3">
            <AgentGraph height="100%" />
          </div>
          <div style={{ flex: "0 0 40%" }} className="overflow-hidden border-t border-[#1f2937]">
            <EventFeed maxHeight="100%" />
          </div>
        </div>

        <div className="w-[340px] shrink-0 overflow-hidden border-l border-[#1f2937]">
          <AlertPanel maxHeight="100%" />
        </div>

        <div className="w-[360px] shrink-0 overflow-y-auto border-l border-[#1f2937]">
          <DemoControlPanel />
        </div>
      </div>

      <ForensicTrace />
    </div>
  );
}
