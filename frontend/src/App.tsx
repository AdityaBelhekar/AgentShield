import { useEffect } from "react";
import { wsManager } from "./services/wsManager";
import { useShieldStore } from "./store/useShieldStore";

function App() {
  const wsConnected = useShieldStore((state) => state.wsConnected);
  const wsError = useShieldStore((state) => state.wsError);

  useEffect(() => {
    wsManager.connect();

    return () => {
      wsManager.disconnect();
    };
  }, []);

  return (
    <main className="flex min-h-screen items-center justify-center bg-shield-bg px-6 py-10 text-center text-shield-text">
      <div className="space-y-4">
        <h1 className="text-2xl font-semibold md:text-3xl">
          AgentShield Dashboard - Phase 7A Foundation
        </h1>
        <p className={wsConnected ? "text-shield-accent" : "text-shield-danger"}>
          WebSocket: {wsConnected ? "Connected" : "Disconnected"}
        </p>
        {wsError ? <p className="text-sm text-shield-warn">{wsError}</p> : null}
      </div>
    </main>
  );
}

export default App
