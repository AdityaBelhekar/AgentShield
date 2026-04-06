import React, { useEffect } from 'react';
import { Layout } from './Layout';
import { useNavigationStore, useBackendStore, useCommandPaletteStore } from './store';
import { Dashboard, Events, Agents, Threats, Forensics, AuditTrail, RedTeam, Settings } from './views';

function App() {
  const { currentView } = useNavigationStore();
  const { setPort, setStatus } = useBackendStore();
  const { open: openCommandPalette } = useCommandPaletteStore();

  useEffect(() => {
    // Port fetching
    window.agentshield?.getBackendPort().then(p => {
      setPort(p);
      setStatus('online'); // Mock healthy for now initially if got port
    });

    // Backend status listener
    if (window.agentshield?.onBackendStatus) {
      window.agentshield.onBackendStatus((_, isOnline) => {
        setStatus(isOnline ? 'online' : 'offline');
      });
    }

    // Command palette global hotkey
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        openCommandPalette();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const renderView = () => {
    switch (currentView) {
      case 'DASHBOARD': return <Dashboard />;
      case 'EVENTS': return <Events />;
      case 'AGENTS': return <Agents />;
      case 'THREATS': return <Threats />;
      case 'FORENSICS': return <Forensics />;
      case 'AUDIT TRAIL': return <AuditTrail />;
      case 'RED TEAM': return <RedTeam />;
      case 'SETTINGS': return <Settings />;
      default: return <Dashboard />;
    }
  };

  return (
    <Layout>
      {renderView()}
    </Layout>
  );
}

export default App;

