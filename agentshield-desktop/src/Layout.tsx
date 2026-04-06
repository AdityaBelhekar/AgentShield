import React, { useEffect, useState } from 'react';
import { useNavigationStore, useBackendStore, useCommandPaletteStore } from './store';
import { Dashboard, Events, Agents, Threats, Forensics, AuditTrail, RedTeam, Settings } from './views';

const TitleBar = () => {
  const currentView = useNavigationStore(s => s.currentView);
  return (
    <div style={{
      height: '36px', width: '100%', WebkitAppRegion: 'drag', display: 'flex', justifyContent: 'space-between',
      alignItems: 'center', background: 'var(--bg-panel)', borderBottom: '1px solid var(--border)'
    }}>
      <div style={{ paddingLeft: '12px', color: 'var(--accent-green)', fontWeight: 'bold' }}>
        ◈ AGENTSHIELD
      </div>
      <div style={{ color: 'var(--text-primary)', fontSize: '11px', letterSpacing: '0.05em' }}>
        {currentView}
      </div>
      <div style={{ WebkitAppRegion: 'no-drag', display: 'flex' }}>
        <button onClick={() => window.agentshield?.minimizeWindow()} style={{ width: 28, height: 28, background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}>_</button>
        <button onClick={() => window.agentshield?.maximizeWindow()} style={{ width: 28, height: 28, background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}>□</button>
        <button onClick={() => window.agentshield?.closeWindow()} style={{ width: 28, height: 28, background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}>×</button>
      </div>
    </div>
  );
};

const Sidebar = () => {
  const { currentView, navigate } = useNavigationStore();
  const { status, port } = useBackendStore();
  const items = ['DASHBOARD', 'EVENTS', 'AGENTS', 'THREATS', 'FORENSICS', 'AUDIT TRAIL', 'RED TEAM', 'SETTINGS'];

  return (
    <div style={{ width: '200px', background: 'var(--bg-panel)', borderRight: '1px solid var(--border)', display: 'flex', flexDirection: 'column' }}>
      <div style={{ flex: 1, padding: '12px 0' }}>
        {items.map(item => {
          if (item === 'SETTINGS') return null; // handle separately below with divider
          const isActive = currentView === item;
          return (
            <div key={item} onClick={() => navigate(item)}
              style={{
                padding: '8px 12px', fontSize: '11px', cursor: 'pointer',
                color: isActive ? 'var(--accent-green)' : 'var(--text-primary)',
                borderLeft: isActive ? '2px solid var(--accent-green)' : '2px solid transparent',
                background: isActive ? 'var(--bg-elevated)' : 'transparent',
                marginBottom: '2px'
              }}
            >
              {item}
            </div>
          );
        })}
        <div style={{ height: '1px', background: 'var(--border)', margin: '12px 0' }} />
        <div onClick={() => navigate('SETTINGS')}
          style={{
            padding: '8px 12px', fontSize: '11px', cursor: 'pointer',
            color: currentView === 'SETTINGS' ? 'var(--accent-green)' : 'var(--text-primary)',
            borderLeft: currentView === 'SETTINGS' ? '2px solid var(--accent-green)' : '2px solid transparent'
          }}>
          SETTINGS
        </div>
      </div>
      
      <div style={{ padding: '12px', borderTop: '1px solid var(--border)', fontSize: '11px' }}>
        <div style={{ display: 'flex', alignItems: 'center', color: status === 'online' ? 'var(--accent-green)' : 'var(--accent-red)' }}>
          <span style={{ marginRight: '6px' }}>●</span>
          BACKEND {status.toUpperCase()}
        </div>
        <div style={{ color: 'var(--text-secondary)', marginTop: '4px' }}>port :{port}</div>
      </div>
    </div>
  );
};

const CommandPalette = () => {
  const { isOpen, query, setQuery, close } = useCommandPaletteStore();
  const navigate = useNavigationStore(s => s.navigate);

  if (!isOpen) return null;

  const commands = [
    { name: 'Go to Dashboard', action: () => navigate('DASHBOARD') },
    { name: 'Go to Events', action: () => navigate('EVENTS') },
    { name: 'Go to Agents', action: () => navigate('AGENTS') },
    { name: 'Go to Threats', action: () => navigate('THREATS') },
    { name: 'Go to Forensics', action: () => navigate('FORENSICS') },
    { name: 'Go to Audit Trail', action: () => navigate('AUDIT TRAIL') },
    { name: 'Go to Red Team', action: () => navigate('RED TEAM') },
    { name: 'Go to Settings', action: () => navigate('SETTINGS') },
    { name: 'Verify Audit Chain', action: () => console.log('Verify Audit Chain') },
    { name: 'Restart Backend', action: () => console.log('Restart Backend') }
  ].filter(c => c.name.toLowerCase().includes(query.toLowerCase()));

  return (
    <div style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
      background: 'rgba(0,0,0,0.5)', display: 'flex', justifyContent: 'center', paddingTop: '100px', zIndex: 1000
    }} onClick={close}>
      <div style={{
        width: '560px', background: 'var(--bg-elevated)', border: '1px solid var(--border-active)',
        boxShadow: '0 8px 32px rgba(0,0,0,0.6)', borderRadius: '2px', display: 'flex', flexDirection: 'column'
      }} onClick={e => e.stopPropagation()}>
        <input 
          autoFocus
          placeholder="Search commands, agents, events..."
          value={query}
          onChange={e => setQuery(e.target.value)}
          style={{
            padding: '16px', background: 'transparent', border: 'none', borderBottom: '1px solid var(--border)',
            color: 'var(--text-primary)', fontSize: '14px', fontFamily: 'inherit', outline: 'none'
          }}
        />
        <div style={{ maxHeight: '300px', overflowY: 'auto', padding: '8px 0' }}>
          {commands.map((cmd, i) => (
            <div key={cmd.name}
              onClick={() => { cmd.action(); close(); }}
              style={{
                padding: '0 12px', height: '40px', display: 'flex', alignItems: 'center', cursor: 'pointer',
                color: i === 0 ? 'var(--accent-green)' : 'var(--text-primary)',
                background: i === 0 ? 'var(--bg-panel)' : 'transparent'
              }}>
              {cmd.name}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export const Layout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', width: '100vw' }}>
      <TitleBar />
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <Sidebar />
        <div style={{ flex: 1, background: 'var(--bg-base)', overflowY: 'auto' }}>
          {children}
        </div>
      </div>
      <CommandPalette />
    </div>
  );
};
