import React from 'react';

export const Dashboard = () => (
  <div style={{ padding: '24px' }}>
    <div style={{ display: 'flex', gap: '16px', marginBottom: '24px' }}>
      {[{ label: 'AGENTS CONNECTED', val: '12', alert: false },
        { label: 'EVENTS (24H)', val: '8,392', alert: false },
        { label: 'THREATS DETECTED', val: '3', alert: true },
        { label: 'BLOCKS ISSUED', val: '2', alert: true }].map(stat => (
        <div key={stat.label} style={{ flex: 1, background: 'var(--bg-panel)', border: '1px solid var(--border)', padding: '16px', borderRadius: '2px' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '8px' }}>{stat.label}</div>
          <div style={{ 
            fontSize: '32px', color: stat.alert ? 'var(--accent-red)' : 'var(--text-primary)',
            textShadow: stat.alert ? 'var(--glow-red)' : 'none' 
          }}>{stat.val}</div>
        </div>
      ))}
    </div>
    <div style={{ display: 'flex', gap: '16px' }}>
      <div style={{ flex: 6, background: 'var(--bg-panel)', border: '1px solid var(--border)', padding: '16px', height: '400px' }}>
        <div style={{ color: 'var(--text-secondary)', marginBottom: '12px' }}>[ EVENT FEED ]</div>
        <div className="selectable" style={{ color: 'var(--accent-green)' }}>[INFO] system booted...</div>
      </div>
      <div style={{ flex: 4, background: 'var(--bg-panel)', border: '1px solid var(--border)', padding: '16px', height: '400px' }}>
        <div style={{ color: 'var(--text-secondary)', marginBottom: '12px' }}>[ ALERT PANEL ]</div>
        <div style={{ color: 'var(--accent-red)', borderLeft: '2px solid var(--accent-red)', paddingLeft: '8px' }}>PROMPT INJECTION DETECTED</div>
      </div>
    </div>
  </div>
);

export const Events = () => (
  <div style={{ padding: '24px' }}>
    <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
      <input placeholder="severity" style={{ background: 'var(--bg-input)', border: '1px solid var(--border)', padding: '4px 8px', color: 'var(--text-primary)' }} />
      <input placeholder="event_type" style={{ background: 'var(--bg-input)', border: '1px solid var(--border)', padding: '4px 8px', color: 'var(--text-primary)' }} />
      <input placeholder="agent_id" style={{ background: 'var(--bg-input)', border: '1px solid var(--border)', padding: '4px 8px', color: 'var(--text-primary)' }} />
    </div>
    <div style={{ background: 'var(--bg-panel)', padding: '12px', border: '1px solid var(--border)', fontFamily: 'monospace' }}>
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', paddingBottom: '8px', color: 'var(--text-secondary)' }}>
        <span style={{ width: '150px' }}>TIMESTAMP</span>
        <span style={{ width: '100px' }}>SEVERITY</span>
        <span style={{ flex: 1 }}>SUMMARY</span>
      </div>
      <div style={{ display: 'flex', paddingTop: '8px', color: 'var(--accent-red)', textShadow: 'var(--glow-red)' }}>
        <span style={{ width: '150px' }}>2026-04-06T12:00</span>
        <span style={{ width: '100px' }}>CRITICAL</span>
        <span style={{ flex: 1 }}>Unauthorized shell execution</span>
      </div>
    </div>
  </div>
);

export const Agents = () => (
  <div style={{ padding: '24px' }}>
    <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
      <thead>
        <tr style={{ color: 'var(--text-secondary)', borderBottom: '1px solid var(--border)' }}>
          <th style={{ padding: '8px' }}>AGENT ID</th>
          <th style={{ padding: '8px' }}>FRAMEWORK</th>
          <th style={{ padding: '8px' }}>STATUS</th>
        </tr>
      </thead>
      <tbody>
        <tr style={{ borderBottom: '1px solid var(--border)' }}>
          <td style={{ padding: '8px' }}>agent-alpha</td>
          <td style={{ padding: '8px' }}>LangChain</td>
          <td style={{ padding: '8px', color: 'var(--accent-green)' }}>● ACTIVE</td>
        </tr>
      </tbody>
    </table>
  </div>
);

export const Threats = () => (
  <div style={{ padding: '24px' }}>
    <div style={{ background: 'var(--bg-panel)', borderLeft: '3px solid var(--accent-red)', padding: '16px', marginBottom: '12px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-secondary)', marginBottom: '8px' }}>
        <span style={{ color: 'var(--accent-red)' }}>[PROMPT INJECTION]</span>
        <span>2 mins ago</span>
      </div>
      <div style={{ color: 'var(--text-primary)' }}>Target: agent-alpha | Summary: "Ignore all previous instructions..."</div>
    </div>
  </div>
);

export const Forensics = () => <div style={{ padding: '24px' }}>FORENSICS VIEW (Trace timeline)</div>;
export const AuditTrail = () => <div style={{ padding: '24px' }}>AUDIT TRAIL VIEW (Hash chains)</div>;
export const RedTeam = () => <div style={{ padding: '24px' }}>RED TEAM VIEW (Attack runner)</div>;
export const Settings = () => <div style={{ padding: '24px' }}>SETTINGS VIEW (Configuration)</div>;
