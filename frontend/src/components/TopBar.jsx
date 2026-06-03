import React from 'react';

const NAV = [
  { id: 'dashboard',  label: 'Overview' },
  { id: 'alerts',     label: 'Alerts' },
  { id: 'hosts',      label: 'Hosts' },
  { id: 'filesystem', label: 'Detections' },
  { id: 'ai',         label: 'AI Analyst' },
  { id: 'reports',    label: 'Reports' },
];

export default function TopBar({ activePage, onNavigate, alertCount, connected }) {
  return (
    <header style={{ height: 46, flexShrink: 0, display: 'flex', alignItems: 'center', gap: 4, padding: '0 12px 0 14px', background: 'var(--panel)', borderBottom: '1px solid var(--border)' }}>

      {/* Brand */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 9, fontWeight: 600, fontSize: 14, letterSpacing: '-0.01em', paddingRight: 8 }}>
        <span style={{ width: 22, height: 22, borderRadius: 5, background: '#20242c', border: '1px solid #333741', display: 'grid', placeItems: 'center', color: 'var(--accent)', fontSize: 12 }}>
          <i className="fa-solid fa-shield-halved" />
        </span>
        <span style={{ color: 'var(--text)' }}>Hybrid R-Sentry</span>
        <span style={{ color: 'var(--muted)', fontWeight: 400, fontSize: 12 }}>Security</span>
      </div>

      {/* Nav */}
      <nav style={{ display: 'flex', alignItems: 'center', gap: 2, marginLeft: 14 }}>
        {NAV.map(item => (
          <button
            key={item.id}
            onClick={() => onNavigate(item.id)}
            className={`siem-nav-btn${activePage === item.id ? ' active' : ''}`}
          >
            {item.label}
            {item.id === 'alerts' && alertCount > 0 && (
              <span style={{ fontFamily: 'var(--mono)', fontSize: 10, background: 'var(--crit-bg)', color: 'var(--crit)', padding: '1px 5px', borderRadius: 4, fontWeight: 500 }}>
                {alertCount}
              </span>
            )}
          </button>
        ))}
      </nav>

      <div style={{ flex: 1 }} />

      {/* Right controls */}
      <button style={{ height: 28, display: 'inline-flex', alignItems: 'center', gap: 7, padding: '0 10px', borderRadius: 6, cursor: 'pointer', background: 'var(--panel-2)', border: '1px solid var(--border)', color: 'var(--text-2)', fontSize: 12, fontFamily: 'var(--sans)' }}>
        <i className="fa-solid fa-layer-group" style={{ fontSize: 11, color: 'var(--muted)' }} />
        rsentry-prod
      </button>
      <button className="siem-icon-btn" title="Alerts">
        <i className="fa-regular fa-bell" style={{ fontSize: 13 }} />
      </button>
      <button className="siem-icon-btn" title="Help">
        <i className="fa-regular fa-circle-question" style={{ fontSize: 13 }} />
      </button>
      <div
        title={connected ? 'WebSocket connected' : 'Disconnected'}
        style={{ width: 28, height: 28, borderRadius: '50%', marginLeft: 4, background: connected ? 'linear-gradient(135deg, #3a6ea5, #2f5680)' : 'linear-gradient(135deg, #7f1d1d, #991b1b)', display: 'grid', placeItems: 'center', color: '#fff', fontSize: 11, fontWeight: 600 }}
      >
        MH
      </div>
    </header>
  );
}
