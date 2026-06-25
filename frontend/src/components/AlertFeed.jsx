import React, { useEffect, useState, useCallback } from 'react';
import { getAlerts, acknowledgeAlert } from '../api/client';
import { formatDistanceToNow } from 'date-fns';

const SEV_BG  = { CRITICAL: 'var(--crit)',  HIGH: 'var(--high)',  MEDIUM: 'var(--med)',  LOW: 'var(--low)'  };
const SEV_FG  = { CRITICAL: '#fff',          HIGH: '#fff',          MEDIUM: '#fff',        LOW: '#fff'        };
const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

export default function AlertFeed({ newAlert }) {
  const [alerts, setAlerts]   = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter]   = useState('ALL');

  const fetchAlerts = useCallback(async () => {
    try {
      const params = { acknowledged: false, limit: 500, ...(filter !== 'ALL' ? { severity: filter } : {}) };
      const { data } = await getAlerts(params);
      setAlerts(data);
    } catch (err) {
      console.error('Failed to fetch alerts:', err);
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => {
    fetchAlerts();
    const t = setInterval(fetchAlerts, 5000);
    return () => clearInterval(t);
  }, [fetchAlerts]);

  useEffect(() => {
    if (!newAlert) return;
    setAlerts(prev => {
      if (prev.find(a => a.id === newAlert.alert_id)) return prev;
      return [{ id: newAlert.alert_id, host_id: newAlert.host_id, severity: newAlert.severity, acknowledged: false, created_at: new Date().toISOString(), _live: true }, ...prev];
    });
  }, [newAlert]);

  const handleAcknowledge = async (id) => {
    try {
      await acknowledgeAlert(id);
      setAlerts(prev => prev.filter(a => a.id !== id));
    } catch (err) {
      console.error('Acknowledge failed:', err);
    }
  };

  const sorted = [...alerts].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  return (
    <div style={{ background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 12, padding: 16, height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
        <div>
          <h2 style={{ color: 'var(--text)', fontSize: 16, fontWeight: 600, margin: 0 }}>Live Alert Feed</h2>
          {alerts.length > 0 && <p style={{ color: 'var(--muted)', fontSize: 11, margin: '2px 0 0' }}>{alerts.length} active</p>}
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => (
            <button
              key={s}
              onClick={() => setFilter(s)}
              style={{
                padding: '3px 8px', fontSize: 11, borderRadius: 5, fontWeight: 500, cursor: 'pointer',
                background: filter === s ? 'var(--accent)' : 'var(--panel-3)',
                color: filter === s ? '#fff' : 'var(--text-2)',
                border: `1px solid ${filter === s ? 'transparent' : 'var(--border)'}`,
              }}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* Body */}
      {loading ? (
        <p style={{ color: 'var(--muted)', fontSize: 13 }}>Loading alerts...</p>
      ) : sorted.length === 0 ? (
        <p style={{ color: 'var(--muted)', fontSize: 13, fontStyle: 'italic' }}>No active alerts. System nominal.</p>
      ) : (
        <div style={{ overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: 8 }}>
          {sorted.map(alert => (
            <AlertRow key={alert.id} alert={alert} onAcknowledge={handleAcknowledge} />
          ))}
        </div>
      )}
    </div>
  );
}

function AlertRow({ alert, onAcknowledge }) {
  return (
    <div
      className={alert._live ? 'animate-pulse-once' : ''}
      style={{ background: 'var(--panel-2)', border: '1px solid var(--border)', borderRadius: 8, padding: '10px 12px', display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}
    >
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 7px', borderRadius: 4, background: SEV_BG[alert.severity], color: SEV_FG[alert.severity] }}>
            {alert.severity}
          </span>
          <span style={{ fontSize: 11, fontFamily: 'var(--mono)', color: 'var(--text-2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{alert.host_id}</span>
          <span style={{ fontSize: 11, color: 'var(--muted)' }}>
            {formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}
          </span>
        </div>
        <p style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          ID: {alert.id?.slice(0, 8)}…
        </p>
      </div>
      <button
        onClick={() => onAcknowledge(alert.id)}
        style={{ fontSize: 11, background: 'var(--panel-3)', border: '1px solid var(--border)', color: 'var(--text-2)', padding: '4px 10px', borderRadius: 5, cursor: 'pointer', flexShrink: 0 }}
        onMouseEnter={e => { e.currentTarget.style.background = 'var(--ok)'; e.currentTarget.style.color = '#fff'; e.currentTarget.style.borderColor = 'transparent'; }}
        onMouseLeave={e => { e.currentTarget.style.background = 'var(--panel-3)'; e.currentTarget.style.color = 'var(--text-2)'; e.currentTarget.style.borderColor = 'var(--border)'; }}
      >
        ACK
      </button>
    </div>
  );
}
