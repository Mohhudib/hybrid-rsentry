import React, { useEffect, useState, useCallback } from 'react';
import { getHosts, getHostRisk } from '../api/client';
import { RadialBarChart, RadialBar, ResponsiveContainer } from 'recharts';

const RISK_COLOR = (score) => {
  if (score >= 80) return 'var(--crit)';
  if (score >= 50) return 'var(--high)';
  if (score >= 25) return 'var(--med)';
  return 'var(--ok)';
};

const RISK_LABEL = (score) => {
  if (score >= 80) return { label: 'CRITICAL', color: 'var(--crit)' };
  if (score >= 50) return { label: 'HIGH',     color: 'var(--high)' };
  if (score >= 25) return { label: 'MEDIUM',   color: 'var(--med)'  };
  return                   { label: 'LOW',      color: 'var(--ok)'   };
};

export default function HostRiskPanel() {
  const [hosts,   setHosts]   = useState([]);
  const [riskMap, setRiskMap] = useState({});
  const [loading, setLoading] = useState(true);

  const fetchAll = useCallback(async () => {
    try {
      const { data: hostList } = await getHosts({ limit: 20 });
      setHosts(hostList);
      const results = await Promise.allSettled(hostList.map(h => getHostRisk(h.host_id)));
      const map = {};
      hostList.forEach((h, i) => { if (results[i].status === 'fulfilled') map[h.host_id] = results[i].value.data; });
      setRiskMap(map);
    } catch (err) {
      console.error('HostRiskPanel error:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 5000);
    return () => clearInterval(interval);
  }, [fetchAll]);

  const panel = { background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 12, padding: 16, height: '100%', overflowY: 'auto' };

  if (loading) return <div style={panel}><p style={{ color: 'var(--muted)', fontSize: 13 }}>Loading hosts…</p></div>;

  if (hosts.length === 0) return (
    <div style={panel}>
      <h2 style={{ color: 'var(--text)', fontSize: 14, fontWeight: 600, marginTop: 0 }}>Host Risk</h2>
      <p style={{ color: 'var(--muted)', fontSize: 13, fontStyle: 'italic' }}>No hosts registered yet.</p>
    </div>
  );

  const radialBg = document.documentElement.dataset.theme === 'light' ? '#cbd5e1' : '#374151';

  return (
    <div style={panel}>
      <h2 style={{ color: 'var(--text)', fontSize: 14, fontWeight: 600, marginTop: 0, marginBottom: 12 }}>Host Risk</h2>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {hosts.map(host => {
          const risk  = riskMap[host.host_id];
          const score = risk?.risk_score ?? host.risk_score ?? 0;
          const color = RISK_COLOR(score);
          const { label, color: labelColor } = RISK_LABEL(score);

          return (
            <div
              key={host.host_id}
              style={{
                display: 'flex', alignItems: 'center', gap: 12, padding: '10px 12px',
                borderRadius: 8, border: `1px solid ${host.is_contained ? 'rgba(220,38,38,0.4)' : 'var(--border)'}`,
                background: host.is_contained ? 'var(--crit-bg)' : 'var(--panel-2)',
              }}
            >
              <div style={{ width: 52, height: 52, flexShrink: 0 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <RadialBarChart cx="50%" cy="50%" innerRadius="55%" outerRadius="100%" data={[{ value: score, fill: color }]} startAngle={90} endAngle={-270}>
                    <RadialBar dataKey="value" background={{ fill: radialBg }} />
                  </RadialBarChart>
                </ResponsiveContainer>
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <p style={{ fontSize: 11, fontFamily: 'var(--mono)', color: 'var(--text)', margin: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{host.host_id}</p>
                <p style={{ fontSize: 11, fontWeight: 700, color: labelColor, margin: '2px 0' }}>{label}</p>
                <p style={{ fontSize: 11, margin: 0, fontFamily: 'var(--mono)' }}>
                  <span style={{ color }}>{score.toFixed(0)}</span>
                  <span style={{ color: 'var(--faint)' }}>/100</span>
                </p>
                {host.is_contained && (
                  <span style={{ fontSize: 10, background: 'var(--crit-bg)', color: 'var(--crit)', border: '1px solid rgba(220,38,38,0.3)', padding: '1px 6px', borderRadius: 4, display: 'inline-block', marginTop: 3 }}>CONTAINED</span>
                )}
              </div>
              <div style={{ textAlign: 'right', flexShrink: 0 }}>
                <p style={{ fontSize: 10, color: 'var(--muted)', margin: 0 }}>Open Alerts</p>
                <p style={{ fontSize: 14, fontWeight: 700, color: 'var(--text)', margin: '2px 0 0' }}>{risk?.alert_count ?? '—'}</p>
              </div>
            </div>
          );
        })}
      </div>
      <p style={{ fontSize: 11, color: 'var(--faint)', textAlign: 'center', marginTop: 10 }}>
        Manage hosts → <span style={{ color: 'var(--muted)' }}>Hosts page</span>
      </p>
    </div>
  );
}
