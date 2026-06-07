import React, { useState } from 'react';
import { RULE_NAME, MITRE } from '../constants/eventTypes';

const SEV_COLOR  = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)' };
const SEV_BG     = { CRITICAL: 'var(--crit-bg)', HIGH: 'var(--high-bg)', MEDIUM: 'var(--med-bg)', LOW: 'var(--low-bg)' };
const STATUS_LABEL = { true: 'Acknowledged', false: 'Open' };

function riskColor(r) { return r >= 85 ? 'var(--crit)' : r >= 65 ? 'var(--high)' : r >= 45 ? 'var(--med)' : 'var(--low)'; }

function riskScore(alert) {
  const n = parseInt((alert.id || '').replace(/-/g, '').slice(0, 8), 16) || 0;
  if (alert.severity === 'CRITICAL') return 90 + Math.min(9, n % 10);
  if (alert.severity === 'HIGH')     return 65 + (n % 20);
  if (alert.severity === 'MEDIUM')   return 40 + (n % 25);
  return 20 + (n % 20);
}

export default function AlertsTable({ alerts, selectedId, onSelect, page, setPage }) {
  const [sortKey, setSortKey] = useState('ts');
  const [sortDir, setSortDir] = useState(-1);

  const PER_PAGE = 25;
  const currentPage = page || 0;

  function handleSort(k) {
    if (sortKey === k) setSortDir(d => d * -1);
    else { setSortKey(k); setSortDir(k === 'ts' || k === 'risk' || k === 'sev' ? -1 : 1); }
  }

  const sorted = [...alerts].sort((a, b) => {
    let va, vb;
    const sevRank = s => ({ CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[s] || 0);
    switch (sortKey) {
      case 'sev':    va = sevRank(a.severity);   vb = sevRank(b.severity);   break;
      case 'rule':   va = a.event_type || '';     vb = b.event_type || '';    break;
      case 'host':   va = a.host_id;              vb = b.host_id;             break;
      case 'risk':   va = riskScore(a);           vb = riskScore(b);          break;
      case 'status': va = String(a.acknowledged); vb = String(b.acknowledged);break;
      default:       va = a.created_at;           vb = b.created_at;
    }
    if (va < vb) return -1 * sortDir;
    if (va > vb) return sortDir;
    return 0;
  });

  const start = currentPage * PER_PAGE;
  const pageRows = sorted.slice(start, start + PER_PAGE);
  const totalPages = Math.ceil(sorted.length / PER_PAGE);

  function th(label, key) {
    const active = sortKey === key;
    return (
      <th
        data-sort={key}
        onClick={() => handleSort(key)}
        style={{ position: 'sticky', top: 0, zIndex: 2, background: 'var(--panel-2)', textAlign: 'left', fontWeight: 500, fontSize: 11, color: active ? 'var(--text)' : 'var(--text-2)', padding: '8px 12px', borderBottom: '1px solid var(--border)', whiteSpace: 'nowrap', cursor: 'pointer', userSelect: 'none' }}
      >
        {label} {active && <span style={{ color: 'var(--muted)', fontSize: 9 }}>{sortDir === -1 ? '▼' : '▲'}</span>}
      </th>
    );
  }

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, background: 'var(--panel)' }}>
      {/* Head */}
      <div style={{ height: 38, display: 'flex', alignItems: 'center', gap: 12, padding: '0 16px', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
        <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--text)' }}>Alerts</span>
        <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--muted)' }}>{alerts.length} hits</span>
      </div>

      {/* Table */}
      <div style={{ flex: 1, overflow: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              {th('@timestamp', 'ts')}
              {th('Severity', 'sev')}
              {th('Rule', 'rule')}
              {th('Host', 'host')}
              {th('Risk', 'risk')}
              {th('Status', 'status')}
            </tr>
          </thead>
          <tbody>
            {pageRows.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>
                  <i className="fa-regular fa-circle-check" style={{ display: 'block', fontSize: 24, marginBottom: 8, color: 'var(--faint)' }} />
                  No alerts — system is clean.
                </td>
              </tr>
            ) : pageRows.map(alert => {
              const risk = riskScore(alert);
              const rule = RULE_NAME[alert.event_type] || alert.event_type || 'Detection Alert';
              const tech = MITRE[alert.event_type];
              const sel  = alert.id === selectedId;
              return (
                <tr
                  key={alert.id}
                  onClick={() => onSelect(alert)}
                  style={{ cursor: 'pointer', background: sel ? 'var(--accent-dim)' : undefined, boxShadow: sel ? 'inset 2px 0 0 var(--accent)' : undefined }}
                  onMouseEnter={e => { if (!sel) e.currentTarget.style.background = 'var(--panel-2)'; }}
                  onMouseLeave={e => { if (!sel) e.currentTarget.style.background = 'transparent'; }}
                >
                  <td style={{ padding: '7px 12px', borderBottom: '1px solid var(--border-soft)', fontSize: 12, whiteSpace: 'nowrap', fontFamily: 'var(--mono)', color: 'var(--text-2)' }}>
                    <b style={{ color: 'var(--text)' }}>{new Date(alert.created_at).toLocaleTimeString()}</b>
                    {' '}
                    <span style={{ fontSize: 11 }}>{new Date(alert.created_at).toLocaleDateString()}</span>
                  </td>
                  <td style={{ padding: '7px 12px', borderBottom: '1px solid var(--border-soft)', whiteSpace: 'nowrap' }}>
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 7 }}>
                      <span style={{ width: 9, height: 9, borderRadius: 2, background: SEV_COLOR[alert.severity] || 'var(--muted)', flexShrink: 0 }} />
                      <span style={{ fontSize: 11, color: SEV_COLOR[alert.severity] || 'var(--muted)' }}>{alert.severity}</span>
                    </span>
                  </td>
                  <td style={{ padding: '7px 12px', borderBottom: '1px solid var(--border-soft)', fontSize: 12, color: 'var(--text)' }}>{rule}</td>
                  <td style={{ padding: '7px 12px', borderBottom: '1px solid var(--border-soft)', fontSize: 12, fontFamily: 'var(--mono)', color: 'var(--text-2)', whiteSpace: 'nowrap' }}>{alert.host_id}</td>
                  <td style={{ padding: '7px 12px', borderBottom: '1px solid var(--border-soft)', whiteSpace: 'nowrap' }}>
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 7, fontFamily: 'var(--mono)' }}>
                      <span style={{ width: 42, height: 5, borderRadius: 3, background: '#2c2f37', overflow: 'hidden', display: 'inline-block' }}>
                        <span style={{ display: 'block', height: '100%', borderRadius: 3, width: `${risk}%`, background: riskColor(risk) }} />
                      </span>
                      {risk}
                    </span>
                  </td>
                  <td style={{ padding: '7px 12px', borderBottom: '1px solid var(--border-soft)', whiteSpace: 'nowrap' }}>
                    <span style={{ fontSize: 11, display: 'inline-flex', alignItems: 'center', gap: 6, fontFamily: 'var(--mono)', color: alert.acknowledged ? 'var(--muted)' : 'var(--text)' }}>
                      <span style={{ width: 6, height: 6, borderRadius: '50%', background: alert.acknowledged ? 'var(--muted)' : 'var(--crit)', display: 'inline-block' }} />
                      {alert.acknowledged ? 'Acknowledged' : 'Open'}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Footer */}
      <div style={{ height: 36, flexShrink: 0, borderTop: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 14, padding: '0 16px', fontSize: 11.5, color: 'var(--muted)', fontFamily: 'var(--mono)' }}>
        <span>Rows per page: <b style={{ color: 'var(--text-2)' }}>{PER_PAGE}</b></span>
        <span style={{ flex: 1 }} />
        <span>{start + 1}–{Math.min(start + PER_PAGE, sorted.length)} of {sorted.length}</span>
        <button className="siem-pgbtn" disabled={currentPage === 0} onClick={() => setPage(p => Math.max(0, p - 1))}>
          <i className="fa-solid fa-chevron-left" style={{ fontSize: 10 }} />
        </button>
        <button className="siem-pgbtn" disabled={currentPage >= totalPages - 1} onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}>
          <i className="fa-solid fa-chevron-right" style={{ fontSize: 10 }} />
        </button>
      </div>
    </div>
  );
}
