import React from 'react';

function Metric({ label, value, trend, color, sq }) {
  return (
    <div style={{ padding: '12px 16px', borderRight: '1px solid var(--border-soft)', flex: 1 }}>
      <div style={{ fontSize: 11, color: 'var(--muted)', letterSpacing: '0.02em', display: 'flex', alignItems: 'center', gap: 6 }}>
        {sq && <span style={{ width: 8, height: 8, borderRadius: 2, background: sq, display: 'inline-block' }} />}
        {label}
      </div>
      <div style={{ fontFamily: 'var(--mono)', fontSize: 23, fontWeight: 500, marginTop: 5, letterSpacing: '-0.01em', color: color || 'var(--text)' }}>
        {value}
      </div>
      {trend && (
        <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 3, fontFamily: 'var(--mono)' }}>
          {trend}
        </div>
      )}
    </div>
  );
}

export default function MetricsStrip({ alerts, events }) {
  const unacked    = alerts.filter(a => !a.acknowledged);
  const open       = unacked.length;
  const critical   = unacked.filter(a => a.severity === 'CRITICAL').length;
  const high       = unacked.filter(a => a.severity === 'HIGH').length;
  const hosts      = new Set(unacked.map(a => a.host_id)).size;

  const cutoff60s  = Date.now() - 60 * 1000;
  const recentEvts = (events || []).filter(e => new Date(e.timestamp).getTime() > cutoff60s);
  const eps        = recentEvts.length > 0 ? (recentEvts.length / 60).toFixed(2) : '0.00';

  const ruleTypes  = new Set((events || []).map(e => e.event_type)).size;

  return (
    <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', background: 'var(--panel)', flexShrink: 0 }}>
      <Metric label="Open alerts"    value={open}     trend={open > 0 ? `${open} unacknowledged` : 'None yet'} />
      <Metric label="Critical"       value={critical} color={critical > 0 ? 'var(--crit)' : undefined} sq="var(--crit)" trend={critical > 0 ? '▲ active' : 'none'} />
      <Metric label="High"           value={high}     color={high > 0 ? 'var(--high)' : undefined} sq="var(--high)" trend={high > 0 ? '▲ active' : 'none'} />
      <Metric label="Hosts affected" value={hosts}    trend={`of monitored`} />
      <Metric label="Ingest (EPS)"   value={eps}      trend="last 60s" />
      <Metric label="Event types"    value={ruleTypes} trend="active rules" style={{ borderRight: 0 }} />
    </div>
  );
}
