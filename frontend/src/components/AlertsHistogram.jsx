import React, { useMemo } from 'react';

const SEV_CLASS = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)' };
const BUCKET_MINS = 30;
const BUCKETS = 48; // 24h

function buildBuckets(events) {
  const now = Date.now();
  const buckets = Array.from({ length: BUCKETS }, () => ({ CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }));
  for (const ev of events) {
    const age = now - new Date(ev.timestamp).getTime();
    const idx = BUCKETS - 1 - Math.floor(age / (BUCKET_MINS * 60 * 1000));
    if (idx >= 0 && idx < BUCKETS) {
      const sev = ev.severity || 'LOW';
      buckets[idx][sev] = (buckets[idx][sev] || 0) + 1;
    }
  }
  return buckets;
}

function axisLabels() {
  const labels = [];
  const now = new Date();
  for (let i = 6; i >= 0; i--) {
    const d = new Date(now - i * 4 * 60 * 60 * 1000);
    labels.push(`${String(d.getHours()).padStart(2, '0')}:00`);
  }
  return labels;
}

export default function AlertsHistogram({ events }) {
  const buckets = useMemo(() => buildBuckets(events || []), [events]);
  const maxTotal = Math.max(...buckets.map(b => b.CRITICAL + b.HIGH + b.MEDIUM + b.LOW), 1);

  return (
    <div style={{ background: 'var(--panel)', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
      {/* Head */}
      <div style={{ height: 38, display: 'flex', alignItems: 'center', gap: 10, padding: '0 16px', borderBottom: '1px solid var(--border-soft)' }}>
        <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--text)' }}>Alerts over time</span>
        <span style={{ fontSize: 11, color: 'var(--muted)', fontFamily: 'var(--mono)' }}>— 30 min interval · count of events</span>
        <span style={{ flex: 1 }} />
        <div style={{ display: 'flex', gap: 12 }}>
          {['CRITICAL','HIGH','MEDIUM','LOW'].map(s => (
            <span key={s} style={{ fontSize: 11, color: 'var(--text-2)', display: 'inline-flex', alignItems: 'center', gap: 6, fontFamily: 'var(--mono)' }}>
              <span style={{ width: 9, height: 9, borderRadius: 2, background: SEV_CLASS[s], display: 'inline-block' }} />
              {s[0] + s.slice(1).toLowerCase()}
            </span>
          ))}
        </div>
      </div>

      {/* Bars */}
      <div style={{ height: 132, padding: '14px 16px 10px', display: 'flex', alignItems: 'flex-end', gap: 2, position: 'relative' }}>
        {/* Grid lines */}
        {[0.25, 0.5, 0.75].map(f => (
          <div key={f} style={{ position: 'absolute', left: 16, right: 16, borderTop: '1px dashed var(--border)', bottom: 10 + f * 108, zIndex: 0 }} />
        ))}
        {buckets.map((b, i) => {
          const total = b.CRITICAL + b.HIGH + b.MEDIUM + b.LOW;
          return (
            <div
              key={i}
              className="hbar-col"
              title={`${total} events — crit ${b.CRITICAL}, high ${b.HIGH}, med ${b.MEDIUM}, low ${b.LOW}`}
              style={{ position: 'relative', zIndex: 1 }}
            >
              {[['LOW',b.LOW],['MEDIUM',b.MEDIUM],['HIGH',b.HIGH],['CRITICAL',b.CRITICAL]].map(([sev, v]) => (
                v > 0 ? (
                  <div
                    key={sev}
                    className="hbar-seg"
                    style={{ width: '100%', height: `${(v / maxTotal) * 108}px`, background: SEV_CLASS[sev] }}
                  />
                ) : null
              ))}
            </div>
          );
        })}
      </div>

      {/* Axis */}
      <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0 16px 10px', fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--muted)' }}>
        {axisLabels().map((l, i) => <span key={i}>{l}</span>)}
      </div>
    </div>
  );
}
