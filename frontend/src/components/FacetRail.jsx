import React, { useState, useMemo } from 'react';

function countBy(arr, fn) {
  const m = {};
  arr.forEach(x => { const k = fn(x); if (k) m[k] = (m[k] || 0) + 1; });
  return m;
}

function FacetGroup({ field, values, colorFor, activeFilters, onToggle }) {
  const [collapsed, setCollapsed] = useState(false);
  const max = Math.max(...Object.values(values), 1);
  const sorted = Object.entries(values).sort((a, b) => b[1] - a[1]).slice(0, 8);

  return (
    <div style={{ borderBottom: '1px solid var(--border-soft)' }}>
      <div className={`facet-head${collapsed ? ' collapsed' : ''}`} onClick={() => setCollapsed(c => !c)}>
        <i className={`fa-solid fa-chevron-down facet-chev`} />
        <span style={{ fontFamily: 'var(--mono)', fontSize: 11.5, flex: 1, letterSpacing: '-0.01em' }}>{field}</span>
        <span style={{ fontSize: 10, color: 'var(--muted)', fontFamily: 'var(--mono)' }}>{Object.keys(values).length}</span>
      </div>
      <div className="facet-values" style={{ padding: '0 8px 8px' }}>
        {sorted.map(([k, c]) => {
          const pct = Math.round((c / max) * 100);
          const active = activeFilters[field] === k;
          return (
            <div key={k} className="fval" onClick={() => onToggle(field, k)} style={{ background: active ? 'var(--accent-dim)' : undefined }}>
              <span style={{ position: 'absolute', left: 0, top: 0, bottom: 0, width: `${pct}%`, background: 'var(--accent-dim)', borderRadius: 5, zIndex: 0 }} />
              <span style={{ position: 'relative', zIndex: 1, flex: 1, fontFamily: 'var(--mono)', fontSize: 11.5, color: colorFor ? colorFor(k) : 'var(--text)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {colorFor && <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: 2, background: colorFor(k), marginRight: 4, verticalAlign: 'middle' }} />}
                {k}
              </span>
              <span style={{ position: 'relative', zIndex: 1, fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--muted)' }}>{c}</span>
              <span className="fadd" style={{ position: 'relative', zIndex: 1 }}><i className="fa-solid fa-plus" /></span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

const SEV_COLOR = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)' };

export default function FacetRail({ alerts, activeFilters, onToggle }) {
  const [search, setSearch] = useState('');

  const groups = useMemo(() => [
    {
      field: 'host.name',
      values: countBy(alerts, a => a.host_id),
    },
    {
      field: 'event.severity',
      values: countBy(alerts, a => a.severity),
      colorFor: v => SEV_COLOR[v] || 'var(--muted)',
    },
    {
      field: 'status',
      values: countBy(alerts, a => a.acknowledged ? 'acknowledged' : 'open'),
    },
  ], [alerts]);

  const visible = search
    ? groups.filter(g => g.field.includes(search.toLowerCase()) || Object.keys(g.values).some(k => k.toLowerCase().includes(search.toLowerCase())))
    : groups;

  return (
    <aside style={{ width: 248, flexShrink: 0, background: 'var(--panel)', borderRight: '1px solid var(--border)', overflowY: 'auto', paddingBottom: 30 }}>
      <div style={{ margin: '10px 12px 8px', height: 28, display: 'flex', alignItems: 'center', gap: 7, background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, padding: '0 9px' }}>
        <i className="fa-solid fa-filter" style={{ color: 'var(--muted)', fontSize: 11 }} />
        <input
          placeholder="Filter fields…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{ flex: 1, background: 'transparent', border: 0, outline: 0, color: 'var(--text)', fontSize: 12, fontFamily: 'var(--sans)' }}
        />
      </div>
      {visible.map(g => (
        <FacetGroup
          key={g.field}
          field={g.field}
          values={g.values}
          colorFor={g.colorFor}
          activeFilters={activeFilters}
          onToggle={onToggle}
        />
      ))}
    </aside>
  );
}
