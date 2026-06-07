import React, { useEffect, useState, useCallback } from 'react';
import { getAlerts, getEvents } from '../api/client';
import FacetRail from '../components/FacetRail';
import MetricsStrip from '../components/MetricsStrip';
import AlertsHistogram from '../components/AlertsHistogram';
import AlertsTable from '../components/AlertsTable';
import DetailFlyout from '../components/DetailFlyout';

export default function AlertsPage({ newAlert, liveAiResult, liveEvent }) {
  const [alerts,   setAlerts]   = useState([]);
  const [events,   setEvents]   = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [selected, setSelected] = useState(null);
  const [filter,   setFilter]   = useState('active');
  const [query,    setQuery]    = useState('');
  const [facets,   setFacets]   = useState({});
  const [page,     setPage]     = useState(0);
  const [spinning, setSpinning] = useState(false);

  const fetchAll = useCallback(async () => {
    try {
      const params = filter === 'active' ? { acknowledged: false, limit: 500 } : { limit: 500 };
      const [alertRes, eventRes] = await Promise.all([
        getAlerts(params),
        getEvents({ limit: 500 }),
      ]);
      const eventById = Object.fromEntries(eventRes.data.map(e => [String(e.id), e]));
      const alertsWithType = alertRes.data.map(a => ({
        ...a,
        event_type: eventById[String(a.event_id)]?.event_type ?? null,
      }));
      setAlerts(alertsWithType);
      setEvents(eventRes.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => {
    fetchAll();
    const t = setInterval(fetchAll, 10000);
    return () => clearInterval(t);
  }, [fetchAll]);

  useEffect(() => { if (newAlert)     fetchAll(); }, [newAlert,     fetchAll]);
  useEffect(() => { if (liveAiResult) fetchAll(); }, [liveAiResult, fetchAll]);

  function handleRefresh() {
    setSpinning(true);
    fetchAll().finally(() => setTimeout(() => setSpinning(false), 600));
  }

  function handleFacetToggle(field, value) {
    setFacets(prev => {
      const next = { ...prev };
      if (next[field] === value) delete next[field]; else next[field] = value;
      return next;
    });
    setPage(0);
  }

  const filtered = alerts.filter(a => {
    if (facets['host.name']      && a.host_id  !== facets['host.name'])      return false;
    if (facets['event.severity'] && a.severity !== facets['event.severity']) return false;
    if (facets['status']) {
      if (facets['status'] === 'acknowledged' && !a.acknowledged) return false;
      if (facets['status'] === 'open'         &&  a.acknowledged) return false;
    }
    if (query) {
      const q = query.toLowerCase();
      return a.host_id?.toLowerCase().includes(q) || a.severity?.toLowerCase().includes(q) || String(a.id).includes(q);
    }
    return true;
  });

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, background: 'var(--bg)' }}>

      {/* Query bar */}
      <div style={{ height: 44, flexShrink: 0, display: 'flex', alignItems: 'center', gap: 8, padding: '0 12px', background: 'var(--panel)', borderBottom: '1px solid var(--border)' }}>
        <div style={{ flex: 1, height: 30, display: 'flex', alignItems: 'center', gap: 8, background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, padding: '0 10px' }}>
          <i className="fa-solid fa-magnifying-glass" style={{ color: 'var(--muted)', fontSize: 12 }} />
          <input
            value={query}
            onChange={e => { setQuery(e.target.value); setPage(0); }}
            placeholder="Search host, severity, alert ID…"
            spellCheck={false}
            style={{ flex: 1, background: 'transparent', border: 0, outline: 0, color: 'var(--text)', fontFamily: 'var(--mono)', fontSize: 12.5 }}
          />
        </div>
        <div style={{ display: 'flex', border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden', fontSize: 12 }}>
          {[['active','Active'],['all','All']].map(([v,l]) => (
            <button key={v} onClick={() => { setFilter(v); setPage(0); }}
              style={{ padding: '5px 12px', background: filter === v ? 'var(--panel-3)' : 'transparent', color: filter === v ? 'var(--text)' : 'var(--text-2)', border: 'none', cursor: 'pointer', fontFamily: 'var(--sans)' }}>
              {l}
            </button>
          ))}
        </div>
        <button onClick={handleRefresh}
          style={{ height: 30, padding: '0 13px', borderRadius: 6, cursor: 'pointer', background: 'var(--accent)', border: 'none', color: '#fff', fontSize: 12, fontWeight: 500, fontFamily: 'var(--sans)', display: 'inline-flex', alignItems: 'center', gap: 7 }}>
          <i className={`fa-solid fa-rotate-right${spinning ? ' fa-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* 3-column body */}
      <div style={{ flex: 1, display: 'flex', minHeight: 0 }}>
        <FacetRail alerts={alerts} activeFilters={facets} onToggle={handleFacetToggle} />

        <section style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <MetricsStrip alerts={filtered} events={events} />
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflowY: 'auto' }}>
            <AlertsHistogram events={events} />
            {loading ? (
              <div style={{ flex: 1, display: 'grid', placeItems: 'center', color: 'var(--muted)', fontFamily: 'var(--mono)', fontSize: 12 }}>
                Loading alerts…
              </div>
            ) : (
              <AlertsTable
                alerts={filtered}
                selectedId={selected?.id}
                onSelect={a => setSelected(prev => prev?.id === a.id ? null : a)}
                page={page}
                setPage={setPage}
              />
            )}
          </div>
        </section>

        <DetailFlyout
          alert={selected}
          liveEvent={liveEvent}
          onClose={() => setSelected(null)}
          onRefresh={fetchAll}
        />
      </div>
    </div>
  );
}
