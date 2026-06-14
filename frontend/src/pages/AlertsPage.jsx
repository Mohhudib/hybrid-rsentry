import React, { useEffect, useState, useCallback } from 'react';
import { getAlerts, getEvents, acknowledgeAllAlerts, clearAllAlerts } from '../api/client';
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
  const [filter,   setFilter]   = useState('all');
  const [query,    setQuery]    = useState('');
  const [facets,   setFacets]   = useState({});
  const [page,     setPage]     = useState(0);
  const [spinning, setSpinning] = useState(false);
  const [railOpen, setRailOpen] = useState(true);
  const [acking,      setAcking]      = useState(false);
  const [clearing,    setClearing]    = useState(false);
  const [exportOpen,  setExportOpen]  = useState(false);
  const [refreshInterval, setRefreshInterval] = useState(10000);

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
        file_path:  eventById[String(a.event_id)]?.file_path ?? null,
        process_name: eventById[String(a.event_id)]?.process_name ?? null,
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
    if (refreshInterval === 0) return;
    const t = setInterval(fetchAll, refreshInterval);
    return () => clearInterval(t);
  }, [fetchAll, refreshInterval]);

  useEffect(() => { if (newAlert)     fetchAll(); }, [newAlert,     fetchAll]);
  useEffect(() => { if (liveAiResult) fetchAll(); }, [liveAiResult, fetchAll]);

  function handleRefresh() {
    setSpinning(true);
    fetchAll().finally(() => setTimeout(() => setSpinning(false), 600));
  }

  async function handleBulkAck() {
    if (!window.confirm('Acknowledge all open alerts?')) return;
    setAcking(true);
    try {
      await acknowledgeAllAlerts();
      await fetchAll();
    } catch (err) {
      console.error(err);
    } finally {
      setAcking(false);
    }
  }

  async function handleClearAll() {
    if (!window.confirm('Clear all open alerts? This marks them all as acknowledged.')) return;
    setClearing(true);
    try {
      await clearAllAlerts();
      await fetchAll();
    } catch (err) {
      console.error(err);
    } finally {
      setClearing(false);
    }
  }

  function handleExport(format) {
    const params = new URLSearchParams({ limit: 1000 });
    if (filter === 'active') params.set('acknowledged', 'false');
    window.open(`/api/alerts/export/${format}?${params}`, '_blank');
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
      return (
        a.host_id?.toLowerCase().includes(q) ||
        a.severity?.toLowerCase().includes(q) ||
        a.event_type?.toLowerCase().includes(q) ||
        a.file_path?.toLowerCase().includes(q) ||
        a.process_name?.toLowerCase().includes(q) ||
        String(a.id).includes(q)
      );
    }
    return true;
  });

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, background: 'var(--bg)' }}>

      {/* Query bar */}
      <div style={{ height: 44, flexShrink: 0, display: 'flex', alignItems: 'center', gap: 8, padding: '0 12px', background: 'var(--panel)', borderBottom: '1px solid var(--border)' }}>
        <div style={{ flex: 1, height: 30, display: 'flex', alignItems: 'center', gap: 8, background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, padding: '0 10px' }}>
          <button
            onClick={() => setRailOpen(v => !v)}
            title={railOpen ? 'Hide filters' : 'Show filters'}
            style={{ flexShrink: 0, width: 22, height: 22, display: 'grid', placeItems: 'center', borderRadius: 4, border: 'none', background: railOpen ? 'var(--accent-dim)' : 'transparent', color: railOpen ? 'var(--accent)' : 'var(--muted)', cursor: 'pointer' }}>
            <i className="fa-solid fa-sliders" style={{ fontSize: 11 }} />
          </button>
          <i className="fa-solid fa-magnifying-glass" style={{ color: 'var(--muted)', fontSize: 12 }} />
          <input
            value={query}
            onChange={e => { setQuery(e.target.value); setPage(0); }}
            placeholder="Search host, severity, file path, process, alert ID…"
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
        {/* Auto-refresh interval */}
        <select
          value={refreshInterval}
          onChange={e => setRefreshInterval(Number(e.target.value))}
          style={{ height: 30, padding: '0 8px', borderRadius: 6, background: 'var(--panel-2)', border: '1px solid var(--border)', color: 'var(--text-2)', fontSize: 12, fontFamily: 'var(--sans)', cursor: 'pointer' }}>
          <option value={5000}>5s</option>
          <option value={10000}>10s</option>
          <option value={30000}>30s</option>
          <option value={0}>Off</option>
        </select>
        <button onClick={handleRefresh}
          style={{ height: 30, padding: '0 13px', borderRadius: 6, cursor: 'pointer', background: 'var(--accent)', border: 'none', color: '#fff', fontSize: 12, fontWeight: 500, fontFamily: 'var(--sans)', display: 'inline-flex', alignItems: 'center', gap: 7 }}>
          <i className={`fa-solid fa-rotate-right${spinning ? ' fa-spin' : ''}`} />
          Refresh
        </button>
        <button onClick={handleBulkAck} disabled={acking}
          title="Acknowledge all open alerts"
          style={{ height: 30, padding: '0 13px', borderRadius: 6, cursor: acking ? 'not-allowed' : 'pointer', background: 'var(--panel-2)', border: '1px solid var(--border)', color: 'var(--text-2)', fontSize: 12, fontFamily: 'var(--sans)', display: 'inline-flex', alignItems: 'center', gap: 7, opacity: acking ? 0.6 : 1 }}>
          <i className="fa-solid fa-check-double" />
          Bulk ACK
        </button>
        <div style={{ position: 'relative' }}>
          <button
            onClick={() => setExportOpen(v => !v)}
            title="Export alerts"
            style={{ height: 30, padding: '0 13px', borderRadius: 6, cursor: 'pointer', background: 'var(--panel-2)', border: '1px solid var(--border)', color: 'var(--text-2)', fontSize: 12, fontFamily: 'var(--sans)', display: 'inline-flex', alignItems: 'center', gap: 7 }}>
            <i className="fa-solid fa-file-export" />
            Export
            <i className="fa-solid fa-chevron-down" style={{ fontSize: 9 }} />
          </button>
          {exportOpen && (
            <div
              onMouseLeave={() => setExportOpen(false)}
              style={{ position: 'absolute', top: 34, right: 0, background: 'var(--panel-2)', border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden', zIndex: 50, minWidth: 140, boxShadow: '0 4px 12px rgba(0,0,0,0.4)' }}>
              <button
                onClick={() => { handleExport('csv'); setExportOpen(false); }}
                style={{ width: '100%', display: 'flex', alignItems: 'center', gap: 9, padding: '8px 14px', background: 'none', border: 'none', color: 'var(--text-2)', fontSize: 12, fontFamily: 'var(--sans)', cursor: 'pointer', textAlign: 'left' }}>
                <i className="fa-solid fa-file-csv" style={{ color: 'var(--accent)', width: 14 }} />
                CSV
                <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--muted)' }}>Excel</span>
              </button>
              <button
                onClick={() => { handleExport('txt'); setExportOpen(false); }}
                style={{ width: '100%', display: 'flex', alignItems: 'center', gap: 9, padding: '8px 14px', background: 'none', border: 'none', color: 'var(--text-2)', fontSize: 12, fontFamily: 'var(--sans)', cursor: 'pointer', textAlign: 'left', borderTop: '1px solid var(--border)' }}>
                <i className="fa-solid fa-file-lines" style={{ color: 'var(--accent)', width: 14 }} />
                TXT
                <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--muted)' }}>Readable</span>
              </button>
            </div>
          )}
        </div>
        <button onClick={handleClearAll} disabled={clearing}
          title="Clear all open alerts (mark as acknowledged)"
          style={{ height: 30, padding: '0 13px', borderRadius: 6, cursor: clearing ? 'not-allowed' : 'pointer', background: 'var(--panel-2)', border: '1px solid var(--border)', color: 'var(--crit)', fontSize: 12, fontFamily: 'var(--sans)', display: 'inline-flex', alignItems: 'center', gap: 7, opacity: clearing ? 0.6 : 1 }}>
          <i className="fa-solid fa-trash-can" />
          Clear
        </button>
      </div>

      {/* 3-column body */}
      <div style={{ flex: 1, display: 'flex', minHeight: 0 }}>
        {railOpen && <FacetRail alerts={alerts} activeFilters={facets} onToggle={handleFacetToggle} onClose={() => setRailOpen(false)} />}

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

        {selected && (
          <DetailFlyout
            alert={selected}
            liveEvent={liveEvent}
            liveAiResult={liveAiResult}
            onClose={() => setSelected(null)}
            onRefresh={fetchAll}
          />
        )}
      </div>
    </div>
  );
}
