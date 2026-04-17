import React, { useEffect, useState, useCallback } from 'react';
import { getAlerts, forensicExport } from '../api/client';
import { format } from 'date-fns';

const SEVERITY_COLORS = {
  CRITICAL: 'bg-red-600 text-white',
  HIGH: 'bg-orange-500 text-white',
  MEDIUM: 'bg-yellow-400 text-gray-900',
  LOW: 'bg-blue-400 text-white',
};

function exportAllAsJSON(alerts) {
  const blob = new Blob([JSON.stringify(alerts, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `rsentry_report_${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function ReportsPage() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(new Set());
  const [exporting, setExporting] = useState(null);
  const [filterSev, setFilterSev] = useState('ALL');
  const [filterAck, setFilterAck] = useState('ALL');

  const fetchAlerts = useCallback(async () => {
    try {
      const { data } = await getAlerts({ limit: 500 });
      setAlerts(data);
    } catch (err) { console.error(err); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchAlerts(); }, [fetchAlerts]);

  const handleExportOne = async (id) => {
    setExporting(id);
    try {
      const { data } = await forensicExport(id);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `forensic_${id.slice(0, 8)}_${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) { console.error(err); }
    finally { setExporting(null); }
  };

  const handleExportSelected = async () => {
    const ids = [...selected];
    for (const id of ids) await handleExportOne(id);
  };

  const toggleSelect = (id) => {
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const toggleAll = () => {
    if (selected.size === filtered.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(filtered.map((a) => a.id)));
    }
  };

  const filtered = alerts
    .filter((a) => filterSev === 'ALL' || a.severity === filterSev)
    .filter((a) => {
      if (filterAck === 'PENDING') return !a.acknowledged;
      if (filterAck === 'ACKED') return a.acknowledged;
      return true;
    });

  // Summary counts — use unacked only to match dashboard StatsBar
  const activeAlerts = alerts.filter(a => !a.acknowledged);
  const activeCritical = activeAlerts.filter(a => a.severity === 'CRITICAL').length;
  const activeHigh = activeAlerts.filter(a => a.severity === 'HIGH').length;

  return (
    <div className="flex-1 overflow-auto p-6">
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h2 className="text-white text-xl font-semibold">Reports</h2>
          <p className="text-gray-500 text-sm">Export forensic data for alerts and incidents</p>
        </div>
        <div className="flex gap-2">
          {selected.size > 0 && (
            <button
              onClick={handleExportSelected}
              className="px-4 py-2 text-sm bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg font-medium transition-colors"
            >
              Export Selected ({selected.size})
            </button>
          )}
          <button
            onClick={() => exportAllAsJSON(filtered)}
            className="px-4 py-2 text-sm bg-gray-700 hover:bg-gray-600 text-white rounded-lg font-medium transition-colors"
          >
            Export All as JSON
          </button>
        </div>
      </div>

      {/* Summary cards — same numbers as dashboard StatsBar (active/unacked only) */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <div className="bg-gray-900 border border-gray-800 rounded-xl px-5 py-4">
          <p className="text-gray-500 text-xs uppercase tracking-wider">Active Alerts</p>
          <p className="text-2xl font-bold text-white mt-1">{activeAlerts.length}</p>
          <p className="text-gray-600 text-xs mt-0.5">unacknowledged</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl px-5 py-4">
          <p className="text-gray-500 text-xs uppercase tracking-wider">Active Critical</p>
          <p className="text-2xl font-bold text-red-400 mt-1">{activeCritical}</p>
          <p className="text-gray-600 text-xs mt-0.5">immediate action</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl px-5 py-4">
          <p className="text-gray-500 text-xs uppercase tracking-wider">Active High</p>
          <p className="text-2xl font-bold text-orange-400 mt-1">{activeHigh}</p>
          <p className="text-gray-600 text-xs mt-0.5">investigate now</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl px-5 py-4">
          <p className="text-gray-500 text-xs uppercase tracking-wider">Total (All-Time)</p>
          <p className="text-2xl font-bold text-gray-400 mt-1">{alerts.length}</p>
          <p className="text-gray-600 text-xs mt-0.5">incl. acknowledged</p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 mb-4 flex-wrap">
        <div className="flex gap-1">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => (
            <button
              key={s}
              onClick={() => setFilterSev(s)}
              className={`px-3 py-1.5 text-xs rounded-lg font-medium transition-all ${
                filterSev === s ? 'bg-indigo-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
              }`}
            >
              {s}
            </button>
          ))}
        </div>
        <div className="flex gap-1 ml-4">
          {['ALL', 'PENDING', 'ACKED'].map((s) => (
            <button
              key={s}
              onClick={() => setFilterAck(s)}
              className={`px-3 py-1.5 text-xs rounded-lg font-medium transition-all ${
                filterAck === s ? 'bg-gray-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
              }`}
            >
              {s}
            </button>
          ))}
        </div>
        <p className="ml-auto text-xs text-gray-500">{filtered.length} alerts</p>
      </div>

      {/* Table */}
      {loading ? (
        <p className="text-gray-400 text-sm">Loading…</p>
      ) : filtered.length === 0 ? (
        <div className="bg-gray-900 rounded-xl p-8 text-center">
          <p className="text-gray-500">No alerts match the current filter.</p>
        </div>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          {/* Table header */}
          <div className="grid grid-cols-[auto_1fr_auto_auto_auto_auto] gap-4 px-4 py-2 border-b border-gray-800 text-xs text-gray-500 uppercase tracking-wider">
            <input
              type="checkbox"
              checked={selected.size === filtered.length && filtered.length > 0}
              onChange={toggleAll}
              className="rounded"
            />
            <span>Alert ID / Host</span>
            <span>Severity</span>
            <span>Status</span>
            <span>Time</span>
            <span>Export</span>
          </div>

          {/* Rows */}
          <div className="divide-y divide-gray-800">
            {filtered.map((alert) => (
              <div
                key={alert.id}
                className={`grid grid-cols-[auto_1fr_auto_auto_auto_auto] gap-4 px-4 py-3 items-center text-sm ${
                  alert.acknowledged ? 'opacity-50' : ''
                }`}
              >
                <input
                  type="checkbox"
                  checked={selected.has(alert.id)}
                  onChange={() => toggleSelect(alert.id)}
                  className="rounded"
                />
                <div className="min-w-0">
                  <p className="text-white font-mono text-xs">{alert.id}</p>
                  <p className="text-gray-500 text-xs mt-0.5">{alert.host_id}</p>
                </div>
                <span className={`text-xs font-bold px-2 py-1 rounded ${SEVERITY_COLORS[alert.severity]}`}>
                  {alert.severity}
                </span>
                <span className={`text-xs ${alert.acknowledged ? 'text-green-500' : 'text-yellow-500'}`}>
                  {alert.acknowledged ? 'ACK' : 'PENDING'}
                </span>
                <span className="text-gray-500 text-xs whitespace-nowrap">
                  {format(new Date(alert.created_at), 'MMM d, HH:mm:ss')}
                </span>
                <button
                  onClick={() => handleExportOne(alert.id)}
                  disabled={exporting === alert.id}
                  className="text-xs bg-gray-800 hover:bg-indigo-700 text-gray-300 hover:text-white px-3 py-1.5 rounded-lg transition-colors whitespace-nowrap"
                >
                  {exporting === alert.id ? 'Exporting…' : 'Export JSON'}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
