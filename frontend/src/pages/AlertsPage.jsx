import React, { useEffect, useState, useCallback } from 'react';
import { getAlerts, acknowledgeAlert, analyzeAlert } from '../api/client';
import { formatDistanceToNow } from 'date-fns';

const SEVERITY_COLORS = {
  CRITICAL: 'bg-red-600 text-white',
  HIGH: 'bg-orange-500 text-white',
  MEDIUM: 'bg-yellow-400 text-gray-900',
  LOW: 'bg-blue-400 text-white',
};

const SEVERITY_BORDER = {
  CRITICAL: 'border-l-red-500',
  HIGH: 'border-l-orange-500',
  MEDIUM: 'border-l-yellow-400',
  LOW: 'border-l-blue-400',
};

export default function AlertsPage({ newAlert }) {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('ALL');
  const [showAcked, setShowAcked] = useState(false);
  const [analyzing, setAnalyzing] = useState(new Set());
  const [analyzed, setAnalyzed] = useState(new Set());

  const fetchAlerts = useCallback(async () => {
    try {
      const { data } = await getAlerts({ limit: 500 });
      setAlerts(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAlerts();
    const t = setInterval(fetchAlerts, 5000);
    return () => clearInterval(t);
  }, [fetchAlerts]);

  useEffect(() => {
    if (!newAlert) return;
    setAlerts((prev) => {
      if (prev.find((a) => a.id === newAlert.alert_id)) return prev;
      return [{ id: newAlert.alert_id, host_id: newAlert.host_id, severity: newAlert.severity, acknowledged: false, created_at: new Date().toISOString(), _live: true }, ...prev];
    });
  }, [newAlert]);

  const handleAck = async (id) => {
    try {
      await acknowledgeAlert(id);
      setAlerts((prev) => prev.map((a) => a.id === id ? { ...a, acknowledged: true } : a));
    } catch (err) { console.error(err); }
  };

  const handleAnalyze = async (id) => {
    if (analyzing.has(id)) return;
    setAnalyzing(prev => new Set([...prev, id]));
    try {
      await analyzeAlert(id);
      setAnalyzed(prev => new Set([...prev, id]));
      // Result arrives via WebSocket → auto-ack if false positive
    } catch (err) {
      console.error(err);
    } finally {
      setAnalyzing(prev => { const n = new Set(prev); n.delete(id); return n; });
    }
  };

  // Active (unacked) alert counts — matches dashboard StatsBar
  const activeAlerts = alerts.filter(a => !a.acknowledged);
  const counts = activeAlerts.reduce((acc, a) => {
    acc[a.severity] = (acc[a.severity] || 0) + 1;
    return acc;
  }, {});

  const filtered = alerts
    .filter((a) => filter === 'ALL' || a.severity === filter)
    .filter((a) => showAcked || !a.acknowledged);

  return (
    <div className="flex-1 overflow-auto p-6">
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h2 className="text-white text-xl font-semibold">Alerts</h2>
          <p className="text-gray-500 text-sm">All detected ransomware activity</p>
        </div>
        <div className="flex items-center gap-3 text-xs text-gray-500">
          <span><span className="text-white font-bold">{activeAlerts.length}</span> active</span>
          <span><span className="text-gray-400 font-bold">{alerts.length}</span> total</span>
        </div>
      </div>

      {/* Filter bar */}
      <div className="flex items-center gap-3 mb-4 flex-wrap">
        {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            className={`px-3 py-1.5 text-xs rounded-lg font-medium transition-all flex items-center gap-1.5 ${
              filter === s ? 'bg-indigo-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            {s}
            {s !== 'ALL' && counts[s] ? (
              <span className="bg-black bg-opacity-30 px-1.5 py-0.5 rounded text-xs">{counts[s]}</span>
            ) : null}
          </button>
        ))}
        <label className="ml-auto flex items-center gap-2 text-xs text-gray-400 cursor-pointer">
          <input type="checkbox" checked={showAcked} onChange={(e) => setShowAcked(e.target.checked)} className="rounded" />
          Show acknowledged
        </label>
      </div>

      {loading ? (
        <p className="text-gray-400 text-sm">Loading…</p>
      ) : filtered.length === 0 ? (
        <div className="bg-gray-900 rounded-xl p-8 text-center">
          <p className="text-gray-500">No alerts found.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((alert) => (
            <div
              key={alert.id}
              className={`bg-gray-900 border border-gray-800 border-l-4 ${SEVERITY_BORDER[alert.severity]} rounded-xl px-4 py-3 flex items-center gap-4 ${alert.acknowledged ? 'opacity-50' : ''}`}
            >
              <span className={`text-xs font-bold px-2 py-1 rounded shrink-0 ${SEVERITY_COLORS[alert.severity]}`}>
                {alert.severity}
              </span>
              <div className="flex-1 min-w-0">
                <p className="text-white text-sm font-mono">{alert.host_id}</p>
                <p className="text-gray-500 text-xs font-mono mt-0.5">ID: {alert.id}</p>
              </div>
              <p className="text-gray-500 text-xs shrink-0">
                {formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}
              </p>
              {alert.acknowledged ? (
                <span className="text-xs text-green-500 shrink-0">Acknowledged</span>
              ) : (
                <div className="flex items-center gap-2 shrink-0">
                  {analyzed.has(alert.id) ? (
                    <span className="text-xs text-indigo-400">AI queued ✓</span>
                  ) : (
                    <button
                      onClick={() => handleAnalyze(alert.id)}
                      disabled={analyzing.has(alert.id)}
                      title="Send to NVIDIA AI — auto-acknowledges if false positive"
                      className="text-xs bg-indigo-900/50 hover:bg-indigo-700 text-indigo-300 hover:text-white px-3 py-1.5 rounded-lg transition-colors disabled:opacity-50 border border-indigo-700/50"
                    >
                      {analyzing.has(alert.id) ? '…' : 'AI Analyze'}
                    </button>
                  )}
                  <button
                    onClick={() => handleAck(alert.id)}
                    className="text-xs bg-gray-700 hover:bg-green-700 text-gray-300 hover:text-white px-3 py-1.5 rounded-lg transition-colors"
                  >
                    ACK
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
