import React, { useEffect, useState, useCallback } from 'react';
import { getAlerts, acknowledgeAlert, analyzeAlert } from '../api/client';

const SEVERITY_STYLES = {
  CRITICAL: { badge: 'bg-red-900 text-red-300 border-red-700',    dot: 'bg-red-500',    border: 'border-red-800' },
  HIGH:     { badge: 'bg-orange-900 text-orange-300 border-orange-700', dot: 'bg-orange-500', border: 'border-orange-800' },
  MEDIUM:   { badge: 'bg-yellow-900 text-yellow-300 border-yellow-700', dot: 'bg-yellow-500', border: 'border-yellow-800' },
  LOW:      { badge: 'bg-gray-800 text-gray-400 border-gray-700', dot: 'bg-gray-500',   border: 'border-gray-800' },
};

function AlertRow({ alert, onAck, onAnalyze, analyzing }) {
  const styles = SEVERITY_STYLES[alert.severity] || SEVERITY_STYLES.LOW;

  return (
    <div className={`bg-gray-900 border ${styles.border} rounded-lg p-4 flex items-start gap-4`}>
      <div className={`mt-1.5 w-2 h-2 rounded-full shrink-0 ${styles.dot}`} />

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className={`text-xs font-bold px-2 py-0.5 rounded border ${styles.badge}`}>
            {alert.severity}
          </span>
          <span className="text-gray-400 text-xs font-mono">{alert.host_id}</span>
          <span className="text-gray-600 text-xs ml-auto">
            {new Date(alert.created_at).toLocaleString()}
          </span>
        </div>

        <p className="text-gray-300 text-xs font-mono mt-1 truncate">
          Alert ID: {alert.id}
        </p>

        {alert.acknowledged && (
          <span className="inline-block mt-1 text-xs bg-green-900 text-green-400 px-2 py-0.5 rounded">
            Acknowledged
          </span>
        )}
      </div>

      <div className="flex gap-2 shrink-0">
        {!alert.acknowledged && (
          <>
            <button
              onClick={() => onAnalyze(alert.id)}
              disabled={analyzing === alert.id}
              className="text-xs px-3 py-1.5 rounded bg-indigo-800 hover:bg-indigo-700 text-indigo-200 transition-colors disabled:opacity-50"
            >
              {analyzing === alert.id ? 'Analyzing…' : 'AI Analyze'}
            </button>
            <button
              onClick={() => onAck(alert.id)}
              className="text-xs px-3 py-1.5 rounded bg-gray-700 hover:bg-gray-600 text-gray-200 transition-colors"
            >
              ACK
            </button>
          </>
        )}
      </div>
    </div>
  );
}

export default function AlertsPage({ newAlert, liveAiResult }) {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(null);
  const [filter, setFilter] = useState('active');

  const fetchAlerts = useCallback(async () => {
    try {
      const params = filter === 'active'
        ? { acknowledged: false, limit: 100 }
        : { limit: 100 };
      const { data } = await getAlerts(params);
      setAlerts(data);
    } catch (err) {
      console.error('Failed to fetch alerts:', err);
    } finally {
      setLoading(false);
    }
  }, [filter]);

  // Poll every 5s
  useEffect(() => {
    fetchAlerts();
    const t = setInterval(fetchAlerts, 5000);
    return () => clearInterval(t);
  }, [fetchAlerts]);

  // Refresh immediately when new alert arrives
  useEffect(() => {
    if (newAlert) fetchAlerts();
  }, [newAlert, fetchAlerts]);

  // Refresh immediately when AI result arrives (may have auto-acked an alert)
  useEffect(() => {
    if (liveAiResult) fetchAlerts();
  }, [liveAiResult, fetchAlerts]);

  const handleAck = async (id) => {
    try {
      await acknowledgeAlert(id);
      fetchAlerts();
    } catch (err) {
      console.error('ACK failed:', err);
    }
  };

  const handleAnalyze = async (id) => {
    setAnalyzing(id);
    try {
      await analyzeAlert(id);
    } catch (err) {
      console.error('Analyze failed:', err);
    } finally {
      setAnalyzing(null);
    }
  };

  const handleAckAll = async () => {
    const active = alerts.filter(a => !a.acknowledged);
    await Promise.allSettled(active.map(a => acknowledgeAlert(a.id)));
    fetchAlerts();
  };

  const activeCount = alerts.filter(a => !a.acknowledged).length;

  return (
    <div className="flex-1 overflow-auto p-6">
      {/* Header */}
      <div className="mb-6 flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-white text-xl font-semibold">Alerts</h2>
          <p className="text-gray-500 text-sm">
            {activeCount} active alert{activeCount !== 1 ? 's' : ''}
          </p>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          {/* Filter tabs */}
          <div className="flex border border-gray-700 rounded-lg overflow-hidden text-xs">
            {[['active', 'Active'], ['all', 'All']].map(([val, label]) => (
              <button
                key={val}
                onClick={() => setFilter(val)}
                className={`px-3 py-1.5 transition-colors ${
                  filter === val ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          {activeCount > 0 && (
            <button
              onClick={handleAckAll}
              className="text-xs px-3 py-1.5 rounded bg-gray-700 hover:bg-gray-600 text-gray-200 transition-colors"
            >
              Acknowledge All ({activeCount})
            </button>
          )}
        </div>
      </div>

      {/* Alert list */}
      {loading ? (
        <p className="text-gray-400 text-sm">Loading alerts…</p>
      ) : alerts.length === 0 ? (
        <div className="bg-gray-900 rounded-xl p-8 text-center border border-gray-800">
          <p className="text-gray-500 text-sm">
            {filter === 'active' ? 'No active alerts — system is clean.' : 'No alerts recorded yet.'}
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {alerts.map(alert => (
            <AlertRow
              key={alert.id}
              alert={alert}
              onAck={handleAck}
              onAnalyze={handleAnalyze}
              analyzing={analyzing}
            />
          ))}
        </div>
      )}
    </div>
  );
}
