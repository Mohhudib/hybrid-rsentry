import React, { useEffect, useState, useCallback } from 'react';
import { getAlerts, acknowledgeAlert } from '../api/client';
import { formatDistanceToNow } from 'date-fns';

const SEVERITY_COLORS = {
  CRITICAL: 'bg-red-600 text-white',
  HIGH: 'bg-orange-500 text-white',
  MEDIUM: 'bg-yellow-400 text-gray-900',
  LOW: 'bg-blue-400 text-white',
};

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

export default function AlertFeed({ newAlert }) {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('ALL');

  const fetchAlerts = useCallback(async () => {
    try {
      const params = filter !== 'ALL' ? { severity: filter } : {};
      const { data } = await getAlerts({ ...params, limit: 100 });
      setAlerts(data);
    } catch (err) {
      console.error('Failed to fetch alerts:', err);
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => { fetchAlerts(); }, [fetchAlerts]);

  // Inject live WS alerts at the top
  useEffect(() => {
    if (!newAlert) return;
    setAlerts((prev) => {
      const exists = prev.find((a) => a.id === newAlert.alert_id);
      if (exists) return prev;
      return [
        {
          id: newAlert.alert_id,
          host_id: newAlert.host_id,
          severity: newAlert.severity,
          acknowledged: false,
          created_at: new Date().toISOString(),
          _live: true,
        },
        ...prev,
      ];
    });
  }, [newAlert]);

  const handleAcknowledge = async (id) => {
    try {
      await acknowledgeAlert(id);
      setAlerts((prev) =>
        prev.map((a) => (a.id === id ? { ...a, acknowledged: true } : a))
      );
    } catch (err) {
      console.error('Acknowledge failed:', err);
    }
  };

  const filtered = filter === 'ALL'
    ? alerts
    : alerts.filter((a) => a.severity === filter);

  const sorted = [...filtered].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
  );

  return (
    <div className="bg-gray-900 rounded-xl p-4 h-full flex flex-col">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-white text-lg font-semibold">Live Alert Feed</h2>
        <div className="flex gap-2">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => (
            <button
              key={s}
              onClick={() => setFilter(s)}
              className={`px-2 py-1 text-xs rounded font-medium transition-all ${
                filter === s
                  ? 'bg-indigo-600 text-white'
                  : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <p className="text-gray-400 text-sm">Loading alerts...</p>
      ) : sorted.length === 0 ? (
        <p className="text-gray-500 text-sm italic">No alerts. System nominal.</p>
      ) : (
        <div className="overflow-y-auto flex-1 space-y-2 pr-1">
          {sorted.map((alert) => (
            <AlertRow
              key={alert.id}
              alert={alert}
              onAcknowledge={handleAcknowledge}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function AlertRow({ alert, onAcknowledge }) {
  return (
    <div
      className={`rounded-lg p-3 flex items-start justify-between gap-3 border ${
        alert.acknowledged
          ? 'border-gray-700 opacity-50'
          : 'border-gray-600'
      } ${alert._live ? 'animate-pulse-once' : ''}`}
      style={{ backgroundColor: '#1e2130' }}
    >
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span
            className={`text-xs font-bold px-2 py-0.5 rounded ${SEVERITY_COLORS[alert.severity]}`}
          >
            {alert.severity}
          </span>
          <span className="text-gray-300 text-xs font-mono truncate">{alert.host_id}</span>
          <span className="text-gray-500 text-xs">
            {formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}
          </span>
        </div>
        <p className="text-gray-400 text-xs mt-1 truncate">ID: {alert.id?.slice(0, 8)}…</p>
      </div>
      {!alert.acknowledged && (
        <button
          onClick={() => onAcknowledge(alert.id)}
          className="text-xs bg-gray-700 hover:bg-green-700 text-gray-300 hover:text-white px-2 py-1 rounded transition-colors shrink-0"
        >
          ACK
        </button>
      )}
    </div>
  );
}
