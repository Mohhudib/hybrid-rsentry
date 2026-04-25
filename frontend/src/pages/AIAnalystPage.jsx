import React, { useState, useRef } from 'react';
import { getEvents } from '../api/client';
import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const RISK_COLORS = {
  CRITICAL: { text: 'text-red-400',    bg: 'bg-red-900/30',    border: 'border-red-700' },
  HIGH:     { text: 'text-orange-400', bg: 'bg-orange-900/30', border: 'border-orange-700' },
  MEDIUM:   { text: 'text-yellow-400', bg: 'bg-yellow-900/20', border: 'border-yellow-700/50' },
  LOW:      { text: 'text-green-400',  bg: 'bg-green-900/20',  border: 'border-green-700/50' },
  UNKNOWN:  { text: 'text-gray-400',   bg: 'bg-gray-800',      border: 'border-gray-700' },
};

const STATUS_COLORS = {
  STABLE:       { text: 'text-green-400',  icon: '✅' },
  UNDER_ATTACK: { text: 'text-red-400',    icon: '🚨' },
  ANOMALOUS:    { text: 'text-orange-400', icon: '⚠️' },
  RECOVERING:   { text: 'text-yellow-400', icon: '🔄' },
  UNKNOWN:      { text: 'text-gray-400',   icon: '❓' },
};

const CONFIDENCE_COLORS = {
  HIGH:   'text-green-400',
  MEDIUM: 'text-yellow-400',
  LOW:    'text-gray-500',
};

function AnalysisCard({ analysis, isNew, timestamp }) {
  const risk = RISK_COLORS[analysis.risk_level] || RISK_COLORS.UNKNOWN;
  return (
    <div className={`rounded-lg border p-3 transition-all ${risk.bg} ${risk.border} ${isNew ? 'ring-1 ring-indigo-500' : ''}`}>
      <div className="flex items-start justify-between gap-2 mb-2">
        <div className="min-w-0">
          <p className={`text-xs font-bold ${risk.text}`}>{analysis.threat_type}</p>
          <p className="text-gray-400 text-xs mt-0.5 truncate">{analysis.technique}</p>
        </div>
        <div className="text-right shrink-0">
          <span className={`text-xs ${CONFIDENCE_COLORS[analysis.confidence] || 'text-gray-500'}`}>
            {analysis.confidence} conf.
          </span>
          {timestamp && (
            <p className="text-gray-600 text-xs mt-0.5">
              {new Date(timestamp).toLocaleTimeString()}
            </p>
          )}
        </div>
      </div>
      <p className="text-gray-300 text-xs leading-relaxed">{analysis.behavior_summary}</p>
      {analysis.language_or_tool && analysis.language_or_tool !== '—' && (
        <p className="text-gray-500 text-xs mt-1">
          Tool: <span className="text-gray-300">{analysis.language_or_tool}</span>
        </p>
      )}
      <div className="mt-2 pt-2 border-t border-gray-700">
        <p className="text-gray-500 text-xs">
          <span className="text-indigo-400">Rec:</span> {analysis.recommendation}
        </p>
      </div>
      {analysis.event_id && (
        <p className="text-gray-700 text-xs font-mono mt-1">
          {analysis.event_id.slice(0, 8)}…
        </p>
      )}
    </div>
  );
}

function PendingCard({ event }) {
  return (
    <div className="rounded-lg border border-gray-700 bg-gray-800/50 p-3 animate-pulse">
      <div className="flex items-center gap-2 mb-2">
        <div className="w-3 h-3 rounded-full border-2 border-indigo-400 border-t-transparent animate-spin" />
        <p className="text-indigo-400 text-xs font-medium">Analyzing…</p>
        <span className={`text-xs ml-auto font-bold ${
          event.severity === 'CRITICAL' ? 'text-red-400' :
          event.severity === 'HIGH' ? 'text-orange-400' :
          event.severity === 'MEDIUM' ? 'text-yellow-400' : 'text-gray-400'
        }`}>{event.severity}</span>
      </div>
      <p className="text-gray-400 text-xs truncate">{event.file_path || event.event_type}</p>
      <p className="text-gray-600 text-xs">{event.process_name}</p>
    </div>
  );
}

function ErrorCard({ analysis }) {
  return (
    <div className="rounded-lg border border-red-800 bg-red-900/20 p-3">
      <div className="flex items-center gap-2 mb-1">
        <span className="text-red-400 text-xs font-bold">⚠ Analysis Failed</span>
      </div>
      <p className="text-gray-400 text-xs">{analysis.reason || 'NVIDIA API unavailable'}</p>
      {analysis.event_id && (
        <p className="text-gray-700 text-xs font-mono mt-1">{analysis.event_id.slice(0, 8)}…</p>
      )}
    </div>
  );
}

export default function AIAnalystPage({
  connected,
  analyses,
  health,
  newIds,
  timestamps,
  pendingEvents,
  onHealthUpdate,
}) {
  const [tab, setTab] = useState('events');
  const [healthLoading, setHealthLoading] = useState(false);
  const healthPendingRef = useRef(false);

  const statusInfo = health ? (STATUS_COLORS[health.status] || STATUS_COLORS.UNKNOWN) : null;

  const pendingList = Object.values(pendingEvents || {});
  const displayAnalyses = analyses || [];

  const runHealthCheck = async () => {
    if (healthPendingRef.current) return;
    healthPendingRef.current = true;
    setHealthLoading(true);
    try {
      const { data: events } = await getEvents({ limit: 100 });
      await axios.post(`${API_URL}/api/ai/health`, { events });
    } catch (err) {
      console.error('Health check failed:', err);
    } finally {
      setHealthLoading(false);
      healthPendingRef.current = false;
    }
  };

  return (
    <div className="flex-1 flex flex-col overflow-hidden p-6">
      {/* Header */}
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h2 className="text-white text-xl font-semibold">
            🤖 AI Threat Analyst
          </h2>
          <p className="text-gray-500 text-sm mt-0.5">Automated threat classification & behavior analysis</p>
        </div>
        <div className={`text-xs px-2 py-1 rounded font-medium ${connected ? 'bg-green-900 text-green-300' : 'bg-gray-800 text-gray-500'}`}>
          {connected ? 'Live' : 'Disconnected'}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-gray-800 mb-4">
        {[['events', 'Event Analysis'], ['health', 'System Health']].map(([id, label]) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={`px-4 py-2 text-sm font-medium transition-colors ${
              tab === id ? 'text-indigo-400 border-b-2 border-indigo-500' : 'text-gray-500 hover:text-gray-300'
            }`}
          >
            {label}
            {id === 'events' && pendingList.length > 0 && (
              <span className="ml-2 text-xs bg-indigo-900 text-indigo-300 px-1.5 py-0.5 rounded-full">
                {pendingList.length}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto">
        {tab === 'events' && (
          <div className="space-y-3">
            {/* Pending spinner cards */}
            {pendingList.map(ev => (
              <PendingCard key={ev.event_id} event={ev} />
            ))}

            {/* Completed analyses */}
            {displayAnalyses.length === 0 && pendingList.length === 0 ? (
              <div className="text-center mt-12">
                <p className="text-gray-600 text-sm">Waiting for HIGH/CRITICAL/MEDIUM events…</p>
                <p className="text-gray-700 text-xs mt-1">The AI will analyze each threat automatically</p>
              </div>
            ) : (
              displayAnalyses.map((a, i) =>
                a.analysis_failed ? (
                  <ErrorCard key={a.event_id || i} analysis={a} />
                ) : (
                  <AnalysisCard
                    key={a.event_id || i}
                    analysis={a}
                    isNew={newIds?.has(a.event_id)}
                    timestamp={timestamps?.[a.event_id]}
                  />
                )
              )
            )}
          </div>
        )}

        {tab === 'health' && (
          <div className="max-w-2xl">
            <button
              onClick={runHealthCheck}
              disabled={healthLoading}
              className="w-full mb-4 py-2.5 text-sm bg-indigo-700 hover:bg-indigo-600 text-white rounded-lg font-medium transition-colors disabled:opacity-50"
            >
              {healthLoading ? 'Analyzing system…' : 'Run System Health Check'}
            </button>

            {health ? (
              <div>
                <div className="flex items-center gap-3 mb-3 p-3 rounded-lg bg-gray-800 border border-gray-700">
                  <span className="text-xl">{statusInfo?.icon}</span>
                  <div>
                    <p className={`text-sm font-bold ${statusInfo?.text}`}>{health.status}</p>
                    <p className="text-gray-500 text-xs">
                      {health.timestamp ? new Date(health.timestamp).toLocaleString() : 'System status'}
                    </p>
                  </div>
                </div>
                <div className={`rounded-lg border p-3 ${(RISK_COLORS[health.risk_level] || RISK_COLORS.UNKNOWN).bg} ${(RISK_COLORS[health.risk_level] || RISK_COLORS.UNKNOWN).border}`}>
                  <p className="text-gray-300 text-xs leading-relaxed mb-2">{health.behavior_summary}</p>
                  <p className="text-gray-500 text-xs">
                    <span className="text-indigo-400">Recommendation:</span> {health.recommendation}
                  </p>
                </div>
              </div>
            ) : (
              <p className="text-gray-600 text-sm text-center mt-6">
                Click the button above to get an AI assessment of overall system behavior
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
