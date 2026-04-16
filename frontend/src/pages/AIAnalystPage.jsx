import React, { useState, useEffect, useCallback } from 'react';
import { getEvents } from '../api/client';
import axios from 'axios';
import { formatDistanceToNow } from 'date-fns';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const RISK_COLORS = {
  CRITICAL: { text: 'text-red-400',    bg: 'bg-red-900/30',    border: 'border-red-700' },
  HIGH:     { text: 'text-orange-400', bg: 'bg-orange-900/30', border: 'border-orange-700' },
  MEDIUM:   { text: 'text-yellow-400', bg: 'bg-yellow-900/20', border: 'border-yellow-700/50' },
  LOW:      { text: 'text-green-400',  bg: 'bg-green-900/20',  border: 'border-green-700/50' },
  UNKNOWN:  { text: 'text-gray-400',   bg: 'bg-gray-800',      border: 'border-gray-700' },
};

const STATUS_INFO = {
  STABLE:       { text: 'text-green-400',  bg: 'bg-green-900/30',  border: 'border-green-700',  icon: '✅' },
  UNDER_ATTACK: { text: 'text-red-400',    bg: 'bg-red-900/30',    border: 'border-red-700',    icon: '🚨' },
  ANOMALOUS:    { text: 'text-orange-400', bg: 'bg-orange-900/30', border: 'border-orange-700', icon: '⚠️' },
  RECOVERING:   { text: 'text-yellow-400', bg: 'bg-yellow-900/20', border: 'border-yellow-700', icon: '🔄' },
  UNKNOWN:      { text: 'text-gray-400',   bg: 'bg-gray-800',      border: 'border-gray-700',   icon: '❓' },
};

const CONFIDENCE_COLORS = { HIGH: 'text-green-400', MEDIUM: 'text-yellow-400', LOW: 'text-gray-500' };

// ─── Analysis card ─────────────────────────────────────────────────────────

function AnalysisCard({ analysis, isNew, timestamp }) {
  const [expanded, setExpanded] = useState(isNew);
  const risk = RISK_COLORS[analysis.risk_level] || RISK_COLORS.UNKNOWN;

  return (
    <div className={`border rounded-xl overflow-hidden transition-all ${risk.border} ${isNew ? 'ring-1 ring-indigo-500' : ''}`}>
      {/* Card header — always visible */}
      <div
        className={`flex items-center gap-3 px-4 py-3 cursor-pointer ${risk.bg} hover:brightness-110 transition-all`}
        onClick={() => setExpanded(e => !e)}
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-sm font-bold ${risk.text}`}>{analysis.threat_type}</span>
            {isNew && (
              <span className="text-xs px-1.5 py-0.5 rounded-full bg-indigo-600 text-white font-bold animate-pulse">
                NEW
              </span>
            )}
            <span className={`text-xs ${CONFIDENCE_COLORS[analysis.confidence] || 'text-gray-500'}`}>
              {analysis.confidence} confidence
            </span>
          </div>
          <p className="text-gray-400 text-xs mt-0.5 truncate">{analysis.technique}</p>
        </div>
        <div className="text-right shrink-0">
          {timestamp && (
            <p className="text-gray-500 text-xs">
              {formatDistanceToNow(new Date(timestamp), { addSuffix: true })}
            </p>
          )}
          <span className="text-gray-600 text-xs">{expanded ? '▲' : '▼'}</span>
        </div>
      </div>

      {/* Expanded details */}
      {expanded && (
        <div className="px-4 py-3 bg-gray-900 border-t border-gray-800 space-y-3">
          <div>
            <p className="text-gray-500 text-xs uppercase tracking-wider mb-1">Behavior Analysis</p>
            <p className="text-gray-200 text-sm leading-relaxed">{analysis.behavior_summary}</p>
          </div>
          {analysis.language_or_tool && analysis.language_or_tool !== '—' && (
            <div>
              <p className="text-gray-500 text-xs uppercase tracking-wider mb-1">Tool / Language Detected</p>
              <span className="inline-block bg-gray-800 text-gray-200 text-xs px-2 py-1 rounded font-mono">
                {analysis.language_or_tool}
              </span>
            </div>
          )}
          <div className={`rounded-lg border p-3 ${risk.bg} ${risk.border}`}>
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Recommendation</p>
            <p className="text-gray-200 text-sm">{analysis.recommendation}</p>
          </div>
          {analysis.event_id && (
            <p className="text-gray-700 text-xs font-mono">Event ID: {analysis.event_id}</p>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Health status card ────────────────────────────────────────────────────

function HealthCard({ health }) {
  const info = STATUS_INFO[health.status] || STATUS_INFO.UNKNOWN;
  const risk = RISK_COLORS[health.risk_level] || RISK_COLORS.UNKNOWN;

  return (
    <div className={`border rounded-xl overflow-hidden ${info.border}`}>
      <div className={`flex items-center gap-4 px-5 py-4 ${info.bg}`}>
        <span style={{ fontSize: 32 }}>{info.icon}</span>
        <div>
          <p className={`text-xl font-bold ${info.text}`}>{health.status}</p>
          <p className="text-gray-400 text-sm">System Status</p>
        </div>
        <div className="ml-auto text-right">
          <span className={`text-sm font-bold ${risk.text}`}>{health.risk_level}</span>
          <p className="text-gray-500 text-xs">Risk Level</p>
        </div>
      </div>
      <div className="px-5 py-4 bg-gray-900 border-t border-gray-800 space-y-3">
        <div>
          <p className="text-gray-500 text-xs uppercase tracking-wider mb-1">System Behavior Analysis</p>
          <p className="text-gray-200 text-sm leading-relaxed">{health.behavior_summary}</p>
        </div>
        <div className={`rounded-lg border p-3 ${risk.bg} ${risk.border}`}>
          <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Recommendation</p>
          <p className="text-gray-200 text-sm">{health.recommendation}</p>
        </div>
        <p className={`text-xs ${CONFIDENCE_COLORS[health.confidence] || 'text-gray-500'}`}>
          Confidence: {health.confidence}
        </p>
      </div>
    </div>
  );
}

// ─── Main page ─────────────────────────────────────────────────────────────

export default function AIAnalystPage({ liveAi, connected }) {
  const [analyses, setAnalyses] = useState([]);
  const [health, setHealth] = useState(null);
  const [newIds, setNewIds] = useState(new Set());
  const [timestamps, setTimestamps] = useState({});
  const [tab, setTab] = useState('events');
  const [healthLoading, setHealthLoading] = useState(false);
  const [autoHealth, setAutoHealth] = useState(false);

  // Inject live AI results from WebSocket instantly
  useEffect(() => {
    if (!liveAi) return;
    if (liveAi.type === 'ai_analysis' && liveAi.event_id) {
      setAnalyses(prev => {
        if (prev.find(a => a.event_id === liveAi.event_id)) return prev;
        return [liveAi, ...prev].slice(0, 100);
      });
      setNewIds(prev => new Set([...prev, liveAi.event_id]));
      setTimestamps(prev => ({ ...prev, [liveAi.event_id]: new Date().toISOString() }));
      setTimeout(() => setNewIds(prev => { const n = new Set(prev); n.delete(liveAi.event_id); return n; }), 10000);
    }
    if (liveAi.type === 'health_analysis') {
      setHealth({ ...liveAi, timestamp: new Date().toISOString() });
    }
  }, [liveAi]);

  const runHealthCheck = useCallback(async () => {
    setHealthLoading(true);
    try {
      const { data: events } = await getEvents({ limit: 100 });
      await axios.post(`${API_URL}/api/ai/health`, { events });
    } catch (err) { console.error(err); }
    finally { setHealthLoading(false); }
  }, []);

  // Auto health check every 5 minutes when enabled
  useEffect(() => {
    if (!autoHealth) return;
    runHealthCheck();
    const t = setInterval(runHealthCheck, 5 * 60 * 1000);
    return () => clearInterval(t);
  }, [autoHealth, runHealthCheck]);

  const newCount = analyses.filter(a => newIds.has(a.event_id)).length;

  return (
    <div className="flex-1 flex flex-col overflow-hidden p-6">
      {/* Header */}
      <div className="mb-5 flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3">
            <span style={{ fontSize: 24 }}>🤖</span>
            <h2 className="text-white text-xl font-semibold">AI Threat Analyst</h2>
            <span className="text-xs px-2 py-1 rounded-lg bg-indigo-900 text-indigo-300 font-medium">
              Powered by NVIDIA
            </span>
            <div className={`flex items-center gap-1.5 text-xs px-2 py-1 rounded-lg border ${
              connected ? 'bg-green-900/30 border-green-700 text-green-400' : 'bg-red-900/30 border-red-800 text-red-400'
            }`}>
              <span className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-green-400 animate-pulse' : 'bg-red-500'}`} />
              {connected ? 'LIVE' : 'OFFLINE'}
            </div>
          </div>
          <p className="text-gray-500 text-sm mt-1">
            Automated threat classification, behavior analysis, and system health monitoring
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-4 bg-gray-900 border border-gray-800 rounded-xl p-1 w-fit">
        <button
          onClick={() => setTab('events')}
          className={`px-4 py-2 text-sm rounded-lg font-medium transition-all flex items-center gap-2 ${
            tab === 'events' ? 'bg-indigo-600 text-white' : 'text-gray-400 hover:text-white'
          }`}
        >
          Event Analysis
          {newCount > 0 && (
            <span className="bg-red-500 text-white text-xs px-1.5 py-0.5 rounded-full">{newCount}</span>
          )}
        </button>
        <button
          onClick={() => setTab('health')}
          className={`px-4 py-2 text-sm rounded-lg font-medium transition-all ${
            tab === 'health' ? 'bg-indigo-600 text-white' : 'text-gray-400 hover:text-white'
          }`}
        >
          System Health
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto">
        {tab === 'events' && (
          <div>
            {analyses.length === 0 ? (
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-10 text-center">
                <p style={{ fontSize: 40 }} className="mb-3">🤖</p>
                <p className="text-gray-400 text-sm">Waiting for HIGH or CRITICAL events…</p>
                <p className="text-gray-600 text-xs mt-1">
                  Gemini will automatically analyze each threat as it happens
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {analyses.map((a, i) => (
                  <AnalysisCard
                    key={a.event_id || i}
                    analysis={a}
                    isNew={newIds.has(a.event_id)}
                    timestamp={timestamps[a.event_id]}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {tab === 'health' && (
          <div className="space-y-4">
            {/* Controls */}
            <div className="flex items-center gap-3">
              <button
                onClick={runHealthCheck}
                disabled={healthLoading}
                className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white text-sm rounded-lg font-medium transition-colors disabled:opacity-50"
              >
                {healthLoading ? 'Analyzing…' : 'Run Health Check Now'}
              </button>
              <label className="flex items-center gap-2 text-sm text-gray-400 cursor-pointer">
                <input
                  type="checkbox"
                  checked={autoHealth}
                  onChange={e => setAutoHealth(e.target.checked)}
                  className="rounded"
                />
                Auto-check every 5 min
              </label>
              {health?.timestamp && (
                <span className="text-gray-600 text-xs ml-auto">
                  Last check: {formatDistanceToNow(new Date(health.timestamp), { addSuffix: true })}
                </span>
              )}
            </div>

            {health ? (
              <HealthCard health={health} />
            ) : (
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-10 text-center">
                <p style={{ fontSize: 40 }} className="mb-3">🏥</p>
                <p className="text-gray-400 text-sm">No health analysis yet</p>
                <p className="text-gray-600 text-xs mt-1">
                  Click "Run Health Check Now" or enable auto-check
                </p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
