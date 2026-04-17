import React, { useState, useEffect, useCallback, useRef } from 'react';
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

const HEALTH_STEPS = [
  { label: 'Collecting recent events from endpoint…',  duration: 1200 },
  { label: 'Sending event data to NVIDIA AI…',         duration: 2500 },
  { label: 'AI is analyzing system behavior…',         duration: 4000 },
  { label: 'Finalizing health report…',                duration: 2000 },
];

// ─── Health check progress card ────────────────────────────────────────────

function HealthProgressCard({ step, done }) {
  const pct = done ? 100 : Math.round(((step + 1) / HEALTH_STEPS.length) * 100);

  return (
    <div className="bg-gray-900 border border-indigo-800/50 rounded-xl p-5 space-y-4">
      <div className="flex items-center gap-3">
        <svg className="animate-spin h-5 w-5 text-indigo-400 shrink-0" viewBox="0 0 24 24" fill="none">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
        </svg>
        <p className="text-indigo-300 text-sm font-medium">
          {done ? 'Analysis complete — loading result…' : HEALTH_STEPS[step]?.label}
        </p>
      </div>

      {/* Progress bar */}
      <div className="w-full bg-gray-800 rounded-full h-2 overflow-hidden">
        <div
          className="h-2 rounded-full bg-indigo-500 transition-all duration-700 ease-out"
          style={{ width: `${pct}%` }}
        />
      </div>

      {/* Step indicators */}
      <div className="flex items-center justify-between gap-2">
        {HEALTH_STEPS.map((s, i) => (
          <div key={i} className="flex-1 flex flex-col items-center gap-1">
            <div className={`w-2.5 h-2.5 rounded-full transition-all duration-300 ${
              done || i < step
                ? 'bg-indigo-500'
                : i === step
                  ? 'bg-indigo-400 ring-2 ring-indigo-400/40 animate-pulse'
                  : 'bg-gray-700'
            }`} />
            <p className={`text-center text-[10px] leading-tight hidden sm:block ${
              done || i < step ? 'text-indigo-400' : i === step ? 'text-gray-300' : 'text-gray-600'
            }`}>
              {['Events', 'Upload', 'Analysis', 'Report'][i]}
            </p>
          </div>
        ))}
      </div>

      <p className="text-gray-600 text-xs text-right">{pct}%</p>
    </div>
  );
}

// ─── Pending card (shown while AI is still processing an event) ─────────────

function PendingCard({ event }) {
  const severityColor = {
    CRITICAL: 'text-red-400 border-red-700 bg-red-900/20',
    HIGH:     'text-orange-400 border-orange-700 bg-orange-900/20',
    MEDIUM:   'text-yellow-400 border-yellow-700/50 bg-yellow-900/10',
  }[event.severity] || 'text-gray-400 border-gray-700 bg-gray-800';

  return (
    <div className={`border rounded-xl px-4 py-3 flex items-center gap-3 ${severityColor}`}>
      <svg className="animate-spin h-4 w-4 shrink-0 opacity-70" viewBox="0 0 24 24" fill="none">
        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
      </svg>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium">AI Analyst is processing this event…</p>
        <p className="text-xs opacity-60 truncate mt-0.5">
          {event.event_type} — {event.file_path || event.process_name || event.host_id}
        </p>
      </div>
      <span className="text-xs font-bold opacity-70 shrink-0">{event.severity}</span>
    </div>
  );
}

// ─── Analysis card ──────────────────────────────────────────────────────────

function AnalysisCard({ analysis, isNew, timestamp }) {
  const [expanded, setExpanded] = useState(isNew);
  const risk = RISK_COLORS[analysis.risk_level] || RISK_COLORS.UNKNOWN;

  return (
    <div className={`border rounded-xl overflow-hidden transition-all ${risk.border} ${isNew ? 'ring-1 ring-indigo-500' : ''}`}>
      <div
        className={`flex items-center gap-3 px-4 py-3 cursor-pointer ${risk.bg} hover:brightness-110 transition-all`}
        onClick={() => setExpanded(e => !e)}
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-sm font-bold ${risk.text}`}>{analysis.threat_type}</span>
            {isNew && (
              <span className="text-xs px-1.5 py-0.5 rounded-full bg-indigo-600 text-white font-bold animate-pulse">NEW</span>
            )}
            {analysis.markov_action && (
              <span className="text-xs px-1.5 py-0.5 rounded-full bg-blue-800 text-blue-200 font-semibold">Markov Chain</span>
            )}
            <span className={`text-xs ${CONFIDENCE_COLORS[analysis.confidence] || 'text-gray-500'}`}>
              {analysis.confidence} confidence
            </span>
          </div>
          <p className="text-gray-400 text-xs mt-0.5 truncate">{analysis.technique}</p>
        </div>
        <div className="text-right shrink-0">
          {timestamp && (
            <p className="text-gray-500 text-xs">{formatDistanceToNow(new Date(timestamp), { addSuffix: true })}</p>
          )}
          <span className="text-gray-600 text-xs">{expanded ? '▲' : '▼'}</span>
        </div>
      </div>

      {expanded && (
        <div className="px-4 py-3 bg-gray-900 border-t border-gray-800 space-y-3">
          {analysis.markov_action && (
            <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-blue-900/20 border border-blue-700/40">
              <span className="text-blue-300 text-xs font-semibold">Action taken by:</span>
              <span className="text-blue-200 text-xs">Markov Chain Adaptive Repositioner — internal defensive system</span>
            </div>
          )}
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

// ─── Health status card ─────────────────────────────────────────────────────

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

// ─── Main page ──────────────────────────────────────────────────────────────

export default function AIAnalystPage({ connected, analyses, health, newIds, timestamps, pendingEvents, onHealthUpdate }) {
  const [tab, setTab] = useState('events');
  const [autoHealth, setAutoHealth] = useState(false);

  // Health check progress state
  const [healthPending, setHealthPending] = useState(false);
  const [healthStep, setHealthStep] = useState(0);
  const [healthDone, setHealthDone] = useState(false);
  const healthStartedAt = useRef(null);
  const stepTimers = useRef([]);

  const clearStepTimers = () => {
    stepTimers.current.forEach(clearTimeout);
    stepTimers.current = [];
  };

  const runHealthCheck = useCallback(async () => {
    if (healthPending) return;
    setHealthPending(true);
    setHealthStep(0);
    setHealthDone(false);
    healthStartedAt.current = Date.now();
    clearStepTimers();

    // Advance steps on a timer to show visual progress
    let elapsed = 0;
    HEALTH_STEPS.forEach((s, i) => {
      if (i === 0) return; // step 0 is immediate
      elapsed += HEALTH_STEPS[i - 1].duration;
      const t = setTimeout(() => setHealthStep(i), elapsed);
      stepTimers.current.push(t);
    });

    try {
      const { data: events } = await getEvents({ limit: 100 });
      await axios.post(`${API_URL}/api/ai/health`, { events });
      // POST returned — Celery task queued, now waiting for WebSocket result
    } catch (err) {
      console.error(err);
      clearStepTimers();
      setHealthPending(false);
    }
  }, [healthPending]);

  // When health prop updates with a new timestamp, the WS result arrived — finish progress
  const prevHealthTs = useRef(null);
  useEffect(() => {
    if (!healthPending) return;
    if (!health?.timestamp) return;
    if (health.timestamp === prevHealthTs.current) return;
    prevHealthTs.current = health.timestamp;
    clearStepTimers();
    setHealthDone(true);
    // Show "done" briefly then hide the progress card
    const t = setTimeout(() => {
      setHealthPending(false);
      setHealthDone(false);
      setHealthStep(0);
    }, 1200);
    return () => clearTimeout(t);
  }, [health, healthPending]);

  // Auto health check every 5 minutes when enabled
  useEffect(() => {
    if (!autoHealth) return;
    runHealthCheck();
    const t = setInterval(runHealthCheck, 5 * 60 * 1000);
    return () => clearInterval(t);
  }, [autoHealth, runHealthCheck]);

  // Cleanup on unmount
  useEffect(() => () => clearStepTimers(), []);

  const completedIds = new Set((analyses || []).map(a => a.event_id));
  const pendingList = Object.values(pendingEvents || {}).filter(e => !completedIds.has(e.event_id));
  const newCount = (analyses || []).filter(a => newIds.has(a.event_id)).length;
  const pendingCount = pendingList.length;

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
          {pendingCount > 0 && (
            <span className="bg-yellow-500 text-black text-xs px-1.5 py-0.5 rounded-full font-bold">{pendingCount}</span>
          )}
          {newCount > 0 && (
            <span className="bg-red-500 text-white text-xs px-1.5 py-0.5 rounded-full">{newCount}</span>
          )}
        </button>
        <button
          onClick={() => setTab('health')}
          className={`px-4 py-2 text-sm rounded-lg font-medium transition-all flex items-center gap-2 ${
            tab === 'health' ? 'bg-indigo-600 text-white' : 'text-gray-400 hover:text-white'
          }`}
        >
          System Health
          {healthPending && (
            <svg className="animate-spin h-3 w-3 text-indigo-300" viewBox="0 0 24 24" fill="none">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
            </svg>
          )}
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto">
        {tab === 'events' && (
          <div>
            {pendingList.length === 0 && (analyses || []).length === 0 ? (
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-10 text-center">
                <p style={{ fontSize: 40 }} className="mb-3">🤖</p>
                <p className="text-gray-400 text-sm">Waiting for HIGH, MEDIUM or CRITICAL events…</p>
                <p className="text-gray-600 text-xs mt-1">
                  NVIDIA AI will automatically analyze each threat as it happens. Analyses persist for 4 minutes.
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {pendingList.map(e => <PendingCard key={e.event_id} event={e} />)}
                {(analyses || []).map((a, i) => (
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
            <div className="flex items-center gap-3 flex-wrap">
              <button
                onClick={runHealthCheck}
                disabled={healthPending}
                className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white text-sm rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {healthPending ? 'Checking…' : 'Run Health Check Now'}
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
              {health?.timestamp && !healthPending && (
                <span className="text-gray-600 text-xs ml-auto">
                  Last check: {formatDistanceToNow(new Date(health.timestamp), { addSuffix: true })}
                </span>
              )}
            </div>

            {/* Progress card — shown while checking */}
            {healthPending && (
              <HealthProgressCard step={healthStep} done={healthDone} />
            )}

            {/* Result card — shown after check completes */}
            {!healthPending && health && <HealthCard health={health} />}

            {/* Empty state — no check run yet */}
            {!healthPending && !health && (
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
