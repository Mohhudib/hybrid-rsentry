import React, { useState, useEffect } from 'react';
import { getEvents } from '../api/client';
import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const RISK_COLORS = {
  CRITICAL: { text: 'text-red-400', bg: 'bg-red-900/30', border: 'border-red-700' },
  HIGH:     { text: 'text-orange-400', bg: 'bg-orange-900/30', border: 'border-orange-700' },
  MEDIUM:   { text: 'text-yellow-400', bg: 'bg-yellow-900/20', border: 'border-yellow-700/50' },
  LOW:      { text: 'text-green-400', bg: 'bg-green-900/20', border: 'border-green-700/50' },
  UNKNOWN:  { text: 'text-gray-400', bg: 'bg-gray-800', border: 'border-gray-700' },
};

const STATUS_COLORS = {
  STABLE:        { text: 'text-green-400', icon: '✅' },
  UNDER_ATTACK:  { text: 'text-red-400',   icon: '🚨' },
  ANOMALOUS:     { text: 'text-orange-400',icon: '⚠️' },
  RECOVERING:    { text: 'text-yellow-400',icon: '🔄' },
  UNKNOWN:       { text: 'text-gray-400',  icon: '❓' },
};

const CONFIDENCE_COLORS = {
  HIGH:   'text-green-400',
  MEDIUM: 'text-yellow-400',
  LOW:    'text-gray-500',
};

function AIBadge({ analysis }) {
  if (!analysis) return null;
  const risk = RISK_COLORS[analysis.risk_level] || RISK_COLORS.UNKNOWN;
  return (
    <div className={`rounded-lg border p-3 ${risk.bg} ${risk.border}`}>
      <div className="flex items-start justify-between gap-2 mb-2">
        <div>
          <p className={`text-xs font-bold ${risk.text}`}>{analysis.threat_type}</p>
          <p className="text-gray-400 text-xs mt-0.5">{analysis.technique}</p>
        </div>
        <span className={`text-xs ${CONFIDENCE_COLORS[analysis.confidence] || 'text-gray-500'}`}>
          {analysis.confidence} confidence
        </span>
      </div>
      <p className="text-gray-300 text-xs leading-relaxed">{analysis.behavior_summary}</p>
      {analysis.language_or_tool && analysis.language_or_tool !== '—' && (
        <p className="text-gray-500 text-xs mt-1">
          Tool/Language: <span className="text-gray-300">{analysis.language_or_tool}</span>
        </p>
      )}
      <div className="mt-2 pt-2 border-t border-gray-700">
        <p className="text-gray-500 text-xs">
          <span className="text-indigo-400">Recommendation:</span> {analysis.recommendation}
        </p>
      </div>
    </div>
  );
}

export default function AIAnalystPanel({ liveAiMessage }) {
  const [analyses, setAnalyses] = useState([]);
  const [health, setHealth] = useState(null);
  const [healthLoading, setHealthLoading] = useState(false);
  const [tab, setTab] = useState('events');

  // Inject live AI analysis from WebSocket
  useEffect(() => {
    if (!liveAiMessage) return;
    if (liveAiMessage.type === 'ai_analysis') {
      setAnalyses((prev) => {
        if (prev.find((a) => a.event_id === liveAiMessage.event_id)) return prev;
        return [liveAiMessage, ...prev].slice(0, 50);
      });
    }
    if (liveAiMessage.type === 'health_analysis') {
      setHealth(liveAiMessage);
    }
  }, [liveAiMessage]);

  const runHealthCheck = async () => {
    setHealthLoading(true);
    try {
      const { data: events } = await getEvents({ limit: 100 });
      await axios.post(`${API_URL}/api/ai/health`, { events });
    } catch (err) {
      console.error(err);
    } finally {
      setHealthLoading(false);
    }
  };

  const statusInfo = health ? (STATUS_COLORS[health.status] || STATUS_COLORS.UNKNOWN) : null;

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 border-b border-gray-800 shrink-0 flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-sm">🤖</span>
            <h2 className="text-white text-sm font-semibold">AI Threat Analyst</h2>
            <span className="text-xs px-1.5 py-0.5 rounded bg-indigo-900 text-indigo-300 font-medium">Gemini</span>
          </div>
          <p className="text-gray-500 text-xs mt-0.5">Automated threat classification & behavior analysis</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-gray-800 shrink-0">
        {['events', 'health'].map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`flex-1 py-2 text-xs font-medium transition-colors ${
              tab === t ? 'text-indigo-400 border-b-2 border-indigo-500' : 'text-gray-500 hover:text-gray-300'
            }`}
          >
            {t === 'events' ? 'Event Analysis' : 'System Health'}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-3">
        {tab === 'events' && (
          <>
            {analyses.length === 0 ? (
              <div className="text-center mt-6">
                <p className="text-gray-600 text-xs">Waiting for HIGH/CRITICAL events…</p>
                <p className="text-gray-700 text-xs mt-1">Gemini will analyze each threat automatically</p>
              </div>
            ) : (
              <div className="space-y-3">
                {analyses.map((a, i) => (
                  <div key={a.event_id || i}>
                    <p className="text-gray-600 text-xs font-mono mb-1 truncate">
                      Event: {a.event_id?.slice(0, 8)}…
                    </p>
                    <AIBadge analysis={a} />
                  </div>
                ))}
              </div>
            )}
          </>
        )}

        {tab === 'health' && (
          <div>
            <button
              onClick={runHealthCheck}
              disabled={healthLoading}
              className="w-full mb-4 py-2 text-sm bg-indigo-700 hover:bg-indigo-600 text-white rounded-lg font-medium transition-colors disabled:opacity-50"
            >
              {healthLoading ? 'Analyzing…' : 'Run System Health Check'}
            </button>

            {health ? (
              <div>
                <div className={`flex items-center gap-2 mb-3 p-3 rounded-lg bg-gray-800 border border-gray-700`}>
                  <span style={{ fontSize: 20 }}>{statusInfo?.icon}</span>
                  <div>
                    <p className={`text-sm font-bold ${statusInfo?.text}`}>{health.status}</p>
                    <p className="text-gray-500 text-xs">System status</p>
                  </div>
                </div>
                <AIBadge analysis={health} />
              </div>
            ) : (
              <p className="text-gray-600 text-xs text-center mt-4">
                Click "Run System Health Check" to get an AI assessment of overall system behavior
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
