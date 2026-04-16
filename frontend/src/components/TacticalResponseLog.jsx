import React, { useEffect, useState } from 'react';
import { formatDistanceToNow } from 'date-fns';
import { getEvents } from '../api/client';

// ─── Response procedure mapping ───────────────────────────────────────────

const PROCEDURES = {
  CANARY_TOUCHED:          { name: 'Immediate Isolation Protocol',     color: '#f87171', bg: '#7f1d1d40', icon: '🛡' },
  ENTROPY_SPIKE:           { name: 'Entropy Containment Response',     color: '#fbbf24', bg: '#78350f40', icon: '📈' },
  PROCESS_ANOMALY:         { name: 'Process Lineage Investigation',    color: '#fb923c', bg: '#7c2d1240', icon: '🔍' },
  COMBINED_ALERT:          { name: 'Multi-Vector Threat Response',     color: '#f43f5e', bg: '#88172540', icon: '⚡' },
  CONTAINMENT_TRIGGERED:   { name: 'Host Isolation Initiated',         color: '#ef4444', bg: '#7f1d1d50', icon: '🔒' },
  CONTAINMENT_COMPLETE:    { name: 'Containment Verified',             color: '#22c55e', bg: '#14532d40', icon: '✅' },
  MARKOV_REPOSITION:       { name: 'Adaptive Canary Reposition',       color: '#818cf8', bg: '#1e1b4b40', icon: '🔄' },
  HEARTBEAT:               { name: 'System Heartbeat',                 color: '#6b7280', bg: '#11182740', icon: '💓' },
};

function getProcedure(event) {
  if (event.event_type === 'HEARTBEAT' && event.details?.sub_type === 'MARKOV_REPOSITION') {
    return PROCEDURES.MARKOV_REPOSITION;
  }
  return PROCEDURES[event.event_type] || { name: event.event_type, color: '#6b7280', bg: '#11182740', icon: '•' };
}

// ─── Single event row ──────────────────────────────────────────────────────

function EventRow({ event, isNew }) {
  const proc = getProcedure(event);
  const isMov = event.event_type === 'HEARTBEAT' && event.details?.sub_type === 'MARKOV_REPOSITION';

  return (
    <div
      className={`border-l-2 pl-3 py-2 mb-2 rounded-r-lg transition-all ${isNew ? 'opacity-100' : 'opacity-80'}`}
      style={{ borderColor: proc.color, backgroundColor: proc.bg }}
    >
      {/* Top row */}
      <div className="flex items-center gap-2 flex-wrap">
        <span style={{ fontSize: 14 }}>{proc.icon}</span>
        <span className="text-xs font-semibold" style={{ color: proc.color }}>
          {proc.name}
        </span>
        {isNew && (
          <span className="text-xs px-1.5 py-0.5 rounded-full bg-yellow-500/20 text-yellow-400 font-bold">NEW</span>
        )}
        <span className="ml-auto text-gray-600 text-xs">
          {formatDistanceToNow(new Date(event.timestamp), { addSuffix: true })}
        </span>
      </div>

      {/* Details */}
      <div className="mt-1 space-y-0.5">
        {event.file_path && !isMov && (
          <p className="text-gray-400 text-xs font-mono truncate">{event.file_path}</p>
        )}
        {event.process_name && event.process_name !== 'unknown' && event.process_name !== 'markov-repositioner' && (
          <p className="text-gray-500 text-xs">Process: <span className="text-gray-300">{event.process_name}</span></p>
        )}
        {event.entropy_delta > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-gray-500 text-xs">Entropy:</span>
            <div className="flex items-center gap-1">
              <div className="w-16 h-1.5 bg-gray-700 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full"
                  style={{
                    width: `${Math.min(100, (event.entropy_delta / 8) * 100)}%`,
                    backgroundColor: event.entropy_delta > 5 ? '#ef4444' : event.entropy_delta > 3.5 ? '#fbbf24' : '#22c55e',
                  }}
                />
              </div>
              <span className="text-xs" style={{ color: event.entropy_delta > 5 ? '#ef4444' : event.entropy_delta > 3.5 ? '#fbbf24' : '#22c55e' }}>
                {event.entropy_delta.toFixed(2)}
              </span>
            </div>
          </div>
        )}
        {isMov && event.details?.moved?.length > 0 && (
          <div className="space-y-0.5">
            {event.details.moved.slice(0, 3).map((m, i) => (
              <p key={i} className="text-xs font-mono text-gray-400 truncate">
                <span className="text-cyan-500">{m.from?.split('/').pop()}</span>
                <span className="text-gray-600"> → </span>
                <span className="text-indigo-400">{m.to?.replace('/home/', '~/')}</span>
              </p>
            ))}
            {event.details?.hotspots?.length > 0 && (
              <p className="text-gray-600 text-xs">
                Hotspots: {event.details.hotspots.slice(0, 2).map(h => h.split('/').pop()).join(', ')}
              </p>
            )}
          </div>
        )}
        {event.canary_hit && (
          <p className="text-red-400 text-xs font-bold">⚠ Canary file triggered</p>
        )}
        <p className="text-gray-700 text-xs font-mono">{event.host_id}</p>
      </div>
    </div>
  );
}

// ─── Main component ────────────────────────────────────────────────────────

const FILTER_OPTIONS = ['ALL', 'CANARY', 'ENTROPY', 'MARKOV', 'PROCESS', 'CONTAINMENT'];

export default function TacticalResponseLog({ liveEvent }) {
  const [events, setEvents] = useState([]);
  const [newIds, setNewIds] = useState(new Set());
  const [filter, setFilter] = useState('ALL');

  const fetchEvents = async () => {
    try {
      const { data } = await getEvents({ limit: 100 });
      setEvents(data);
    } catch (err) { console.error(err); }
  };

  useEffect(() => {
    fetchEvents();
    const t = setInterval(fetchEvents, 10000);
    return () => clearInterval(t);
  }, []);

  // Inject live WS event instantly
  useEffect(() => {
    if (!liveEvent || liveEvent.type !== 'new_event') return;
    const synth = {
      id: liveEvent.event_id,
      host_id: liveEvent.host_id,
      event_type: liveEvent.event_type,
      severity: liveEvent.severity,
      file_path: liveEvent.file_path || '',
      entropy_delta: liveEvent.entropy_delta || 0,
      canary_hit: liveEvent.canary_hit || false,
      process_name: liveEvent.process_name || '',
      details: liveEvent.details || {},
      timestamp: new Date().toISOString(),
    };
    setEvents((prev) => {
      if (prev.find((e) => e.id === synth.id)) return prev;
      return [synth, ...prev];
    });
    setNewIds((prev) => new Set([...prev, synth.id]));
    setTimeout(() => setNewIds((prev) => { const n = new Set(prev); n.delete(synth.id); return n; }), 5000);
  }, [liveEvent]);

  const filtered = events.filter((e) => {
    if (filter === 'ALL') return true;
    if (filter === 'CANARY') return e.event_type === 'CANARY_TOUCHED' || e.canary_hit;
    if (filter === 'ENTROPY') return e.event_type === 'ENTROPY_SPIKE';
    if (filter === 'MARKOV') return e.event_type === 'HEARTBEAT' && e.details?.sub_type === 'MARKOV_REPOSITION';
    if (filter === 'PROCESS') return e.event_type === 'PROCESS_ANOMALY' || e.event_type === 'COMBINED_ALERT';
    if (filter === 'CONTAINMENT') return e.event_type === 'CONTAINMENT_TRIGGERED' || e.event_type === 'CONTAINMENT_COMPLETE';
    return true;
  });

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 border-b border-gray-800 shrink-0">
        <h2 className="text-white text-sm font-semibold">Tactical Response Log</h2>
        <p className="text-gray-500 text-xs mt-0.5">Live detection & automated response procedures</p>
      </div>

      {/* Filters */}
      <div className="px-3 py-2 border-b border-gray-800 flex gap-1 flex-wrap shrink-0">
        {FILTER_OPTIONS.map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-2 py-0.5 text-xs rounded font-medium transition-all ${
              filter === f ? 'bg-indigo-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            {f}
          </button>
        ))}
      </div>

      {/* Events */}
      <div className="flex-1 overflow-y-auto p-3">
        {filtered.length === 0 ? (
          <p className="text-gray-600 text-xs italic text-center mt-4">No events yet. Run a simulation to see activity.</p>
        ) : (
          filtered.map((event) => (
            <EventRow key={event.id} event={event} isNew={newIds.has(event.id)} />
          ))
        )}
      </div>
    </div>
  );
}
