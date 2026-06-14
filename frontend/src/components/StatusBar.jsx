import React, { useState, useEffect } from 'react';

function stamp() {
  const d = new Date();
  const p = n => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}`;
}

function agentStatusFromLastSeen(lastSeen) {
  if (!lastSeen) return { status: 'offline', color: 'var(--crit)', label: 'Agent Offline' };
  const secsAgo = (Date.now() - new Date(lastSeen).getTime()) / 1000;
  if (secsAgo <= 90)  return { status: 'online',  color: 'var(--ok)',   label: 'Agent Active',  secsAgo };
  if (secsAgo <= 300) return { status: 'stale',   color: 'var(--high)', label: 'Agent Stale',   secsAgo };
  return                     { status: 'offline', color: 'var(--crit)', label: 'Agent Offline', secsAgo };
}

function fmtAgo(secs) {
  if (secs == null) return '';
  if (secs < 60) return `${Math.round(secs)}s ago`;
  return `${Math.round(secs / 60)}m ago`;
}

export default function StatusBar({ connected }) {
  const [time, setTime] = useState(stamp());
  const [hosts, setHosts] = useState([]);
  const [eventRate, setEventRate] = useState(null);
  const [sensorMode, setSensorMode] = useState('eBPF');
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const t = setInterval(() => { setTime(stamp()); setTick(n => n + 1); }, 15000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    let cancelled = false;
    const fetchHosts = async () => {
      try {
        const res = await fetch('/api/hosts');
        if (!res.ok) return;
        const data = await res.json();
        if (!cancelled) setHosts(Array.isArray(data) ? data : []);
      } catch (_) {}
    };
    fetchHosts();
    const t = setInterval(fetchHosts, 30000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  useEffect(() => {
    let cancelled = false;
    const fetchEps = async () => {
      try {
        const since = new Date(Date.now() - 60000).toISOString();
        const res = await fetch(`/api/events?since=${since}&limit=1000`);
        if (!res.ok) return;
        const data = await res.json();
        if (!cancelled) setEventRate(Array.isArray(data) ? (data.length / 60).toFixed(2) : null);
      } catch (_) {}
    };
    fetchEps();
    const t = setInterval(fetchEps, 15000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  useEffect(() => {
    const fetchHealth = async () => {
      try {
        const res = await fetch('/health');
        if (!res.ok) return;
        const data = await res.json();
        if (data.sensor_backend) setSensorMode(data.sensor_backend === 'ebpf' ? 'eBPF' : 'inotify');
      } catch (_) {}
    };
    fetchHealth();
  }, []);

  // Pick the most-recently-seen host as the representative agent
  const latestHost = hosts.length > 0
    ? hosts.reduce((a, b) => new Date(a.last_seen) > new Date(b.last_seen) ? a : b)
    : null;
  const { color, label, secsAgo } = agentStatusFromLastSeen(latestHost?.last_seen);

  return (
    <footer style={{ height: 28, flexShrink: 0, display: 'flex', alignItems: 'center', gap: 14, padding: '0 14px', background: 'var(--panel)', borderTop: '1px solid var(--border)', fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--muted)' }}>

      {/* Agent status badge */}
      <span style={{
        display: 'inline-flex', alignItems: 'center', gap: 6,
        background: 'var(--panel-2)', border: `1px solid ${color}40`,
        borderRadius: 5, padding: '2px 9px', color,
      }}>
        <span style={{
          width: 7, height: 7, borderRadius: '50%',
          background: color, display: 'inline-block',
          boxShadow: `0 0 5px ${color}`,
        }} />
        {label}
        {secsAgo != null && (
          <span style={{ color: 'var(--muted)', fontSize: 10 }}>· {fmtAgo(secsAgo)}</span>
        )}
      </span>

      {/* Host count */}
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
        <i className="fa-solid fa-server" style={{ fontSize: 9, color: 'var(--accent)' }} />
        {hosts.length} host{hosts.length !== 1 ? 's' : ''}
      </span>

      {/* EPS */}
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
        <i className="fa-solid fa-bolt" style={{ fontSize: 9, color: 'var(--accent)' }} />
        {eventRate ?? '—'} EPS
      </span>

      {/* Sensor mode */}
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, background: 'var(--panel-2)', border: '1px solid var(--border)', borderRadius: 4, padding: '1px 7px', color: 'var(--accent)', fontSize: 10, letterSpacing: '0.04em' }}>
        <i className="fa-solid fa-microchip" style={{ fontSize: 9 }} />
        {sensorMode}
      </span>

      {/* WebSocket */}
      {!connected && (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color: 'var(--high)' }}>
          <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--high)', display: 'inline-block' }} />
          WebSocket disconnected
        </span>
      )}

      <span style={{ flex: 1 }} />
      <span>last refreshed {time}</span>
      <span>cluster: rsentry-prod · v2.2.0</span>
    </footer>
  );
}
