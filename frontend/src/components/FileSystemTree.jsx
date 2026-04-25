import React, { useEffect, useState, useCallback, useRef } from 'react';
import { getEvents } from '../api/client';

// ─── Tree builder ──────────────────────────────────────────────────────────

function emptyStats() {
  return { alertCount: 0, maxEntropy: 0, canaryHit: false, lastEventType: null };
}

function mergeStats(target, event) {
  if (['HIGH', 'CRITICAL'].includes(event.severity)) target.alertCount++;
  if (event.entropy_delta > target.maxEntropy) target.maxEntropy = event.entropy_delta;
  if (event.canary_hit) target.canaryHit = true;
  target.lastEventType = event.event_type;
}

function buildTree(events) {
  const root = { name: '/', path: '/', children: {}, stats: emptyStats(), isCanary: false, isFile: false };
  for (const ev of events) {
    if (!ev.file_path) continue;
    const parts = ev.file_path.replace(/^\//, '').split('/').filter(Boolean);
    let node = root;
    for (let i = 0; i < parts.length; i++) {
      const name = parts[i];
      const path = '/' + parts.slice(0, i + 1).join('/');
      if (!node.children[name]) {
        node.children[name] = {
          name, path, children: {}, stats: emptyStats(),
          isCanary: name.startsWith('AAA_'),
          isFile: i === parts.length - 1,
        };
      }
      mergeStats(node.children[name].stats, ev);
      node = node.children[name];
    }
    mergeStats(root.stats, ev);
  }
  return root;
}

function sortChildren(children) {
  return Object.values(children).sort((a, b) => {
    if (a.isCanary !== b.isCanary) return a.isCanary ? -1 : 1;
    if (a.stats.alertCount !== b.stats.alertCount) return b.stats.alertCount - a.stats.alertCount;
    const aDir = Object.keys(a.children).length > 0;
    const bDir = Object.keys(b.children).length > 0;
    if (aDir !== bDir) return aDir ? -1 : 1;
    return a.name.localeCompare(b.name);
  });
}

// ─── Colours ───────────────────────────────────────────────────────────────

function nodeColor(node) {
  if (node.isCanary && node.stats.canaryHit) return { text: '#f87171', glow: '#ef444460' };
  if (node.isCanary)                          return { text: '#67e8f9', glow: '#06b6d430' };
  if (node.stats.alertCount > 0)              return { text: '#fb923c', glow: '#f9731630' };
  if (node.stats.maxEntropy > 3.5)            return { text: '#fbbf24', glow: null };
  return { text: '#9ca3af', glow: null };
}

function EntropyPill({ value }) {
  const color = value > 5 ? '#ef4444' : value > 3.5 ? '#fbbf24' : '#22c55e';
  const pct = Math.min(100, (value / 8) * 100);
  return (
    <span className="inline-flex items-center gap-1 ml-2">
      <span style={{ fontSize: 10, color: '#6b7280' }}>H:</span>
      <span className="relative inline-block w-14 h-1.5 rounded-full overflow-hidden bg-gray-700">
        <span className="absolute left-0 top-0 h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: color }} />
      </span>
      <span style={{ fontSize: 10, color }}>{value.toFixed(1)}</span>
    </span>
  );
}

// ─── Single tree row ───────────────────────────────────────────────────────

function TreeRow({ node, prefix, isLast, flashPaths, depth }) {
  const hasChildren = Object.keys(node.children).length > 0;
  const autoOpen = depth < 2 || node.stats.alertCount > 0 || node.isCanary || node.stats.canaryHit;
  const [open, setOpen] = useState(autoOpen);
  const isFlashing = flashPaths.has(node.path);
  const { text, glow } = nodeColor(node);

  const connector = isLast ? '└── ' : '├── ';
  const childPrefix = prefix + (isLast ? '    ' : '│   ');
  const children = sortChildren(node.children);

  return (
    <div>
      {/* Row */}
      <div
        className="flex items-center group cursor-pointer select-none"
        style={{ backgroundColor: isFlashing ? '#1f2937' : 'transparent', transition: 'background 0.3s' }}
        onClick={() => hasChildren && setOpen((o) => !o)}
      >
        {/* Tree connector */}
        <span className="font-mono text-gray-600 whitespace-pre shrink-0" style={{ fontSize: 13 }}>
          {prefix}{connector}
        </span>

        {/* Arrow for directories */}
        {hasChildren && (
          <span className="mr-1 text-gray-500 shrink-0" style={{ fontSize: 11 }}>
            {open ? '▼' : '▶'}
          </span>
        )}

        {/* Icon */}
        <span className="mr-1 shrink-0" style={{ fontSize: 13 }}>
          {node.isCanary ? '🛡' : node.isFile ? '📄' : open ? '📂' : '📁'}
        </span>

        {/* Name */}
        <span
          className="font-mono text-sm shrink-0"
          style={{
            color: text,
            textShadow: glow ? `0 0 8px ${glow}` : 'none',
            fontWeight: node.stats.alertCount > 0 || node.isCanary ? 600 : 400,
          }}
        >
          {node.name}
        </span>

        {/* Badges */}
        {node.isCanary && node.stats.canaryHit && (
          <span className="ml-2 text-xs px-1.5 py-0.5 rounded font-bold bg-red-700 text-white shrink-0">
            CANARY HIT
          </span>
        )}
        {node.isCanary && !node.stats.canaryHit && (
          <span className="ml-2 text-xs px-1.5 py-0.5 rounded font-bold bg-cyan-900 text-cyan-300 shrink-0">
            CANARY
          </span>
        )}
        {node.stats.alertCount > 0 && (
          <span className="ml-2 text-xs px-1.5 py-0.5 rounded-full font-bold bg-red-800 text-red-200 shrink-0">
            {node.stats.alertCount} alert{node.stats.alertCount > 1 ? 's' : ''}
          </span>
        )}

        {/* Entropy — always visible if significant, otherwise on hover */}
        {node.stats.maxEntropy > 3.5 && <EntropyPill value={node.stats.maxEntropy} />}
        {node.stats.maxEntropy > 0 && node.stats.maxEntropy <= 3.5 && (
          <span className="opacity-0 group-hover:opacity-100 transition-opacity">
            <EntropyPill value={node.stats.maxEntropy} />
          </span>
        )}

        {/* Pulse dot for flash */}
        {isFlashing && (
          <span className="ml-2 w-2 h-2 rounded-full bg-yellow-400 animate-ping shrink-0" />
        )}
      </div>

      {/* Children */}
      {hasChildren && open && children.map((child, i) => (
        <TreeRow
          key={child.path}
          node={child}
          prefix={childPrefix}
          isLast={i === children.length - 1}
          flashPaths={flashPaths}
          depth={depth + 1}
        />
      ))}
    </div>
  );
}

// ─── Root renderer ─────────────────────────────────────────────────────────

function RootRow({ node, flashPaths }) {
  const hasChildren = Object.keys(node.children).length > 0;
  const [open, setOpen] = useState(true);
  const children = sortChildren(node.children);

  return (
    <div>
      <div
        className="flex items-center cursor-pointer mb-1"
        onClick={() => setOpen((o) => !o)}
      >
        {hasChildren && (
          <span className="mr-1 text-gray-500" style={{ fontSize: 11 }}>
            {open ? '▼' : '▶'}
          </span>
        )}
        <span className="mr-1" style={{ fontSize: 13 }}>📂</span>
        <span className="font-mono text-sm text-gray-200 font-semibold">/</span>
        {node.stats.alertCount > 0 && (
          <span className="ml-2 text-xs px-1.5 py-0.5 rounded-full font-bold bg-red-800 text-red-200">
            {node.stats.alertCount} alerts
          </span>
        )}
      </div>
      {open && children.map((child, i) => (
        <TreeRow
          key={child.path}
          node={child}
          prefix=""
          isLast={i === children.length - 1}
          flashPaths={flashPaths}
          depth={1}
        />
      ))}
    </div>
  );
}

// ─── Main export ───────────────────────────────────────────────────────────

export default function FileSystemTree({ newEvent, connected }) {
  const [tree, setTree] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [flashPaths, setFlashPaths] = useState(new Set());
  const [canaryCount, setCanaryCount] = useState(0);
  const [alertPaths, setAlertPaths] = useState(0);
  const [search, setSearch] = useState('');

  const rebuild = useCallback((events) => {
    const filtered = search
      ? events.filter((e) => e.file_path?.toLowerCase().includes(search.toLowerCase()))
      : events;
    const t = buildTree(filtered);
    setTree(t);
    setLastUpdated(new Date());
    let canaries = 0, alerts = 0;
    const count = (node) => {
      if (node.isCanary) canaries++;
      if (node.stats.alertCount > 0) alerts++;
      Object.values(node.children).forEach(count);
    };
    count(t);
    setCanaryCount(canaries);
    setAlertPaths(alerts);
  }, [search]);

  const fetchEvents = useCallback(async () => {
    try {
      const { data } = await getEvents({ limit: 500 });
      rebuild(data);
    } catch (err) { console.error(err); }
  }, [rebuild]);

  useEffect(() => {
    fetchEvents();
    const t = setInterval(fetchEvents, 5000);
    return () => clearInterval(t);
  }, [fetchEvents]);

  useEffect(() => {
    if (!newEvent?.file_path) return;
    const parts = newEvent.file_path.replace(/^\//, '').split('/').filter(Boolean);
    const paths = new Set(parts.map((_, i) => '/' + parts.slice(0, i + 1).join('/')));
    setFlashPaths(paths);
    setTimeout(() => setFlashPaths(new Set()), 3000);
  }, [newEvent]);

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="px-5 py-3 border-b border-gray-800 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <div>
            <h2 className="text-white text-sm font-semibold">Filesystem Tree</h2>
            <p className="text-gray-500 text-xs">Live activity · refreshes every 5s</p>
          </div>
        </div>
        <div className="flex items-center gap-4 text-xs">
          <span className="text-cyan-400">🛡 {canaryCount} canaries</span>
          <span className="text-orange-400">⚠ {alertPaths} hot paths</span>
          <span className={`flex items-center gap-1 ${connected ? 'text-green-400' : 'text-red-400'}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-green-400 animate-pulse' : 'bg-red-500'}`} />
            {lastUpdated ? lastUpdated.toLocaleTimeString('en-JO', { timeZone: 'Asia/Amman' }) : '—'}
          </span>
        </div>
      </div>

      {/* Search */}
      <div className="px-4 py-2 border-b border-gray-800 shrink-0">
        <input
          type="text"
          placeholder="Filter paths…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full bg-gray-800 border border-gray-700 text-gray-300 text-xs rounded-lg px-3 py-1.5 font-mono placeholder-gray-600 focus:outline-none focus:border-indigo-500"
        />
      </div>

      {/* Legend */}
      <div className="px-4 py-2 border-b border-gray-800 flex items-center gap-5 text-xs text-gray-500 shrink-0 flex-wrap">
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-cyan-400" /> Canary zone</span>
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-red-500" /> Alert / hit</span>
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-yellow-400" /> Entropy &gt; 3.5</span>
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-gray-600" /> Normal</span>
        <span className="ml-auto text-gray-700">H: = entropy score (0–8)</span>
      </div>

      {/* Tree */}
      <div className="flex-1 overflow-y-auto p-4 leading-6">
        {!tree ? (
          <p className="text-gray-500 text-sm">Loading filesystem…</p>
        ) : (
          <RootRow node={tree} flashPaths={flashPaths} />
        )}
      </div>
    </div>
  );
}
