import React, { useEffect, useState, useCallback, useRef } from 'react';
import { getEvents } from '../api/client';

// ─── Tree builder ──────────────────────────────────────────────────────────

function emptyStats() {
  return { alertCount: 0, maxEntropy: 0, hasCanary: false, canaryHit: false, lastEventType: null, lastSeverity: null };
}

function mergeStats(target, event) {
  if (['HIGH', 'CRITICAL'].includes(event.severity)) target.alertCount++;
  if (event.entropy_delta > target.maxEntropy) target.maxEntropy = event.entropy_delta;
  if (event.canary_hit) target.canaryHit = true;
  target.lastEventType = event.event_type;
  target.lastSeverity = event.severity;
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
          name,
          path,
          children: {},
          stats: emptyStats(),
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
    const aIsDir = Object.keys(a.children).length > 0;
    const bIsDir = Object.keys(b.children).length > 0;
    if (aIsDir !== bIsDir) return aIsDir ? -1 : 1;
    return a.name.localeCompare(b.name);
  });
}

// ─── Node colours ─────────────────────────────────────────────────────────

function nodeStyle(node) {
  if (node.isCanary && node.stats.canaryHit) return { text: 'text-red-400', bg: 'bg-red-900/30', border: 'border-red-700', badge: 'CANARY HIT' };
  if (node.isCanary) return { text: 'text-cyan-300', bg: 'bg-cyan-900/20', border: 'border-cyan-700', badge: 'CANARY' };
  if (node.stats.alertCount > 0) return { text: 'text-orange-300', bg: 'bg-orange-900/20', border: 'border-orange-700', badge: null };
  if (node.stats.maxEntropy > 3.5) return { text: 'text-yellow-300', bg: 'bg-yellow-900/10', border: 'border-yellow-700/50', badge: null };
  return { text: 'text-gray-300', bg: '', border: 'border-transparent', badge: null };
}

function EntropyBar({ value }) {
  const pct = Math.min(100, (value / 8) * 100);
  const color = value > 5 ? 'bg-red-500' : value > 3.5 ? 'bg-yellow-400' : 'bg-green-500';
  return (
    <div className="flex items-center gap-1">
      <div className="w-12 h-1.5 bg-gray-700 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-gray-500 text-xs">{value.toFixed(1)}</span>
    </div>
  );
}

// ─── Tree node component ───────────────────────────────────────────────────

function TreeNode({ node, depth = 0, flashPaths, defaultOpen }) {
  const hasChildren = Object.keys(node.children).length > 0;
  const [open, setOpen] = useState(defaultOpen || depth < 2 || node.stats.alertCount > 0 || node.isCanary);
  const isFlashing = flashPaths.has(node.path);
  const style = nodeStyle(node);

  return (
    <div className={`${depth > 0 ? 'ml-4 border-l border-gray-800' : ''}`}>
      <div
        className={`flex items-center gap-1.5 px-2 py-0.5 rounded cursor-pointer group border ${style.bg} ${style.border} ${
          isFlashing ? 'animate-pulse' : ''
        } hover:bg-gray-800/50 transition-all`}
        onClick={() => hasChildren && setOpen((o) => !o)}
      >
        {/* Expand toggle */}
        <span className="text-gray-600 w-3 text-xs shrink-0">
          {hasChildren ? (open ? '▾' : '▸') : ' '}
        </span>

        {/* Icon */}
        <span className="text-xs shrink-0">
          {node.isCanary ? '🛡' : node.isFile ? '📄' : open ? '📂' : '📁'}
        </span>

        {/* Name */}
        <span className={`text-xs font-mono ${style.text} truncate flex-1`}>{node.name}</span>

        {/* Badge */}
        {style.badge && (
          <span className={`text-xs px-1.5 py-0.5 rounded font-bold shrink-0 ${
            style.badge === 'CANARY HIT' ? 'bg-red-600 text-white' : 'bg-cyan-800 text-cyan-200'
          }`}>
            {style.badge}
          </span>
        )}

        {/* Alert count */}
        {node.stats.alertCount > 0 && (
          <span className="text-xs bg-red-700 text-white px-1.5 py-0.5 rounded-full font-bold shrink-0">
            {node.stats.alertCount}
          </span>
        )}

        {/* Entropy bar */}
        {node.stats.maxEntropy > 0 && (
          <div className="shrink-0 hidden group-hover:flex items-center">
            <EntropyBar value={node.stats.maxEntropy} />
          </div>
        )}
      </div>

      {/* Children */}
      {hasChildren && open && (
        <div>
          {sortChildren(node.children).map((child) => (
            <TreeNode key={child.path} node={child} depth={depth + 1} flashPaths={flashPaths} defaultOpen={false} />
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Main component ────────────────────────────────────────────────────────

export default function FileSystemTree({ newEvent }) {
  const [tree, setTree] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [flashPaths, setFlashPaths] = useState(new Set());
  const [canaryCount, setCanaryCount] = useState(0);
  const [alertPaths, setAlertPaths] = useState(0);
  const eventsRef = useRef([]);

  const rebuild = useCallback((events) => {
    eventsRef.current = events;
    const t = buildTree(events);
    setTree(t);
    setLastUpdated(new Date());

    // Count canaries and alert paths
    let canaries = 0;
    let alerts = 0;
    const countNodes = (node) => {
      if (node.isCanary) canaries++;
      if (node.stats.alertCount > 0) alerts++;
      Object.values(node.children).forEach(countNodes);
    };
    countNodes(t);
    setCanaryCount(canaries);
    setAlertPaths(alerts);
  }, []);

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

  // Flash new event path on WS push
  useEffect(() => {
    if (!newEvent?.file_path) return;
    const parts = newEvent.file_path.replace(/^\//, '').split('/').filter(Boolean);
    const paths = new Set(parts.map((_, i) => '/' + parts.slice(0, i + 1).join('/')));
    setFlashPaths(paths);
    setTimeout(() => setFlashPaths(new Set()), 3000);
  }, [newEvent]);

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl flex flex-col h-full">
      {/* Header */}
      <div className="px-4 py-3 border-b border-gray-800 flex items-center justify-between">
        <div>
          <h2 className="text-white text-sm font-semibold">Filesystem Monitor</h2>
          <p className="text-gray-500 text-xs mt-0.5">Live activity tree</p>
        </div>
        <div className="flex items-center gap-3 text-xs">
          <span className="flex items-center gap-1 text-cyan-400">
            <span>🛡</span> {canaryCount} canaries
          </span>
          <span className="flex items-center gap-1 text-orange-400">
            <span>⚠</span> {alertPaths} hot paths
          </span>
          {lastUpdated && (
            <span className="text-gray-600">
              {lastUpdated.toLocaleTimeString()}
            </span>
          )}
        </div>
      </div>

      {/* Legend */}
      <div className="px-4 py-2 border-b border-gray-800 flex items-center gap-4 text-xs flex-wrap">
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-cyan-400 inline-block" /> Canary zone</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-500 inline-block" /> Alert / canary hit</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-yellow-400 inline-block" /> Entropy spike</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-gray-500 inline-block" /> Normal</span>
        <span className="text-gray-600 ml-auto">Hover node for entropy</span>
      </div>

      {/* Tree */}
      <div className="flex-1 overflow-y-auto p-3 font-mono text-xs">
        {!tree ? (
          <p className="text-gray-500 text-sm p-2">Loading filesystem…</p>
        ) : (
          <TreeNode node={tree} depth={0} flashPaths={flashPaths} defaultOpen />
        )}
      </div>
    </div>
  );
}
