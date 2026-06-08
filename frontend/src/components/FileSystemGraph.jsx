import React, { useEffect, useRef, useState, useCallback } from 'react';
import * as d3 from 'd3';
import { getEvents } from '../api/client';

// ─── Graph builder ────────────────────────────────────────────────────────

function emptyStats() {
  return { alertCount: 0, maxEntropy: 0, canaryHit: false, lastEventType: null };
}
function mergeStats(s, ev) {
  if (['HIGH', 'CRITICAL'].includes(ev.severity)) s.alertCount++;
  if ((ev.entropy_delta || 0) > s.maxEntropy) s.maxEntropy = ev.entropy_delta;
  if (ev.canary_hit) s.canaryHit = true;
  s.lastEventType = ev.event_type;
}

function buildGraph(events) {
  const nodesMap = new Map();
  const linksSet = new Set();

  nodesMap.set('/', { id: '/', name: '/', depth: 0, stats: emptyStats(), isCanary: false, isFile: false, isRoot: true });

  for (const ev of events) {
    if (!ev.file_path) continue;
    const parts = ev.file_path.replace(/^\//, '').split('/').filter(Boolean);
    for (let i = 0; i < parts.length; i++) {
      const name  = parts[i];
      const path  = '/' + parts.slice(0, i + 1).join('/');
      const ppath = i === 0 ? '/' : '/' + parts.slice(0, i).join('/');
      if (!nodesMap.has(path)) {
        nodesMap.set(path, { id: path, name, depth: i + 1, stats: emptyStats(), isCanary: /^(AAA_|aaa_|ZZZ_|zzz_)/.test(name), isFile: i === parts.length - 1 });
        linksSet.add(`${ppath}||${path}`);
      }
      mergeStats(nodesMap.get(path).stats, ev);
    }
    mergeStats(nodesMap.get('/').stats, ev);
  }

  const nodes = Array.from(nodesMap.values());
  const links = Array.from(linksSet).map(l => { const [s, t] = l.split('||'); return { source: s, target: t }; });
  return { nodes, links };
}

// ─── Helpers ──────────────────────────────────────────────────────────────

function nodeColor(n, highlightPaths) {
  if (highlightPaths?.has(n.id)) return '#4f8cc9';
  if (n.isCanary && n.stats.canaryHit) return '#f87171';
  if (n.isCanary)                      return '#67e8f9';
  if (n.stats.alertCount > 0)          return '#fb923c';
  if (n.stats.maxEntropy > 3.5)        return '#fbbf24';
  if (n.isRoot)                        return '#a3a6b0';
  return n.isFile ? '#4b5568' : '#374151';
}

function nodeRadius(n, highlightPaths) {
  const base = n.isRoot ? 12 : n.isFile ? 5 : 8;
  const bonus = highlightPaths?.has(n.id) ? 4 : n.stats.alertCount > 0 ? 2 : 0;
  return base + bonus;
}

function buildHighlightPaths(highlightPath) {
  if (!highlightPath) return null;
  const parts = highlightPath.replace(/^\//, '').split('/').filter(Boolean);
  return new Set(['/', ...parts.map((_, i) => '/' + parts.slice(0, i + 1).join('/'))]);
}

// ─── Main component ───────────────────────────────────────────────────────

export default function FileSystemGraph({ highlightPath, newEvent, hostId }) {
  const containerRef = useRef(null);
  const svgRef       = useRef(null);
  const simRef       = useRef(null);

  const [events,    setEvents]    = useState([]);
  const [tooltip,   setTooltip]   = useState(null);
  const [nodeCount, setNodeCount] = useState(0);
  const [loading,   setLoading]   = useState(true);

  // ── fetch events ──────────────────────────────────────────────────────
  const fetchEvents = useCallback(async () => {
    try {
      const params = { limit: 500 };
      if (hostId) params.host_id = hostId;
      const { data } = await getEvents(params);
      setEvents(data);
    } catch (_) {}
    finally { setLoading(false); }
  }, [hostId]);

  useEffect(() => {
    fetchEvents();
    const t = setInterval(fetchEvents, 8000);
    return () => clearInterval(t);
  }, [fetchEvents]);

  // Live event injection
  useEffect(() => {
    if (!newEvent?.file_path) return;
    if (hostId && newEvent.host_id && newEvent.host_id !== hostId) return;
    setEvents(prev => {
      const synth = { id: newEvent.event_id, host_id: newEvent.host_id, event_type: newEvent.event_type, severity: newEvent.severity, file_path: newEvent.file_path, entropy_delta: newEvent.entropy_delta || 0, canary_hit: newEvent.canary_hit || false, timestamp: new Date().toISOString() };
      if (prev.find(e => e.id === synth.id)) return prev;
      return [synth, ...prev];
    });
  }, [newEvent]);

  // ── D3 render ─────────────────────────────────────────────────────────
  useEffect(() => {
    if (!svgRef.current || !containerRef.current || events.length === 0) return;
    let mounted = true;

    const container  = containerRef.current;
    const W          = container.clientWidth  || 600;
    const H          = container.clientHeight || 400;
    const hPaths     = buildHighlightPaths(highlightPath);

    const { nodes, links } = buildGraph(events);
    setNodeCount(nodes.length);

    // Clone nodes/links so D3 can mutate them
    const simNodes = nodes.map(d => ({ ...d, x: W / 2 + (Math.random() - 0.5) * 200, y: H / 2 + (Math.random() - 0.5) * 200 }));
    const nodeById = new Map(simNodes.map(n => [n.id, n]));
    const simLinks = links.map(l => ({ source: nodeById.get(l.source) || l.source, target: nodeById.get(l.target) || l.target }));

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    // ── Defs: glow filters ──────────────────────────────────────────────
    const defs = svg.append('defs');
    const addGlow = (id, color, blur) => {
      const f = defs.append('filter').attr('id', id).attr('x', '-50%').attr('y', '-50%').attr('width', '200%').attr('height', '200%');
      f.append('feGaussianBlur').attr('stdDeviation', blur).attr('result', 'blur');
      f.append('feFlood').attr('flood-color', color).attr('flood-opacity', 0.8).attr('result', 'color');
      f.append('feComposite').attr('in', 'color').attr('in2', 'blur').attr('operator', 'in').attr('result', 'glow');
      const merge = f.append('feMerge');
      merge.append('feMergeNode').attr('in', 'glow');
      merge.append('feMergeNode').attr('in', 'SourceGraphic');
    };
    addGlow('glow-red',    '#f87171', 5);
    addGlow('glow-cyan',   '#67e8f9', 4);
    addGlow('glow-orange', '#fb923c', 4);
    addGlow('glow-blue',   '#4f8cc9', 6);
    addGlow('glow-yellow', '#fbbf24', 3);

    // ── Root group (for zoom/pan) ────────────────────────────────────────
    const g = svg.append('g');

    // ── Zoom ────────────────────────────────────────────────────────────
    const zoom = d3.zoom().scaleExtent([0.15, 5]).on('zoom', ev => g.attr('transform', ev.transform));
    svg.call(zoom).on('dblclick.zoom', null);

    // Auto-fit after simulation settles
    function autoFit() {
      const xs = simNodes.map(n => n.x), ys = simNodes.map(n => n.y);
      const x0 = Math.min(...xs) - 40, x1 = Math.max(...xs) + 40;
      const y0 = Math.min(...ys) - 40, y1 = Math.max(...ys) + 40;
      const scale = Math.min(W / (x1 - x0), H / (y1 - y0), 2);
      const tx = W / 2 - scale * ((x0 + x1) / 2);
      const ty = H / 2 - scale * ((y0 + y1) / 2);
      svg.transition().duration(600).call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
    }

    // ── Links ────────────────────────────────────────────────────────────
    const linkSel = g.append('g').attr('class', 'links')
      .selectAll('line')
      .data(simLinks)
      .join('line')
      .attr('stroke', l => {
        const t = l.target;
        return hPaths?.has(t.id) ? '#4f8cc9' : '#2b2e37';
      })
      .attr('stroke-width', l => hPaths?.has(l.target.id) ? 1.5 : 0.8)
      .attr('stroke-opacity', l => hPaths?.has(l.target.id) ? 0.9 : 0.45);

    // ── Node groups ──────────────────────────────────────────────────────
    const nodeSel = g.append('g').attr('class', 'nodes')
      .selectAll('g')
      .data(simNodes)
      .join('g')
      .attr('cursor', 'pointer')
      .call(
        d3.drag()
          .on('start', (ev, d) => { if (!ev.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
          .on('drag',  (ev, d) => { d.fx = ev.x; d.fy = ev.y; })
          .on('end',   (ev, d) => { if (!ev.active) sim.alphaTarget(0); d.fx = null; d.fy = null; })
      )
      .on('mouseenter', (ev, d) => {
        if (!mounted) return;
        const rect = containerRef.current.getBoundingClientRect();
        setTooltip({ x: ev.clientX - rect.left, y: ev.clientY - rect.top, node: d });
      })
      .on('mousemove', (ev, d) => {
        if (!mounted) return;
        const rect = containerRef.current.getBoundingClientRect();
        setTooltip({ x: ev.clientX - rect.left, y: ev.clientY - rect.top, node: d });
      })
      .on('mouseleave', () => { if (mounted) setTooltip(null); });

    // Outer glow ring for highlighted / alert nodes
    nodeSel.append('circle')
      .attr('r', d => {
        if (hPaths?.has(d.id)) return nodeRadius(d, hPaths) + 6;
        if (d.isCanary && d.stats.canaryHit) return nodeRadius(d, hPaths) + 5;
        if (d.stats.alertCount > 0)          return nodeRadius(d, hPaths) + 4;
        return 0;
      })
      .attr('fill', 'none')
      .attr('stroke', d => nodeColor(d, hPaths))
      .attr('stroke-width', 1)
      .attr('stroke-opacity', 0.35)
      .attr('stroke-dasharray', d => hPaths?.has(d.id) ? '3,3' : null);

    // Main circle
    nodeSel.append('circle')
      .attr('r', d => nodeRadius(d, hPaths))
      .attr('fill', d => nodeColor(d, hPaths))
      .attr('fill-opacity', d => d.isFile ? 0.75 : 0.9)
      .attr('filter', d => {
        if (hPaths?.has(d.id))              return 'url(#glow-blue)';
        if (d.isCanary && d.stats.canaryHit) return 'url(#glow-red)';
        if (d.isCanary)                      return 'url(#glow-cyan)';
        if (d.stats.alertCount > 0)          return 'url(#glow-orange)';
        if (d.stats.maxEntropy > 3.5)        return 'url(#glow-yellow)';
        return null;
      });

    // Label: root, canary, highlighted, or high-alert nodes only
    nodeSel.append('text')
      .text(d => {
        const show = d.isRoot || d.isCanary || hPaths?.has(d.id) || d.stats.alertCount > 1;
        return show ? d.name : null;
      })
      .attr('x', d => nodeRadius(d, hPaths) + 4)
      .attr('y', 4)
      .attr('font-size', d => d.isRoot ? 11 : 9)
      .attr('font-family', 'var(--mono)')
      .attr('fill', d => {
        if (hPaths?.has(d.id)) return '#4f8cc9';
        if (d.isCanary)        return '#67e8f9';
        if (d.stats.alertCount > 0) return '#fb923c';
        return '#6b7280';
      })
      .attr('pointer-events', 'none');

    // ── Simulation ───────────────────────────────────────────────────────
    const sim = d3.forceSimulation(simNodes)
      .force('link',    d3.forceLink(simLinks).id(d => d.id).distance(d => d.target.isFile ? 28 : 48).strength(0.9))
      .force('charge',  d3.forceManyBody().strength(d => d.isFile ? -35 : -70))
      .force('center',  d3.forceCenter(W / 2, H / 2).strength(0.05))
      .force('collide', d3.forceCollide(d => nodeRadius(d, hPaths) + 4))
      .force('radial',  hPaths
        ? d3.forceRadial(0, W / 2, H / 2).strength(d => hPaths.has(d.id) ? 0.6 : 0)
        : null
      );

    simRef.current = sim;

    sim.on('tick', () => {
      linkSel
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y);
      nodeSel.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    sim.on('end', autoFit);

    return () => { mounted = false; svg.interrupt(); svg.on('.zoom', null); sim.stop(); };
  }, [events, highlightPath]);

  return (
    <div ref={containerRef} style={{ width: '100%', height: '100%', position: 'relative', background: 'var(--bg)', borderRadius: 6, overflow: 'hidden' }}>

      {/* SVG canvas */}
      <svg ref={svgRef} style={{ width: '100%', height: '100%' }} />

      {/* Loading */}
      {loading && (
        <div style={{ position: 'absolute', inset: 0, display: 'grid', placeItems: 'center', color: 'var(--muted)', fontSize: 12, fontFamily: 'var(--mono)', pointerEvents: 'none' }}>
          <span><i className="fa-solid fa-circle-notch fa-spin" style={{ marginRight: 6 }} />Building graph…</span>
        </div>
      )}

      {/* Empty state */}
      {!loading && events.length === 0 && (
        <div style={{ position: 'absolute', inset: 0, display: 'grid', placeItems: 'center', color: 'var(--muted)', fontSize: 12, pointerEvents: 'none' }}>
          <span><i className="fa-solid fa-folder-open" style={{ marginRight: 6 }} />No filesystem events yet</span>
        </div>
      )}

      {/* Tooltip */}
      {tooltip && (
        <div style={{
          position: 'absolute',
          left:  tooltip.x + 14,
          top:   tooltip.y - 10,
          background: 'var(--panel-2)',
          border: '1px solid var(--border)',
          borderRadius: 6,
          padding: '7px 10px',
          fontSize: 11,
          fontFamily: 'var(--mono)',
          color: 'var(--text)',
          pointerEvents: 'none',
          maxWidth: 260,
          zIndex: 10,
          boxShadow: '0 4px 16px rgba(0,0,0,0.4)',
        }}>
          <div style={{ fontWeight: 600, marginBottom: 3, wordBreak: 'break-all' }}>{tooltip.node.id}</div>
          {tooltip.node.stats.alertCount > 0 && (
            <div style={{ color: '#fb923c' }}>⚠ {tooltip.node.stats.alertCount} alert{tooltip.node.stats.alertCount !== 1 ? 's' : ''}</div>
          )}
          {tooltip.node.isCanary && tooltip.node.stats.canaryHit && (
            <div style={{ color: '#f87171' }}>🛡 CANARY HIT</div>
          )}
          {tooltip.node.isCanary && !tooltip.node.stats.canaryHit && (
            <div style={{ color: '#67e8f9' }}>🛡 Canary file</div>
          )}
          {tooltip.node.stats.maxEntropy > 0 && (
            <div style={{ color: tooltip.node.stats.maxEntropy > 5 ? '#ef4444' : tooltip.node.stats.maxEntropy > 3.5 ? '#fbbf24' : '#6b7280' }}>
              H: {tooltip.node.stats.maxEntropy.toFixed(2)}
            </div>
          )}
          <div style={{ color: 'var(--muted)', marginTop: 2 }}>{tooltip.node.isFile ? 'file' : tooltip.node.isRoot ? 'root' : 'directory'}</div>
        </div>
      )}

      {/* Legend + node count */}
      <div style={{ position: 'absolute', bottom: 8, left: 8, display: 'flex', gap: 10, flexWrap: 'wrap', pointerEvents: 'none' }}>
        {[
          { color: '#4f8cc9', label: 'Selected path' },
          { color: '#f87171', label: 'Canary hit' },
          { color: '#67e8f9', label: 'Canary' },
          { color: '#fb923c', label: 'Alert' },
          { color: '#fbbf24', label: 'High entropy' },
        ].map(({ color, label }) => (
          <span key={label} style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 10, color: 'var(--muted)', fontFamily: 'var(--mono)' }}>
            <span style={{ width: 7, height: 7, borderRadius: '50%', background: color, display: 'inline-block' }} />
            {label}
          </span>
        ))}
      </div>
      <div style={{ position: 'absolute', top: 8, right: 8, fontSize: 10, color: 'var(--faint)', fontFamily: 'var(--mono)', pointerEvents: 'none' }}>
        {nodeCount} nodes · scroll to zoom · drag to pan
      </div>
    </div>
  );
}
