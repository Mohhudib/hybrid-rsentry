import { useRef, useState } from 'react';
import { motion, useInView, AnimatePresence } from 'framer-motion';

const NODES = [
  {
    id: 'file-write',
    emoji: '🔴',
    label: 'FILE WRITE',
    latency: '< 1ms',
    color: '#ff1744',
    detail: 'inotify kernel event fires the moment a file handle opens for write. Zero polling overhead.',
    shake: false,
  },
  {
    id: 'entropy',
    emoji: '📊',
    label: 'ENTROPY ENGINE',
    latency: '< 2ms',
    color: '#00f5ff',
    detail: 'Shannon entropy computed per 4KB block. Sliding window across all watched directories in parallel.',
    shake: false,
  },
  {
    id: 'lineage',
    emoji: '🧬',
    label: 'LINEAGE SCORER',
    latency: '< 20ms',
    color: '#b537f2',
    detail: 'Scores process ancestry against 416K dpkg hashes loaded at startup. Binary mismatch, /tmp spawn, or no TTY each add weight to a 0–100 score.',
    shake: false,
  },
  {
    id: 'combined',
    emoji: '⚡',
    label: 'COMBINED SCORE',
    latency: '< 8ms',
    color: '#ffd700',
    detail: 'Weighted sum of entropy delta + lineage score + canary signal. Threshold: 65/100 triggers SIGSTOP.',
    shake: false,
  },
  {
    id: 'sigstop',
    emoji: '🔒',
    label: 'SIGSTOP PIPELINE',
    latency: '< 200ms',
    color: '#ff1744',
    detail: 'SIGSTOP → /proc forensics capture → iptables network block → SIGKILL. No escape.',
    shake: true,
  },
  {
    id: 'ai',
    emoji: '🤖',
    label: 'AI ANALYST',
    latency: '< 2s',
    color: '#b537f2',
    detail: 'Powerful LLM reads /proc forensics and renders a plain-English verdict: threat or benign.',
    shake: false,
  },
  {
    id: 'dashboard',
    emoji: '📡',
    label: 'LIVE DASHBOARD',
    latency: 'realtime',
    color: '#00ff88',
    detail: 'React dashboard receives events via Redis WebSocket and renders the threat graph live.',
    shake: false,
  },
];


function HexNode({ node, index }) {
  const [hovered, setHovered] = useState(false);
  const isRed = node.color === '#ff1744';

  return (
    <motion.div
      initial={{ opacity: 0, y: 40 }}
      whileInView={{ opacity: 1, y: node.shake ? -20 : -20 }}
      viewport={{ once: true, amount: 0.5 }}
      transition={{ duration: 0.5, delay: index * 0.12 }}
      className={`relative flex flex-col items-center cursor-pointer ${node.shake ? 'shake' : ''}`}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      data-hover
    >
      {/* Hex shape */}
      <div
        className="hex relative flex flex-col items-center justify-center w-24 h-28 transition-all duration-300"
        style={{
          background: `radial-gradient(circle, ${node.color}22 0%, ${node.color}08 100%)`,
          border: `2px solid ${node.color}`,
          boxShadow: hovered
            ? `0 0 30px ${node.color}80, 0 0 60px ${node.color}30`
            : `0 0 12px ${node.color}40`,
          transform: hovered ? 'scale(1.12)' : 'scale(1)',
        }}
      >
        <span className="text-2xl mb-0.5">{node.emoji}</span>
        <span
          className="font-mono font-bold text-center leading-tight px-1"
          style={{ fontSize: 8, color: node.color, letterSpacing: 1 }}
        >
          {node.label}
        </span>
        {/* Latency badge */}
        <div
          className="absolute -top-3 -right-3 px-1.5 py-0.5 rounded font-mono"
          style={{ background: node.color, color: '#000', fontSize: 8, fontWeight: 700 }}
        >
          {node.latency}
        </div>
      </div>

      {/* Hover detail card */}
      <AnimatePresence>
        {hovered && (
          <motion.div
            initial={{ opacity: 0, y: 10, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 10, scale: 0.95 }}
            transition={{ duration: 0.2 }}
            className="absolute z-30 w-52 glass rounded-lg p-3 bottom-full mb-4 text-left"
            style={{ border: `1px solid ${node.color}60`, boxShadow: `0 0 20px ${node.color}30` }}
          >
            <p className="font-mono text-[10px] text-gray-300 leading-relaxed">{node.detail}</p>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// Animated traveling pulse on SVG path
function PulsePath({ d, color = '#00f5ff' }) {
  return (
    <g>
      <path d={d} stroke={color} strokeWidth="1" strokeOpacity="0.25" fill="none" />
      <path
        d={d}
        stroke={color}
        strokeWidth="2"
        fill="none"
        strokeDasharray="12 150"
        strokeOpacity="0.9"
        style={{ animation: 'dash-travel 2s linear infinite' }}
      />
    </g>
  );
}

export default function ThreatTimeline() {
  const ref = useRef();
  const inView = useInView(ref, { once: true, amount: 0.2 });
  const nodeMap = Object.fromEntries(NODES.map((n) => [n.id, n]));

  return (
    <section id="timeline" ref={ref} className="section py-28 px-6">
      {/* Section header */}
      <div className="max-w-4xl mx-auto text-center mb-16">
        <motion.p
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          className="font-mono text-xs tracking-widest text-[#00f5ff] mb-3 uppercase"
        >
          Detection Pipeline
        </motion.p>
        <motion.h2
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ delay: 0.1 }}
          className="font-heading font-bold mb-4"
          style={{ fontSize: 'clamp(1.8rem, 4vw, 3rem)', color: '#fff' }}
        >
          From First Byte to Full Containment
        </motion.h2>
        <motion.p
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ delay: 0.2 }}
          className="font-mono text-sm text-gray-400 max-w-xl mx-auto"
        >
          Four detection layers fire in parallel. Ransomware has nowhere to hide.
        </motion.p>
      </div>

      {/* Pipeline layout */}
      <div className="max-w-5xl mx-auto">
        {/* Row 1: FILE WRITE → ENTROPY ENGINE → LINEAGE SCORER */}
        <div className="flex items-start justify-center gap-4 md:gap-8 mb-8 flex-wrap">
          {['file-write', 'entropy', 'lineage'].map((id, i) => (
            <div key={id} className="flex items-center gap-4">
              <HexNode node={nodeMap[id]} index={i} />
              {i < 2 && (
                <svg width="40" height="4" className="hidden md:block">
                  <PulsePath d="M 0 2 L 40 2" color={nodeMap[id].color} />
                </svg>
              )}
            </div>
          ))}
        </div>

        {/* Vertical drops */}
        <div className="flex justify-center gap-8 md:gap-40 mb-0">
          <svg width="4" height="40" className="hidden md:block">
            <PulsePath d="M 2 0 L 2 40" color="#00f5ff" />
          </svg>
          <svg width="4" height="40" className="hidden md:block">
            <PulsePath d="M 2 0 L 2 40" color="#b537f2" />
          </svg>
        </div>

        {/* Row 2: COMBINED SCORE → SIGSTOP */}
        <div className="flex items-start justify-center gap-4 md:gap-8 mb-8 flex-wrap">
          {['combined', 'sigstop'].map((id, i) => (
            <div key={id} className="flex items-center gap-4">
              <HexNode node={nodeMap[id]} index={3 + i} />
              {i < 1 && (
                <svg width="40" height="4" className="hidden md:block">
                  <PulsePath d="M 0 2 L 40 2" color={nodeMap[id].color} />
                </svg>
              )}
            </div>
          ))}
        </div>

        {/* Vertical drop from combined */}
        <div className="flex justify-start pl-[calc(50%-8rem)] mb-0">
          <svg width="4" height="40" className="hidden md:block">
            <PulsePath d="M 2 0 L 2 40" color="#ffd700" />
          </svg>
        </div>

        {/* Row 3: AI ANALYST → LIVE DASHBOARD */}
        <div className="flex items-start justify-center gap-4 md:gap-8 flex-wrap">
          {['ai', 'dashboard'].map((id, i) => (
            <div key={id} className="flex items-center gap-4">
              <HexNode node={nodeMap[id]} index={5 + i} />
              {i < 1 && (
                <svg width="40" height="4" className="hidden md:block">
                  <PulsePath d="M 0 2 L 40 2" color={nodeMap[id].color} />
                </svg>
              )}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
