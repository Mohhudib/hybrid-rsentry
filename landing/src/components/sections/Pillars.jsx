import { useRef, useState, useEffect } from 'react';
import { motion } from 'framer-motion';

/* ── Entropy animated chart (Canvas 2D, not WebGL) ── */
function EntropyChart({ color }) {
  const canvasRef = useRef();
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let frame, t = 0;
    const draw = () => {
      t += 0.025;
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      // threshold line
      const threshY = canvas.height * 0.35;
      ctx.strokeStyle = `rgba(255,23,68,${0.4 + 0.4 * Math.sin(t * 3)})`;
      ctx.setLineDash([4, 4]);
      ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(0, threshY); ctx.lineTo(canvas.width, threshY); ctx.stroke();
      ctx.setLineDash([]);
      // entropy curve
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.shadowBlur = 8; ctx.shadowColor = color;
      ctx.beginPath();
      for (let x = 0; x < canvas.width; x++) {
        const p = x / canvas.width;
        const base  = 0.5 + 0.18 * Math.sin(p * 8 + t);
        const spike = p > 0.6 && p < 0.8 ? (p - 0.6) * 5 : 0;
        const y = canvas.height * (1 - base - spike * 0.55);
        x === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
      }
      ctx.stroke();
      frame = requestAnimationFrame(draw);
    };
    draw();
    return () => cancelAnimationFrame(frame);
  }, [color]);
  return <canvas ref={canvasRef} width={220} height={56} className="w-full rounded" />;
}

/* ── CSS DNA helix icon ── */
function HelixIcon({ color }) {
  return (
    <div className="relative w-full h-full flex items-center justify-center overflow-hidden">
      {Array.from({ length: 10 }).map((_, i) => {
        const offset = (i / 9) * 100;
        return (
          <div key={i} className="absolute w-full flex justify-between px-8" style={{ top: `${offset}%` }}>
            <motion.div
              className="w-3 h-3 rounded-full"
              style={{ background: color, boxShadow: `0 0 8px ${color}` }}
              animate={{ x: [0, 12, 0, -12, 0] }}
              transition={{ duration: 2, delay: i * 0.12, repeat: Infinity, ease: 'easeInOut' }}
            />
            <motion.div
              className="w-3 h-3 rounded-full"
              style={{ background: color, boxShadow: `0 0 8px ${color}`, opacity: 0.6 }}
              animate={{ x: [0, -12, 0, 12, 0] }}
              transition={{ duration: 2, delay: i * 0.12, repeat: Infinity, ease: 'easeInOut' }}
            />
            <motion.div
              className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 h-px w-1/2"
              style={{ background: `linear-gradient(90deg, ${color}40, ${color}, ${color}40)` }}
            />
          </div>
        );
      })}
    </div>
  );
}

/* ── CSS Waveform icon ── */
function WaveformIcon({ color }) {
  return (
    <div className="w-full h-full flex items-center justify-center gap-1 px-4">
      {Array.from({ length: 18 }).map((_, i) => (
        <motion.div
          key={i}
          className="flex-1 rounded-sm"
          style={{ background: color, boxShadow: `0 0 6px ${color}80` }}
          animate={{ height: ['20%', `${30 + Math.sin(i * 0.8) * 60}%`, '20%'] }}
          transition={{ duration: 1.4, delay: i * 0.06, repeat: Infinity, ease: 'easeInOut' }}
        />
      ))}
    </div>
  );
}

/* ── CSS Markov graph icon ── */
function MarkovIcon({ color }) {
  const nodes = [
    { cx: 50, cy: 20 },
    { cx: 20, cy: 55 },
    { cx: 80, cy: 55 },
    { cx: 35, cy: 85 },
    { cx: 65, cy: 85 },
  ];
  const edges = [[0,1],[0,2],[1,2],[1,3],[2,4],[3,4]];
  return (
    <svg viewBox="0 0 100 100" className="w-full h-full p-4">
      {edges.map(([a,b], i) => (
        <motion.line
          key={i}
          x1={nodes[a].cx} y1={nodes[a].cy}
          x2={nodes[b].cx} y2={nodes[b].cy}
          stroke={color} strokeWidth="1" strokeOpacity="0.4"
          animate={{ strokeOpacity: [0.2, 0.7, 0.2] }}
          transition={{ duration: 2, delay: i * 0.3, repeat: Infinity }}
        />
      ))}
      {nodes.map((n, i) => (
        <motion.circle
          key={i}
          cx={n.cx} cy={n.cy} r="6"
          fill={color}
          animate={{ r: [5, 7, 5], opacity: [0.7, 1, 0.7] }}
          transition={{ duration: 1.6, delay: i * 0.25, repeat: Infinity }}
          style={{ filter: `drop-shadow(0 0 4px ${color})` }}
        />
      ))}
    </svg>
  );
}

/* ── CSS Padlock icon ── */
function PadlockIcon({ color, isHovered }) {
  return (
    <div className="w-full h-full flex items-center justify-center">
      <motion.div
        animate={{ scale: isHovered ? [1, 1.15, 1] : 1, rotate: isHovered ? [0, -8, 0] : 0 }}
        transition={{ duration: 0.4 }}
      >
        <svg viewBox="0 0 60 80" width="70" height="90">
          {/* shackle */}
          <motion.path
            d="M15 35 Q15 10 30 10 Q45 10 45 35"
            fill="none" stroke={color} strokeWidth="5" strokeLinecap="round"
            animate={isHovered ? { d: 'M15 35 Q15 20 30 20 Q45 20 45 35' } : { d: 'M15 35 Q15 10 30 10 Q45 10 45 35' }}
            transition={{ duration: 0.3 }}
            style={{ filter: `drop-shadow(0 0 4px ${color})` }}
          />
          {/* body */}
          <rect x="8" y="33" width="44" height="34" rx="5" fill={color} opacity="0.85"
            style={{ filter: `drop-shadow(0 0 8px ${color})` }} />
          {/* keyhole */}
          <circle cx="30" cy="47" r="5" fill="#000010" />
          <rect x="27" y="47" width="6" height="8" rx="2" fill="#000010" />
        </svg>
      </motion.div>
    </div>
  );
}

/* ── Prediction counter ── */
function PredictionCounter() {
  const [val, setVal] = useState(87);
  useEffect(() => {
    const id = setInterval(() => {
      setVal(v => Math.max(60, Math.min(97, Math.round(v + (Math.random() - 0.45) * 3))));
    }, 1200);
    return () => clearInterval(id);
  }, []);
  return (
    <div className="font-mono text-xs text-center mt-2">
      <span className="text-gray-500">Prediction confidence: </span>
      <motion.span
        key={val}
        initial={{ opacity: 0, y: -4 }}
        animate={{ opacity: 1, y: 0 }}
        className="font-bold"
        style={{ color: '#00f5ff' }}
      >
        {val}%
      </motion.span>
    </div>
  );
}

/* ── SIGSTOP step badges ── */
function SigstopBadges() {
  const steps  = ['FREEZE', 'CAPTURE', 'BLOCK', 'KILL'];
  const colors = ['#ff5722', '#ff9800', '#ff1744', '#b71c1c'];
  const [active, setActive] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setActive(a => (a + 1) % steps.length), 700);
    return () => clearInterval(id);
  }, []);
  return (
    <div className="flex gap-1 flex-wrap mt-2 justify-center">
      {steps.map((s, i) => (
        <motion.span
          key={s}
          animate={active === i
            ? { scale: 1.1, boxShadow: `0 0 12px ${colors[i]}` }
            : { scale: 1, boxShadow: 'none' }}
          className="font-mono text-[9px] px-2 py-0.5 rounded-full font-bold transition-colors duration-300"
          style={{
            background: active === i ? colors[i] : 'transparent',
            border: `1px solid ${colors[i]}`,
            color: active === i ? '#000' : colors[i],
          }}
        >
          {s}
        </motion.span>
      ))}
    </div>
  );
}

/* ── Lineage badges ── */
function LineageBadges() {
  return (
    <div className="flex gap-1 flex-wrap mt-2 justify-center">
      {['/tmp/ +50', 'Unknown hash +25', 'No TTY +5'].map(label => (
        <span key={label} className="font-mono text-[9px] px-2 py-0.5 rounded font-bold"
          style={{ background: '#b537f218', border: '1px solid #b537f2', color: '#b537f2' }}>
          {label}
        </span>
      ))}
    </div>
  );
}

/* ── Card definitions ── */
const CARDS = [
  {
    id: 'entropy', title: 'Entropy Velocity Profiling', color: '#ffd700',
    icon: (hov) => <WaveformIcon color="#ffd700" />,
    body: 'Shannon entropy computed across all directories simultaneously. When 3+ directories spike together within 10 seconds — ransomware is encrypting in bulk. EVP catches what signatures miss.',
    extra: <EntropyChart color="#ffd700" />,
  },
  {
    id: 'lineage', title: 'Process Lineage Scoring', color: '#b537f2',
    icon: (hov) => <HelixIcon color="#b537f2" />,
    body: 'Every process has a family tree. We score its entire ancestry — parent names, spawn location, binary SHA-256 hash. A process born in /tmp with no TTY scores 80/100 immediately.',
    extra: <LineageBadges />,
  },
  {
    id: 'canary', title: 'Adaptive Canary Repositioning', color: '#00f5ff',
    icon: (hov) => <MarkovIcon color="#00f5ff" />,
    body: "15 AAA_ canary files move themselves. A Markov transition matrix learns the ransomware's traversal pattern and predicts its next directory — placing a canary there before it arrives.",
    extra: <PredictionCounter />,
  },
  {
    id: 'sigstop', title: 'SIGSTOP Containment', color: '#ff1744',
    icon: (hov) => <PadlockIcon color="#ff1744" isHovered={hov} />,
    body: 'Four steps. No escape. SIGSTOP freezes execution → /proc forensics captured → iptables cuts all network traffic → SIGKILL ends the process. Total time: under 200ms.',
    extra: <SigstopBadges />,
  },
];

function PillarCard({ card, index }) {
  const [hovered, setHovered] = useState(false);
  return (
    <motion.div
      initial={{ opacity: 0, y: 60 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.2 }}
      transition={{ duration: 0.6, delay: index * 0.12 }}
      whileHover={{ y: -30, rotateX: 3, rotateY: index % 2 === 0 ? 3 : -3 }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      className="glass rounded-2xl p-6 flex flex-col relative overflow-hidden"
      style={{
        border: `1px solid ${card.color}40`,
        boxShadow: hovered
          ? `0 30px 60px ${card.color}30, 0 0 40px ${card.color}20`
          : `0 20px 40px ${card.color}15, 0 0 20px ${card.color}10`,
        transformStyle: 'preserve-3d',
        transform: 'translateY(-20px)',
      }}
    >
      <div className="absolute top-0 left-0 right-0 h-px"
        style={{ background: `linear-gradient(90deg, transparent, ${card.color}, transparent)` }} />

      {/* CSS/SVG Icon (no WebGL) */}
      <div className="h-28 mb-4 rounded-lg overflow-hidden flex items-center justify-center"
        style={{ background: `${card.color}08` }}>
        {card.icon(hovered)}
      </div>

      <h3 className="font-heading font-bold text-base mb-2"
        style={{ color: card.color, textShadow: `0 0 10px ${card.color}60` }}>
        {card.title}
      </h3>

      <p className="font-mono text-[11px] text-gray-400 leading-relaxed flex-1 mb-3">
        {card.body}
      </p>

      {card.extra}

      <div className="absolute top-4 right-4 w-6 h-6 rounded-full flex items-center justify-center"
        style={{ background: `${card.color}30`, border: `1px solid ${card.color}` }}>
        <span className="font-mono text-[8px] font-bold" style={{ color: card.color }}>
          {String(index + 1).padStart(2, '0')}
        </span>
      </div>
    </motion.div>
  );
}

export default function Pillars() {
  return (
    <section id="pillars" className="section py-28 px-6">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-16">
          <motion.p initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} viewport={{ once: true }}
            className="font-mono text-xs tracking-widest text-[#b537f2] mb-3 uppercase">
            Four Enhancements
          </motion.p>
          <motion.h2 initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }} transition={{ delay: 0.1 }}
            className="font-heading font-bold"
            style={{ fontSize: 'clamp(1.8rem, 4vw, 3rem)', color: '#fff' }}>
            Four Enhancements.{' '}
            <span style={{ color: '#00f5ff' }}>One Unbreakable Shield.</span>
          </motion.h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 pt-5">
          {CARDS.map((card, i) => (
            <PillarCard key={card.id} card={card} index={i} />
          ))}
        </div>
      </div>
    </section>
  );
}
