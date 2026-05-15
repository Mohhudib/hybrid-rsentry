import { useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

/* ── Alert generation ── */
const PATHS = [
  '/home/user/Documents/AAA_a3f9.txt',
  '/home/user/Downloads/invoice.pdf',
  '/home/user/Desktop/report.docx',
  '/home/user/.config/startup.sh',
  '/home/user/Music/playlist.m3u',
  '/var/tmp/svchost32.exe',
  '/home/user/Pictures/IMG_4821.jpg',
];
const TYPES = ['CANARY_TOUCHED', 'COMBINED_ALERT', 'ENTROPY_SPIKE', 'LINEAGE_SCORE', 'AI_AUTO_ACK'];
const LEVELS = [
  { label: '🔴 CRITICAL', color: '#ff1744', bg: '#ff174415' },
  { label: '🟠 HIGH',     color: '#ff9800', bg: '#ff980015' },
  { label: '🟡 MEDIUM',   color: '#ffd700', bg: '#ffd70015' },
  { label: '🤖 AI ACK',   color: '#b537f2', bg: '#b537f215' },
];

let alertId = 0;
function generateAlert() {
  const levelIdx = Math.floor(Math.random() * LEVELS.length);
  const level = LEVELS[levelIdx];
  const type = levelIdx === 3 ? 'AI_AUTO_ACK' : TYPES[Math.floor(Math.random() * (TYPES.length - 1))];
  const path = PATHS[Math.floor(Math.random() * PATHS.length)];
  const pid  = Math.floor(Math.random() * 9000) + 1000;
  return {
    id: ++alertId,
    level,
    type,
    path,
    pid,
    ts: new Date().toLocaleTimeString('en-US', { hour12: false }),
    isAI: levelIdx === 3,
  };
}

/* ── Risk Gauge SVG ── */
function RiskGauge({ value }) {
  const R = 70;
  const circ = Math.PI * R; // half circle arc
  const pct  = Math.min(value / 100, 1);
  const dash = pct * circ;
  const color = value > 60 ? '#ff1744' : value > 30 ? '#ffd700' : '#00ff88';

  return (
    <svg viewBox="0 0 180 110" className="w-full max-w-xs mx-auto">
      {/* Track */}
      <path
        d="M 20 100 A 70 70 0 0 1 160 100"
        fill="none"
        stroke="#1a2030"
        strokeWidth="12"
        strokeLinecap="round"
      />
      {/* Value arc */}
      <path
        d="M 20 100 A 70 70 0 0 1 160 100"
        fill="none"
        stroke={color}
        strokeWidth="12"
        strokeLinecap="round"
        strokeDasharray={`${dash} ${circ}`}
        style={{
          transition: 'stroke-dasharray 0.8s ease, stroke 0.5s',
          filter: `drop-shadow(0 0 8px ${color})`,
        }}
      />
      {/* Center value */}
      <text x="90" y="88" textAnchor="middle" fill={color} fontSize="28" fontFamily="JetBrains Mono" fontWeight="700">
        {value}
      </text>
      <text x="90" y="105" textAnchor="middle" fill="#4a5568" fontSize="9" fontFamily="JetBrains Mono">
        RISK SCORE
      </text>
      {/* Min/Max labels */}
      <text x="16" y="115" fill="#4a5568" fontSize="8" fontFamily="JetBrains Mono">0</text>
      <text x="162" y="115" fill="#4a5568" fontSize="8" fontFamily="JetBrains Mono">100</text>
    </svg>
  );
}

/* ── Live stat counter ── */
function LiveCounter({ label, value, color = '#00f5ff' }) {
  return (
    <div className="flex flex-col items-center px-6 border-r border-white/10 last:border-0">
      <span className="font-mono text-lg font-bold stat-num" style={{ color }}>
        {value.toLocaleString()}
      </span>
      <span className="font-mono text-[10px] text-gray-500 tracking-widest">{label}</span>
    </div>
  );
}

export default function ThreatConsole() {
  const [alerts, setAlerts]     = useState(() => Array.from({ length: 6 }, generateAlert));
  const [risk, setRisk]         = useState(12);
  const [filesScanned, setFS]   = useState(847291);
  const [threatsStopped, setTS] = useState(23);
  const [uptime]                = useState('99.97%');
  const feedRef                 = useRef();
  const cycleRef                = useRef(0);

  // Alert feed
  useEffect(() => {
    const id = setInterval(() => {
      setAlerts((prev) => [generateAlert(), ...prev.slice(0, 19)]);
    }, 2200 + Math.random() * 1000);
    return () => clearInterval(id);
  }, []);

  // Risk gauge cycle: spike then drop
  useEffect(() => {
    const cycle = () => {
      // Ramp up to 87
      let val = 12;
      const up = setInterval(() => {
        val = Math.min(87, val + 5);
        setRisk(val);
        if (val >= 87) {
          clearInterval(up);
          // After 2s drop back
          setTimeout(() => {
            let down = 87;
            const dn = setInterval(() => {
              down = Math.max(12, down - 4);
              setRisk(down);
              if (down <= 12) clearInterval(dn);
            }, 80);
          }, 2000);
        }
      }, 60);
    };
    cycle();
    const id = setInterval(cycle, 9000);
    return () => clearInterval(id);
  }, []);

  // Live counters
  useEffect(() => {
    const id = setInterval(() => {
      setFS((v) => v + Math.floor(Math.random() * 12) + 3);
    }, 200);
    return () => clearInterval(id);
  }, []);

  return (
    <section id="console" className="section py-28 px-6">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="text-center mb-12">
          <motion.p
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
            className="font-mono text-xs tracking-widest text-[#00ff88] mb-3 uppercase"
          >
            Live Dashboard
          </motion.p>
          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.1 }}
            className="font-heading font-bold"
            style={{ fontSize: 'clamp(1.8rem, 4vw, 3rem)', color: '#fff' }}
          >
            The Dashboard That{' '}
            <span style={{ color: '#00ff88' }}>Never Blinks</span>
          </motion.h2>
        </div>

        {/* Terminal window */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.1 }}
          transition={{ duration: 0.7 }}
          className="glass rounded-2xl overflow-hidden"
          style={{ border: '1px solid rgba(0,245,255,0.15)', boxShadow: '0 0 60px rgba(0,245,255,0.06)' }}
        >
          {/* Title bar */}
          <div className="flex items-center gap-2 px-5 py-3 border-b border-white/10" style={{ background: '#080820' }}>
            <div className="w-3 h-3 rounded-full bg-[#ff1744]" />
            <div className="w-3 h-3 rounded-full bg-[#ffd700]" />
            <div className="w-3 h-3 rounded-full bg-[#00ff88]" />
            <span className="font-mono text-xs text-gray-500 ml-3 tracking-wider">
              hybrid-rsentry — threat-console — live
            </span>
            <div className="ml-auto flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[#00ff88] animate-blink" />
              <span className="font-mono text-[10px] text-[#00ff88]">ACTIVE</span>
            </div>
          </div>

          {/* Two-panel body */}
          <div className="flex flex-col md:flex-row min-h-[380px]">
            {/* Left: Alert feed */}
            <div className="flex-1 p-4 overflow-hidden">
              <div className="font-mono text-[10px] text-gray-600 mb-3 tracking-widest uppercase">
                ▸ Alert Feed
              </div>
              <div
                ref={feedRef}
                className="space-y-1 overflow-hidden terminal-body"
                style={{ maxHeight: 300 }}
              >
                <AnimatePresence initial={false}>
                  {alerts.slice(0, 10).map((a) => (
                    <motion.div
                      key={a.id}
                      initial={{ opacity: 0, y: -20 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0 }}
                      transition={{ duration: 0.25 }}
                      className="flex items-start gap-2 py-1 px-2 rounded"
                      style={{ background: a.level.bg, borderLeft: `2px solid ${a.level.color}` }}
                    >
                      <span className="font-mono text-[10px] shrink-0" style={{ color: a.level.color }}>
                        {a.level.label}
                      </span>
                      {a.isAI ? (
                        <span className="font-mono text-[10px] text-gray-400">
                          → Powerful AI identified benign process. Alert resolved.
                        </span>
                      ) : (
                        <>
                          <span className="font-mono text-[10px] text-gray-300 shrink-0">{a.type}</span>
                          <span className="font-mono text-[10px] text-gray-500 truncate">{a.path}</span>
                          <span className="font-mono text-[10px] text-gray-600 shrink-0">pid:{a.pid}</span>
                        </>
                      )}
                    </motion.div>
                  ))}
                </AnimatePresence>
              </div>
            </div>

            {/* Divider */}
            <div className="w-px bg-white/10 hidden md:block" />

            {/* Right: Risk gauge */}
            <div className="w-full md:w-72 p-6 flex flex-col items-center justify-center" style={{ background: '#05051a' }}>
              <div className="font-mono text-[10px] text-gray-600 mb-4 tracking-widest uppercase self-start">
                ▸ Risk Score
              </div>
              <RiskGauge value={risk} />
              <div className="font-mono text-[10px] text-gray-500 mt-3 text-center">
                {risk > 60
                  ? '⚠ HIGH THREAT DETECTED'
                  : risk > 30
                  ? '● MODERATE ACTIVITY'
                  : '✓ System Nominal'}
              </div>
            </div>
          </div>

          {/* Bottom stat bar */}
          <div
            className="flex items-center justify-center py-3 px-5 border-t border-white/10"
            style={{ background: '#040412' }}
          >
            <LiveCounter label="Files Scanned"   value={filesScanned}   color="#00f5ff" />
            <LiveCounter label="Threats Stopped" value={threatsStopped} color="#ff1744" />
            <div className="flex flex-col items-center px-6">
              <span className="font-mono text-lg font-bold" style={{ color: '#00ff88' }}>{uptime}</span>
              <span className="font-mono text-[10px] text-gray-500 tracking-widest">Uptime</span>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
