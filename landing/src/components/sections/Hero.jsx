import { Suspense, useEffect, useState } from 'react';
import { Canvas } from '@react-three/fiber';
import { motion } from 'framer-motion';
import NodeSphere from '../three/NodeSphere';
import Particles from '../three/Particles';

const STATS = [
  { label: 'avg detection', value: 675,  suffix: 'μs', prefix: '' },
  { label: 'false positives', value: 0,  suffix: '',   prefix: '' },
  { label: 'detection layers', value: 4, suffix: '',   prefix: '' },
  { label: 'containment',  value: 100,   suffix: '%',  prefix: '' },
];

function useCounter(target, duration = 2000, start = false) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    if (!start) return;
    let startTime = null;
    const step = (timestamp) => {
      if (!startTime) startTime = timestamp;
      const progress = Math.min((timestamp - startTime) / duration, 1);
      setVal(Math.floor(progress * target));
      if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }, [target, duration, start]);
  return val;
}

function StatCounter({ stat, start }) {
  const val = useCounter(stat.value, 2000, start);
  return (
    <div className="flex flex-col items-center">
      <span className="font-mono text-xl font-bold stat-num" style={{ color: '#00f5ff' }}>
        {stat.prefix}{val}{stat.suffix}
      </span>
      <span className="font-mono text-[10px] text-gray-500 tracking-widest mt-0.5 uppercase">
        {stat.label}
      </span>
    </div>
  );
}

export default function Hero() {
  const [statsStart, setStatsStart] = useState(false);
  const isMobile = window.innerWidth < 768;

  useEffect(() => {
    const t = setTimeout(() => setStatsStart(true), 2200);
    return () => clearTimeout(t);
  }, []);

  return (
    <section id="hero" className="relative w-full h-screen overflow-hidden">
      {/* 3D Canvas background */}
      <div className="absolute inset-0">
        <Canvas
          camera={{ position: [0, 0, 4], fov: 55 }}
          gl={{ antialias: false, alpha: true, powerPreference: 'high-performance' }}
          dpr={1}
        >
          <ambientLight intensity={0.1} />
          <Suspense fallback={null}>
            <NodeSphere radius={1.1} isMobile={isMobile} />
            <Particles count={isMobile ? 150 : 500} radius={1.8} isMobile={isMobile} />
          </Suspense>
          <fog attach="fog" args={['#000020', 4, 12]} />
        </Canvas>
      </div>

      {/* Radial glow beneath sphere */}
      <div
        className="absolute inset-x-0 pointer-events-none"
        style={{
          top: '35%',
          height: '40%',
          background: 'radial-gradient(ellipse 50% 50% at 50% 60%, rgba(0,245,255,0.07) 0%, transparent 70%)',
        }}
      />

      {/* Foreground content */}
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center px-6 z-10">
        {/* Badge */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="flex items-center gap-2 mb-8 px-4 py-1.5 rounded-full glass"
          style={{ border: '1px solid rgba(0,255,136,0.3)' }}
        >
          <span className="w-2 h-2 rounded-full bg-[#00ff88] animate-blink" />
        </motion.div>

        {/* H1 — Glitch */}
        <motion.h1
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.3, delay: 0.2 }}
          className="font-heading font-bold leading-none mb-4 select-none"
          style={{
            fontSize: 'clamp(3rem, 10vw, 8rem)',
            color: '#fff',
            textShadow: '0 0 30px #00f5ff, 0 0 80px #00f5ff40',
          }}
        >
          <span
            className="glitch-wrapper"
            data-text="HYBRID R-SENTRY"
          >
            HYBRID R-SENTRY
          </span>
        </motion.h1>

        {/* H2 */}
        <motion.h2
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.8 }}
          className="font-heading italic mb-6 glow-violet"
          style={{
            fontSize: 'clamp(1.2rem, 3vw, 2rem)',
            color: '#b537f2',
          }}
        >
          Ransomware dies here.
        </motion.h2>

        {/* Body */}
        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.8, delay: 1.2 }}
          className="font-mono text-sm md:text-base text-gray-400 max-w-xl mb-10 leading-relaxed"
        >
          The only detection system that sees ransomware before it touches your files —
          using entropy physics, process DNA, and self-repositioning AI canaries.
        </motion.p>

        {/* CTA Buttons */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 1.5 }}
          className="flex gap-4 mb-12 flex-wrap justify-center"
        >
          <a
            href="#console"
            id="btn-watch-demo"
            className="flex items-center gap-2 px-8 py-3 rounded-lg font-heading font-semibold text-sm tracking-wider transition-all duration-200 active:scale-95"
            style={{
              background: '#00f5ff',
              color: '#000010',
              boxShadow: '0 0 24px #00f5ff60, 0 4px 16px rgba(0,0,0,0.4)',
            }}
            onMouseEnter={(e) => e.currentTarget.style.boxShadow = '0 0 40px #00f5ff90, 0 4px 24px rgba(0,0,0,0.5)'}
            onMouseLeave={(e) => e.currentTarget.style.boxShadow = '0 0 24px #00f5ff60, 0 4px 16px rgba(0,0,0,0.4)'}
          >
            ▶ Watch Demo
          </a>
          <a
            href="https://github.com/Mohhudib/hybrid-rsentry"
            target="_blank"
            rel="noopener noreferrer"
            id="btn-github"
            className="flex items-center gap-2 px-8 py-3 rounded-lg font-heading font-semibold text-sm tracking-wider border transition-all duration-200"
            style={{
              borderColor: '#00f5ff',
              color: '#00f5ff',
              background: 'transparent',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = 'rgba(0,245,255,0.08)';
              e.currentTarget.style.boxShadow = '0 0 20px #00f5ff30';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = 'transparent';
              e.currentTarget.style.boxShadow = 'none';
            }}
          >
            {'<>'} GitHub
          </a>
        </motion.div>

        {/* Live Stats */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.6, delay: 2 }}
          className="flex gap-8 md:gap-12 flex-wrap justify-center"
        >
          {STATS.map((s, i) => (
            <StatCounter key={i} stat={s} start={statsStart} />
          ))}
        </motion.div>
      </div>

      {/* Scroll indicator */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 3, duration: 1 }}
        className="absolute bottom-8 left-1/2 -translate-x-1/2 flex flex-col items-center gap-2 z-10"
      >
        <span className="font-mono text-[10px] tracking-widest text-gray-600">SCROLL</span>
        <motion.div
          animate={{ y: [0, 6, 0] }}
          transition={{ duration: 1.5, repeat: Infinity, ease: 'easeInOut' }}
          className="w-px h-8 bg-gradient-to-b from-[#00f5ff] to-transparent"
        />
      </motion.div>
    </section>
  );
}
