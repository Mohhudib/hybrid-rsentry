import { motion } from 'framer-motion';

// Pure CSS — no WebGL canvas here, saves a full context
export default function FinalCTA() {
  return (
    <section id="cta" className="relative w-full min-h-screen flex flex-col items-center justify-center overflow-hidden py-24 px-6">
      {/* CSS animated background — replaces the 3D sphere */}
      <div className="absolute inset-0 pointer-events-none">
        {/* Radial pulsing glow */}
        <motion.div
          className="absolute inset-0"
          animate={{ opacity: [0.4, 0.7, 0.4] }}
          transition={{ duration: 4, repeat: Infinity, ease: 'easeInOut' }}
          style={{
            background: 'radial-gradient(ellipse 55% 55% at 50% 50%, rgba(0,245,255,0.07) 0%, transparent 70%)',
          }}
        />
        {/* Rotating ring 1 */}
        <motion.div
          className="absolute left-1/2 top-1/2 rounded-full"
          style={{
            width: 500, height: 500,
            marginLeft: -250, marginTop: -250,
            border: '1px solid rgba(0,245,255,0.12)',
          }}
          animate={{ rotate: 360 }}
          transition={{ duration: 30, repeat: Infinity, ease: 'linear' }}
        />
        {/* Rotating ring 2 */}
        <motion.div
          className="absolute left-1/2 top-1/2 rounded-full"
          style={{
            width: 700, height: 700,
            marginLeft: -350, marginTop: -350,
            border: '1px solid rgba(181,55,242,0.08)',
          }}
          animate={{ rotate: -360 }}
          transition={{ duration: 45, repeat: Infinity, ease: 'linear' }}
        />
        {/* Floating dots */}
        {Array.from({ length: 24 }).map((_, i) => {
          const angle = (i / 24) * Math.PI * 2;
          const r = 220 + (i % 3) * 60;
          const cx = 50 + Math.cos(angle) * (r / 10);
          const cy = 50 + Math.sin(angle) * (r / 10);
          return (
            <motion.div
              key={i}
              className="absolute w-1 h-1 rounded-full"
              style={{
                left: `${cx}%`, top: `${cy}%`,
                background: i % 3 === 0 ? '#ff1744' : '#00f5ff',
                boxShadow: `0 0 6px ${i % 3 === 0 ? '#ff1744' : '#00f5ff'}`,
              }}
              animate={{ opacity: [0.2, 1, 0.2], scale: [0.8, 1.4, 0.8] }}
              transition={{ duration: 2 + (i % 4) * 0.5, delay: i * 0.1, repeat: Infinity }}
            />
          );
        })}
      </div>

      {/* Content */}
      <div className="relative z-10 text-center max-w-3xl">
        <motion.p
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.7 }}
          className="font-mono text-base md:text-lg text-gray-400 mb-3 leading-relaxed"
        >
          Ransomware encrypted files while you read this page.
        </motion.p>
        <motion.p
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.7, delay: 0.3 }}
          className="font-heading font-bold mb-12 glow-cyan"
          style={{ fontSize: 'clamp(1.6rem, 4vw, 3rem)', color: '#00f5ff' }}
        >
          Hybrid R-Sentry would have stopped it in 675μs.
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.6 }}
          className="flex gap-5 justify-center flex-wrap"
        >
          <a
            href="https://github.com/Mohhudib/hybrid-rsentry"
            target="_blank"
            rel="noopener noreferrer"
            id="btn-github-cta"
            className="flex items-center gap-2 px-8 py-3.5 rounded-xl font-heading font-semibold text-sm tracking-wider transition-all duration-200"
            style={{ background: '#00f5ff', color: '#000010', boxShadow: '0 0 28px #00f5ff50' }}
            onMouseEnter={(e) => e.currentTarget.style.boxShadow = '0 0 50px #00f5ff80'}
            onMouseLeave={(e) => e.currentTarget.style.boxShadow = '0 0 28px #00f5ff50'}
          >
            ⭐ Star on GitHub
          </a>
        </motion.div>
      </div>
    </section>
  );
}
