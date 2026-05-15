import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';

const NAV_LINKS = [
  { label: 'Hero',        href: '#hero' },
  { label: 'Timeline',   href: '#timeline' },
  { label: 'Pillars',    href: '#pillars' },
  { label: 'Console',    href: '#console' },
  { label: 'Arch',       href: '#architecture' },
  { label: 'Team',       href: '#team' },
];

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const handler = () => setScrolled(window.scrollY > 40);
    window.addEventListener('scroll', handler);
    return () => window.removeEventListener('scroll', handler);
  }, []);

  return (
    <motion.nav
      initial={{ y: -80, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.6, ease: 'easeOut' }}
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        scrolled
          ? 'bg-[#000005cc] backdrop-blur-xl border-b border-cyan/10'
          : 'bg-transparent'
      }`}
    >
      <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
        {/* Logo */}
        <a href="#hero" className="flex items-center gap-2 group">
          <span
            className="font-heading font-bold text-lg tracking-widest glow-cyan"
            style={{ color: '#00f5ff' }}
          >
            R-SENTRY
          </span>
          <span className="text-[10px] font-mono text-gray-500 tracking-wider mt-0.5">
            HYBRID
          </span>
        </a>

        {/* Nav links */}
        <ul className="hidden md:flex items-center gap-6">
          {NAV_LINKS.map((link) => (
            <li key={link.href}>
              <a
                href={link.href}
                className="font-mono text-xs tracking-widest text-gray-400 hover:text-[#00f5ff] transition-colors duration-200"
              >
                {link.label}
              </a>
            </li>
          ))}
        </ul>

        {/* CTA */}
        <a
          href="#"
          className="hidden md:inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-[#00f5ff] text-[#00f5ff] font-mono text-xs tracking-wider hover:bg-[#00f5ff15] transition-all duration-300"
          style={{ boxShadow: '0 0 12px #00f5ff30' }}
        >
          <span className="w-1.5 h-1.5 rounded-full bg-[#00ff88] animate-blink" />
          Live Demo
        </a>
      </div>
    </motion.nav>
  );
}
