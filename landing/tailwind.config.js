/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#000005',
        cyan: {
          DEFAULT: '#00f5ff',
          dark: '#00c4cc',
        },
        threat: '#ff1744',
        ai: '#b537f2',
        safe: '#00ff88',
        gold: '#ffd700',
      },
      fontFamily: {
        heading: ['"Space Grotesk"', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
      animation: {
        blink: 'blink 1.2s step-end infinite',
        'grid-scroll': 'gridScroll 20s linear infinite',
        glitch: 'glitch 0.4s steps(1) forwards',
        shake: 'shake 0.5s ease-in-out infinite',
        pulse: 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'pulse-violet': 'pulseViolet 2s ease-in-out infinite',
        'orbit-inner': 'orbit 8s linear infinite',
        'orbit-mid': 'orbit 16s linear infinite',
        'orbit-outer': 'orbit 28s linear infinite',
      },
      keyframes: {
        blink: {
          '0%, 100%': { opacity: 1 },
          '50%': { opacity: 0 },
        },
        gridScroll: {
          '0%': { backgroundPosition: '0 0' },
          '100%': { backgroundPosition: '60px 60px' },
        },
        glitch: {
          '0%': { clipPath: 'inset(0 0 95% 0)', transform: 'skewX(-5deg)' },
          '20%': { clipPath: 'inset(30% 0 50% 0)', transform: 'skewX(3deg)' },
          '40%': { clipPath: 'inset(60% 0 20% 0)', transform: 'skewX(-2deg)' },
          '60%': { clipPath: 'inset(10% 0 70% 0)', transform: 'skewX(4deg)' },
          '80%': { clipPath: 'inset(80% 0 5% 0)', transform: 'skewX(-3deg)' },
          '100%': { clipPath: 'inset(0 0 0 0)', transform: 'skewX(0deg)' },
        },
        shake: {
          '0%, 100%': { transform: 'translateX(0)' },
          '25%': { transform: 'translateX(-2px)' },
          '75%': { transform: 'translateX(2px)' },
        },
        pulseViolet: {
          '0%, 100%': { boxShadow: '0 0 20px #b537f2' },
          '50%': { boxShadow: '0 0 60px #b537f2, 0 0 120px #b537f250' },
        },
        orbit: {
          from: { transform: 'rotate(0deg)' },
          to: { transform: 'rotate(360deg)' },
        },
      },
      backdropBlur: {
        xs: '2px',
      },
    },
  },
  plugins: [],
};
