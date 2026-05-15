import { lazy, Suspense } from 'react';
import Navbar       from './components/layout/Navbar';
import Footer       from './components/layout/Footer';
import AnimatedGrid from './components/common/AnimatedGrid';
import ScanLines    from './components/common/ScanLines';
import Hero         from './components/sections/Hero';

// Lazy-load below-fold sections
const ThreatTimeline = lazy(() => import('./components/sections/ThreatTimeline'));
const Pillars        = lazy(() => import('./components/sections/Pillars'));
const ThreatConsole  = lazy(() => import('./components/sections/ThreatConsole'));
const TechUniverse   = lazy(() => import('./components/sections/TechUniverse'));
const Architecture   = lazy(() => import('./components/sections/Architecture'));
const Team           = lazy(() => import('./components/sections/Team'));
const FinalCTA       = lazy(() => import('./components/sections/FinalCTA'));

function SectionFallback() {
  return (
    <div className="w-full h-64 flex items-center justify-center">
      <div className="font-mono text-xs text-gray-600 animate-pulse">Loading...</div>
    </div>
  );
}

export default function App() {
  return (
    <div className="relative min-h-screen" style={{ background: '#000005' }}>
      {/* Global overlays */}
      <AnimatedGrid />
      <ScanLines />

      {/* Navigation */}
      <Navbar />

      {/* Hero — eager loaded (above fold) */}
      <Hero />

      {/* Below-fold sections — lazy loaded */}
      <Suspense fallback={<SectionFallback />}>
        <ThreatTimeline />
      </Suspense>

      {/* Separator */}
      <div className="w-full h-px" style={{ background: 'linear-gradient(90deg, transparent, #00f5ff30, transparent)' }} />

      <Suspense fallback={<SectionFallback />}>
        <Pillars />
      </Suspense>

      <div className="w-full h-px" style={{ background: 'linear-gradient(90deg, transparent, #b537f230, transparent)' }} />

      <Suspense fallback={<SectionFallback />}>
        <ThreatConsole />
      </Suspense>

      <div className="w-full h-px" style={{ background: 'linear-gradient(90deg, transparent, #b537f230, transparent)' }} />

      <Suspense fallback={<SectionFallback />}>
        <TechUniverse />
      </Suspense>

      <div className="w-full h-px" style={{ background: 'linear-gradient(90deg, transparent, #00f5ff20, transparent)' }} />

      <Suspense fallback={<SectionFallback />}>
        <Architecture />
      </Suspense>

      <div className="w-full h-px" style={{ background: 'linear-gradient(90deg, transparent, #00ff8820, transparent)' }} />

      <Suspense fallback={<SectionFallback />}>
        <Team />
      </Suspense>

      <Suspense fallback={<SectionFallback />}>
        <FinalCTA />
      </Suspense>

      <Footer />
    </div>
  );
}
