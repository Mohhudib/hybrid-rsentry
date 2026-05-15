import { Suspense } from 'react';
import { Canvas } from '@react-three/fiber';
import { OrbitControls } from '@react-three/drei';
import { motion } from 'framer-motion';
import SolarSystem from '../three/SolarSystem';

export default function TechUniverse() {
  const isMobile = window.innerWidth < 768;
  return (
    <section id="tech" className="section py-28 px-6">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="text-center mb-6">
          <motion.p
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
            className="font-mono text-xs tracking-widest text-[#b537f2] mb-3 uppercase"
          >
            Tech Stack
          </motion.p>
          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.1 }}
            className="font-heading font-bold mb-4"
            style={{ fontSize: 'clamp(1.8rem, 4vw, 3rem)', color: '#fff' }}
          >
            Built on{' '}
            <span style={{ color: '#b537f2' }}>Battle-Tested Technology</span>
          </motion.h2>
          <motion.p
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
            transition={{ delay: 0.2 }}
            className="font-mono text-xs text-gray-500"
          >
            Click any planet to learn its role in the system.
          </motion.p>
        </div>

        {/* 3D Canvas */}
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true, amount: 0.1 }}
          transition={{ duration: 1 }}
          className="w-full rounded-2xl overflow-hidden glass"
          style={{ height: isMobile ? 400 : 600, border: '1px solid rgba(181,55,242,0.15)' }}
        >
          <Canvas
            camera={{ position: [0, 2, 7], fov: 65 }}
            gl={{ antialias: false, alpha: true, powerPreference: 'high-performance' }}
            dpr={1}
          >
            <ambientLight intensity={0.05} />
            <Suspense fallback={null}>
              <SolarSystem />
            </Suspense>
            <OrbitControls
              enableZoom={false}
              enablePan={false}
              minPolarAngle={Math.PI / 6}
              maxPolarAngle={Math.PI / 2.2}
              rotateSpeed={0.4}
            />
          </Canvas>
        </motion.div>
      </div>
    </section>
  );
}
