import { Suspense } from 'react';
import { Canvas } from '@react-three/fiber';
import { OrbitControls } from '@react-three/drei';
import { motion } from 'framer-motion';
import ArchGraph from '../three/ArchGraph';

export default function Architecture() {
  const isMobile = window.innerWidth < 768;
  return (
    <section id="architecture" className="section py-28 px-6">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="text-center mb-6">
          <motion.p
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
            className="font-mono text-xs tracking-widest text-[#00f5ff] mb-3 uppercase"
          >
            System Architecture
          </motion.p>
          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.1 }}
            className="font-heading font-bold mb-4"
            style={{ fontSize: 'clamp(1.8rem, 4vw, 3rem)', color: '#fff' }}
          >
            How the{' '}
            <span style={{ color: '#00f5ff' }}>System Talks</span>
          </motion.h2>
          <motion.p
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
            transition={{ delay: 0.2 }}
            className="font-mono text-xs text-gray-500"
          >
            Hover any node for its role. Glowing packets show live data flow.
          </motion.p>
        </div>

        {/* 3D Canvas */}
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true, amount: 0.1 }}
          transition={{ duration: 1 }}
          className="w-full rounded-2xl overflow-hidden glass"
          style={{ height: isMobile ? 380 : 520, border: '1px solid rgba(0,245,255,0.12)' }}
        >
          <Canvas
            camera={{ position: [0, 0, 9], fov: 60 }}
            gl={{ antialias: false, alpha: true, powerPreference: 'high-performance' }}
            dpr={1}
          >
            <ambientLight intensity={0.1} />
            <Suspense fallback={null}>
              <ArchGraph />
            </Suspense>
            <OrbitControls
              enableZoom={false}
              enablePan={false}
              rotateSpeed={0.3}
              minPolarAngle={Math.PI / 4}
              maxPolarAngle={Math.PI / 1.8}
            />
          </Canvas>
        </motion.div>
      </div>
    </section>
  );
}
