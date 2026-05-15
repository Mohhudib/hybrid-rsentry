import { useRef, useMemo, useState } from 'react';
import { useFrame } from '@react-three/fiber';
import { Text, Html } from '@react-three/drei';
import * as THREE from 'three';

const TECH_INFO = {
  'Python':      { color: '#3776ab', desc: 'Core agent and backend language. Drives the detection pipeline, signal processing, and ML models.' },
  'FastAPI':     { color: '#009688', desc: 'High-performance async API layer connecting the Kali agent to the React dashboard via WebSockets.' },
  'React':       { color: '#61dafb', desc: 'Real-time dashboard UI. Renders live alerts, risk gauges, and the filesystem graph.' },
  'PostgreSQL':  { color: '#336791', desc: 'Persistent storage for process lineage records, alert history, and system events.' },
  'Redis':       { color: '#dc382d', desc: 'Pub/Sub broker and cache. Streams real-time alert events to connected WebSocket clients.' },
  'Celery':      { color: '#37b34a', desc: 'Distributed task queue for async analysis jobs and AI inference workloads.' },
  'Docker':      { color: '#2496ed', desc: 'Containerizes each service (agent, backend, workers) for reproducible deployments.' },
  'NetworkX':    { color: '#00f5ff', desc: 'Builds and queries the filesystem graph. Computes traversal patterns for canary placement.' },
  'NumPy':       { color: '#013243', desc: 'Core numerical engine for entropy computation, matrix operations, and signal analysis.' },
  'psutil':      { color: '#00ff88', desc: 'Low-level process introspection. Reads /proc, monitors I/O rates, and captures forensic snapshots.' },
  'SciPy':       { color: '#8b5cf6', desc: 'Statistical analysis of entropy distributions and threshold calibration.' },
  'AI LLM':     { color: '#b537f2', desc: 'Powerful Large Language Model analyst. Auto-classifies suspicious processes and resolves ambiguous alerts autonomously.' },
};

const INNER  = ['Python', 'FastAPI', 'React'];
const MIDDLE = ['PostgreSQL', 'Redis', 'Celery', 'Docker'];
const OUTER  = ['NetworkX', 'NumPy', 'psutil', 'SciPy', 'AI LLM'];

function Planet({ name, orbitRadius, angle, speed, size = 0.12 }) {
  const ref    = useRef();
  const aRef   = useRef(angle);
  const [hovered, setHovered] = useState(false);
  const [clicked, setClicked] = useState(false);
  const info   = TECH_INFO[name];
  const color  = new THREE.Color(info.color);

  useFrame((_, delta) => {
    aRef.current += speed * delta;
    if (ref.current) {
      ref.current.position.x = Math.cos(aRef.current) * orbitRadius;
      ref.current.position.z = Math.sin(aRef.current) * orbitRadius;
      ref.current.position.y = Math.sin(aRef.current * 0.5) * 0.2;
      if (hovered) {
        ref.current.scale.setScalar(1 + 0.1 * Math.sin(Date.now() * 0.005));
      }
    }
  });

  return (
    <group ref={ref}>
      <mesh
        onPointerEnter={() => setHovered(true)}
        onPointerLeave={() => setHovered(false)}
        onClick={() => setClicked((v) => !v)}
      >
        <sphereGeometry args={[size, 8, 8]} />
        <meshBasicMaterial
          color={info.color}
          toneMapped={false}
        />
      </mesh>
      <Text
        position={[0, size + 0.08, 0]}
        fontSize={0.07}
        color="white"
        anchorX="center"
        anchorY="bottom"
      >
        {name}
      </Text>
      {clicked && (
        <Html center style={{ pointerEvents: 'none', width: 180 }}>
          <div style={{
            background: 'rgba(0,0,5,0.9)',
            border: `1px solid ${info.color}`,
            borderRadius: 8,
            padding: '10px 14px',
            color: 'white',
            fontSize: 11,
            fontFamily: 'JetBrains Mono, monospace',
            boxShadow: `0 0 20px ${info.color}40`,
            lineHeight: 1.5,
          }}>
            <div style={{ color: info.color, fontWeight: 700, marginBottom: 4 }}>{name}</div>
            {info.desc}
          </div>
        </Html>
      )}
    </group>
  );
}

export default function SolarSystem() {
  const coreRef = useRef();

  useFrame(({ clock }) => {
    if (coreRef.current) {
      const t = clock.getElapsedTime();
      coreRef.current.scale.setScalar(1 + 0.05 * Math.sin(t * 1.5));
    }
  });

  // Orbit ring geometry
  const ringGeo = (r) => {
    const pts = [];
    for (let i = 0; i <= 128; i++) {
      const a = (i / 128) * Math.PI * 2;
      pts.push(new THREE.Vector3(Math.cos(a) * r, 0, Math.sin(a) * r));
    }
    return new THREE.BufferGeometry().setFromPoints(pts);
  };
  const innerRing  = useMemo(() => ringGeo(1.4), []);
  const middleRing = useMemo(() => ringGeo(2.4), []);
  const outerRing  = useMemo(() => ringGeo(3.6), []);

  return (
    <group>
      {/* Core */}
      <mesh ref={coreRef}>
        <sphereGeometry args={[0.25, 16, 16]} />
        <meshBasicMaterial color="#00f5ff" toneMapped={false} />
      </mesh>
      <Text position={[0, 0.42, 0]} fontSize={0.1} color="#00f5ff" anchorX="center" anchorY="bottom">
        R-SENTRY
      </Text>

      <pointLight position={[0, 0, 0]} color="#00f5ff" intensity={3} distance={6} />

      {/* Orbit rings */}
      <line geometry={innerRing}>
        <lineBasicMaterial color="#00f5ff" transparent opacity={0.15} toneMapped={false} />
      </line>
      <line geometry={middleRing}>
        <lineBasicMaterial color="#00f5ff" transparent opacity={0.1} toneMapped={false} />
      </line>
      <line geometry={outerRing}>
        <lineBasicMaterial color="#b537f2" transparent opacity={0.1} toneMapped={false} />
      </line>

      {/* Inner planets */}
      {INNER.map((name, i) => (
        <Planet
          key={name}
          name={name}
          orbitRadius={1.4}
          angle={(i / INNER.length) * Math.PI * 2}
          speed={0.5}
          size={0.1}
        />
      ))}

      {/* Middle planets */}
      {MIDDLE.map((name, i) => (
        <Planet
          key={name}
          name={name}
          orbitRadius={2.4}
          angle={(i / MIDDLE.length) * Math.PI * 2}
          speed={0.28}
          size={0.13}
        />
      ))}

      {/* Outer planets */}
      {OUTER.map((name, i) => (
        <Planet
          key={name}
          name={name}
          orbitRadius={3.6}
          angle={(i / OUTER.length) * Math.PI * 2}
          speed={0.14}
          size={name === 'AI LLM' ? 0.22 : 0.11}
        />
      ))}
    </group>
  );
}
