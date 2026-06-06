import { useRef, useMemo } from 'react';
import { useFrame } from '@react-three/fiber';
import { Html } from '@react-three/drei';
import * as THREE from 'three';
import { useState } from 'react';

// Node definitions: [id, label, x, y, z, color, desc]
const NODES = [
  { id: 0, label: 'KALI AGENT',      x: -4,   y: 1.5,  z: 0,   color: '#ff1744', desc: 'Endpoint agent running on Kali Linux. Monitors inotify events and dispatches alerts to the backend.' },
  { id: 1, label: 'FASTAPI',         x: -1.2, y: 1.5,  z: 0,   color: '#009688', desc: 'Async REST + WebSocket API. Routes alerts, serves the dashboard, and coordinates worker tasks.' },
  { id: 2, label: 'CELERY WORKERS',  x:  1.6, y: 1.5,  z: 0,   color: '#37b34a', desc: 'Distributed task workers that run entropy analysis, lineage scoring, and AI inference asynchronously.' },
  { id: 3, label: 'AI ANALYST',      x:  4,   y: 1.5,  z: 0,   color: '#b537f2', desc: 'Powerful LLM analyst. Reads process forensics and classifies threats with natural language reasoning.' },
  { id: 4, label: 'WATCHDOG',        x: -4,   y: -0.5, z: 0,   color: '#ff5722', desc: 'inotify-based filesystem watcher. Detects file writes, renames, and deletions in real time.' },
  { id: 5, label: 'POSTGRESQL',      x: -1.2, y: -0.5, z: 0,   color: '#336791', desc: 'Persistent relational store. Holds process lineage trees, canary positions, and historical alerts.' },
  { id: 6, label: 'REDIS PUB/SUB',   x:  1.6, y: -0.5, z: 0,   color: '#dc382d', desc: 'Real-time message bus. Streams events from workers to all connected dashboard WebSocket clients.' },
  { id: 7, label: 'CONTAINMENT',     x: -4,   y: -2.5, z: 0,   color: '#ff1744', desc: 'SIGSTOP → /proc capture → iptables block → SIGKILL. Completes in under 200ms.' },
  { id: 8, label: 'REACT DASHBOARD', x:  1.6, y: -2.5, z: 0,   color: '#61dafb', desc: 'Live browser UI. Displays the filesystem graph, alert feed, risk gauge, and containment events.' },
];

// Directed edges [from, to]
const EDGES = [
  [0, 1], [1, 2], [2, 3],
  [0, 4], [1, 5], [2, 6],
  [4, 7], [6, 8],
];

function buildPacketSpline(fromNode, toNode) {
  const start = new THREE.Vector3(fromNode.x, fromNode.y, fromNode.z);
  const end   = new THREE.Vector3(toNode.x,   toNode.y,   toNode.z);
  const mid   = start.clone().lerp(end, 0.5).add(new THREE.Vector3(0, 0.4, 0.3));
  return new THREE.CatmullRomCurve3([start, mid, end]);
}

function DataPacket({ spline, speed, offset, color }) {
  const ref  = useRef();
  const tRef = useRef(offset);

  useFrame((_, delta) => {
    tRef.current = (tRef.current + delta * speed) % 1;
    if (ref.current) {
      const pt = spline.getPoint(tRef.current);
      ref.current.position.copy(pt);
    }
  });

  return (
    <mesh ref={ref}>
      <sphereGeometry args={[0.045, 8, 8]} />
      <meshStandardMaterial color={color} emissive={color} emissiveIntensity={3} toneMapped={false} />
    </mesh>
  );
}

function NodeBox({ node, isAI }) {
  const ref       = useRef();
  const [hov, setHov] = useState(false);
  useFrame(({ clock }) => {
    if (!ref.current) return;
    if (isAI) {
      const s = 1 + 0.06 * Math.sin(clock.getElapsedTime() * 2);
      ref.current.scale.setScalar(s);
    }
  });

  const size = isAI ? 0.55 : 0.38;

  return (
    <group position={[node.x, node.y, node.z]}>
      <mesh
        ref={ref}
        onPointerEnter={() => setHov(true)}
        onPointerLeave={() => setHov(false)}
      >
        <boxGeometry args={[size * 1.6, size, size * 0.5]} />
        <meshStandardMaterial
          color={node.color}
          emissive={node.color}
          emissiveIntensity={hov ? 2.5 : 1}
          transparent
          opacity={0.25}
          toneMapped={false}
        />
      </mesh>
      {/* Edge glow lines */}
      <lineSegments>
        <edgesGeometry args={[new THREE.BoxGeometry(size * 1.6, size, size * 0.5)]} />
        <lineBasicMaterial color={node.color} toneMapped={false} />
      </lineSegments>

      {/* Label */}
      <Html center distanceFactor={6} style={{ pointerEvents: 'none' }}>
        <div style={{
          color: node.color,
          fontFamily: 'JetBrains Mono, monospace',
          fontSize: isAI ? 10 : 8,
          fontWeight: 700,
          letterSpacing: 1,
          textShadow: `0 0 10px ${node.color}`,
          whiteSpace: 'nowrap',
          textAlign: 'center',
        }}>
          {node.label}
        </div>
      </Html>

      {/* Hover tooltip */}
      {hov && (
        <Html center position={[0, (size / 2) + 0.3, 0]} style={{ pointerEvents: 'none', width: 200 }}>
          <div style={{
            background: 'rgba(0,0,5,0.92)',
            border: `1px solid ${node.color}`,
            borderRadius: 6,
            padding: '8px 12px',
            color: 'white',
            fontSize: 10,
            fontFamily: 'JetBrains Mono, monospace',
            lineHeight: 1.5,
            boxShadow: `0 0 20px ${node.color}50`,
          }}>
            <div style={{ color: node.color, fontWeight: 700, marginBottom: 4 }}>{node.label}</div>
            {node.desc}
          </div>
        </Html>
      )}
      <pointLight color={node.color} intensity={0.5} distance={1.5} />
    </group>
  );
}

export default function ArchGraph() {
  const nodeMap = useMemo(() => {
    const m = {};
    NODES.forEach((n) => (m[n.id] = n));
    return m;
  }, []);

  const splines = useMemo(() => EDGES.map(([a, b]) => buildPacketSpline(nodeMap[a], nodeMap[b])), [nodeMap]);

  // Edge line geometries
  const edgeGeos = useMemo(() => EDGES.map(([a, b]) => {
    const pts = [
      new THREE.Vector3(nodeMap[a].x, nodeMap[a].y, nodeMap[a].z),
      new THREE.Vector3(nodeMap[b].x, nodeMap[b].y, nodeMap[b].z),
    ];
    return new THREE.BufferGeometry().setFromPoints(pts);
  }), [nodeMap]);

  return (
    <group position={[0, 0.5, 0]} scale={0.72}>
      {/* Connection lines */}
      {edgeGeos.map((geo, i) => (
        <line key={i} geometry={geo}>
          <lineBasicMaterial color="#00f5ff" transparent opacity={0.3} toneMapped={false} />
        </line>
      ))}

      {/* Data packets — 2 per edge at offset intervals */}
      {splines.map((spline, i) => {
        const fromNode = nodeMap[EDGES[i][0]];
        return (
          <group key={`packet-group-${i}`}>
            <DataPacket spline={spline} speed={0.22 + i * 0.03} offset={0}    color={fromNode.color} />
            <DataPacket spline={spline} speed={0.22 + i * 0.03} offset={0.5}  color={fromNode.color} />
          </group>
        );
      })}

      {/* Nodes */}
      {NODES.map((node) => (
        <NodeBox key={node.id} node={node} isAI={node.id === 3} />
      ))}
    </group>
  );
}
