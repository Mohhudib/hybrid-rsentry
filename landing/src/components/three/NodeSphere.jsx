import { useRef, useMemo, useEffect, useState } from 'react';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';

const NODE_COUNT = 120;
const EDGE_PROBABILITY = 0.014;

function buildGraph(count) {
  // Distribute nodes on a sphere using Fibonacci sphere
  const positions = [];
  const goldenAngle = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < count; i++) {
    const y = 1 - (i / (count - 1)) * 2;
    const r = Math.sqrt(1 - y * y);
    const theta = goldenAngle * i;
    positions.push(new THREE.Vector3(r * Math.cos(theta), y, r * Math.sin(theta)));
  }

  // Build edges between nearby nodes
  const edges = [];
  const adjacency = Array.from({ length: count }, () => []);
  for (let i = 0; i < count; i++) {
    for (let j = i + 1; j < count; j++) {
      const d = positions[i].distanceTo(positions[j]);
      if (d < 0.42 && Math.random() < EDGE_PROBABILITY / (d * d + 0.01)) {
        edges.push([i, j]);
        adjacency[i].push(j);
        adjacency[j].push(i);
      }
    }
  }
  return { positions, edges, adjacency };
}

// BFS infection spread
function bfsSpread(start, adjacency, maxDepth) {
  const visited = new Map(); // node -> depth
  const queue = [[start, 0]];
  visited.set(start, 0);
  while (queue.length) {
    const [node, depth] = queue.shift();
    if (depth >= maxDepth) continue;
    for (const neighbor of adjacency[node]) {
      if (!visited.has(neighbor)) {
        visited.set(neighbor, depth + 1);
        queue.push([neighbor, depth + 1]);
      }
    }
  }
  return visited;
}

const CYAN_COLOR   = new THREE.Color('#00f5ff');
const RED_COLOR    = new THREE.Color('#ff1744');
const GREEN_COLOR  = new THREE.Color('#00ff88');
const GRAY_COLOR   = new THREE.Color('#1a3040');

export default function NodeSphere({ radius = 1.1, isMobile = false }) {
  const groupRef     = useRef();
  const meshRef      = useRef();
  const edgeRef      = useRef();
  const colorsRef    = useRef(null);
  const phaseRef     = useRef('idle'); // idle | spreading | containing
  const infectedRef  = useRef(new Set());
  const containedRef = useRef(new Set());
  const timerRef     = useRef(0);

  const { positions, edges, adjacency } = useMemo(() => buildGraph(NODE_COUNT), []);

  // Build instanced mesh positions
  const dummy = useMemo(() => new THREE.Object3D(), []);
  const nodeColors = useMemo(() => {
    const c = new Float32Array(NODE_COUNT * 3);
    CYAN_COLOR.toArray(c, 0);
    for (let i = 0; i < NODE_COUNT; i++) CYAN_COLOR.toArray(c, i * 3);
    return c;
  }, []);
  colorsRef.current = nodeColors;

  // Edge geometry
  const edgeGeometry = useMemo(() => {
    const pts = [];
    for (const [a, b] of edges) {
      pts.push(positions[a].clone().multiplyScalar(radius));
      pts.push(positions[b].clone().multiplyScalar(radius));
    }
    const geo = new THREE.BufferGeometry().setFromPoints(pts);
    return geo;
  }, [edges, positions, radius]);

  // Set initial instance positions
  useEffect(() => {
    if (!meshRef.current) return;
    for (let i = 0; i < NODE_COUNT; i++) {
      dummy.position.copy(positions[i]).multiplyScalar(radius);
      dummy.scale.setScalar(isMobile ? 0.012 : 0.016);
      dummy.updateMatrix();
      meshRef.current.setMatrixAt(i, dummy.matrix);
      meshRef.current.setColorAt(i, CYAN_COLOR);
    }
    meshRef.current.instanceMatrix.needsUpdate = true;
    meshRef.current.instanceColor.needsUpdate = true;
  }, [dummy, positions, radius, isMobile]);

  // Threat animation cycle
  useEffect(() => {
    let timeouts = [];
    const runCycle = () => {
      const origin = Math.floor(Math.random() * NODE_COUNT);
      const spread = bfsSpread(origin, adjacency, 5);
      infectedRef.current = new Set();
      containedRef.current = new Set();
      phaseRef.current = 'spreading';

      // Spread red node-by-node
      const spreadEntries = [...spread.entries()].sort((a, b) => a[1] - b[1]);
      spreadEntries.forEach(([node, depth]) => {
        const t = setTimeout(() => {
          infectedRef.current.add(node);
          if (meshRef.current) {
            meshRef.current.setColorAt(node, RED_COLOR);
            meshRef.current.instanceColor.needsUpdate = true;
          }
        }, depth * 180);
        timeouts.push(t);
      });

      // After spread: start containment
      const containDelay = spreadEntries.length * 180 + 600;
      const t2 = setTimeout(() => {
        phaseRef.current = 'containing';
        const infectedList = [...infectedRef.current];
        infectedList.forEach((node, idx) => {
          const t = setTimeout(() => {
            containedRef.current.add(node);
            infectedRef.current.delete(node);
            if (meshRef.current) {
              meshRef.current.setColorAt(node, GREEN_COLOR);
              meshRef.current.instanceColor.needsUpdate = true;
            }
          }, idx * 80);
          timeouts.push(t);
        });

        // Reset to cyan
        const resetDelay = infectedList.length * 80 + 500;
        const t3 = setTimeout(() => {
          phaseRef.current = 'idle';
          for (let i = 0; i < NODE_COUNT; i++) {
            meshRef.current?.setColorAt(i, CYAN_COLOR);
          }
          if (meshRef.current) meshRef.current.instanceColor.needsUpdate = true;
          infectedRef.current.clear();
          containedRef.current.clear();
        }, resetDelay);
        timeouts.push(t3);
      }, containDelay);
      timeouts.push(t2);
    };

    const interval = setInterval(runCycle, 5000);
    const initialDelay = setTimeout(runCycle, 1500);

    return () => {
      clearInterval(interval);
      clearTimeout(initialDelay);
      timeouts.forEach(clearTimeout);
    };
  }, [adjacency]);

  useFrame((_, delta) => {
    if (groupRef.current) {
      groupRef.current.rotation.y += delta * 0.08;
      groupRef.current.rotation.x += delta * 0.015;
    }
  });

  return (
    <group ref={groupRef}>
      {/* Node dots */}
      <instancedMesh ref={meshRef} args={[null, null, NODE_COUNT]}>
        <sphereGeometry args={[1, 5, 5]} />
        <meshBasicMaterial
          color="#00f5ff"
          toneMapped={false}
        />
      </instancedMesh>

      {/* Edge lines */}
      <lineSegments ref={edgeRef} geometry={edgeGeometry}>
        <lineBasicMaterial
          color="#00f5ff"
          transparent
          opacity={0.18}
          toneMapped={false}
        />
      </lineSegments>

      {/* Ambient glow light */}
      <pointLight position={[0, 0, 0]} color="#00f5ff" intensity={1.5} distance={4} />
    </group>
  );
}
