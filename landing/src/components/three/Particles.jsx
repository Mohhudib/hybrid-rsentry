import { useRef, useMemo, useEffect } from 'react';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';

// Pre-computed reusable axis vectors — allocated once, never inside useFrame
const AXIS_Y = new THREE.Vector3(0, 1, 0);
const AXIS_X = new THREE.Vector3(1, 0, 0);

export default function Particles({ count = 2000, radius = 1.8, isMobile = false }) {
  const actualCount = isMobile ? 200 : count;
  const meshRef = useRef();
  const dummy   = useMemo(() => new THREE.Object3D(), []);

  // Random positions + velocities, built once
  const { positions, velocities } = useMemo(() => {
    const pos = [];
    const vel = [];
    for (let i = 0; i < actualCount; i++) {
      const theta = Math.random() * Math.PI * 2;
      const phi   = Math.acos(2 * Math.random() - 1);
      const r     = radius + (Math.random() - 0.5) * 0.6;
      pos.push(new THREE.Vector3(
        r * Math.sin(phi) * Math.cos(theta),
        r * Math.sin(phi) * Math.sin(theta),
        r * Math.cos(phi),
      ));
      vel.push({
        speedY: (Math.random() - 0.5) * 0.003,
        speedX: (Math.random() - 0.5) * 0.0015,
        phase:  Math.random() * Math.PI * 2,
        size:   0.006 + Math.random() * 0.006,
      });
    }
    return { positions: pos, velocities: vel };
  }, [actualCount, radius]);

  // Reusable scratch vector for normalisation — avoid clone() per frame
  const scratch = useMemo(() => new THREE.Vector3(), []);

  // Set initial positions once
  useEffect(() => {
    if (!meshRef.current) return;
    for (let i = 0; i < actualCount; i++) {
      dummy.position.copy(positions[i]);
      dummy.scale.setScalar(velocities[i].size);
      dummy.updateMatrix();
      meshRef.current.setMatrixAt(i, dummy.matrix);
    }
    meshRef.current.instanceMatrix.needsUpdate = true;
  }, [actualCount, dummy, positions, velocities]);

  useFrame(({ clock }) => {
    if (!meshRef.current) return;
    const t = clock.getElapsedTime();
    for (let i = 0; i < actualCount; i++) {
      const { speedY, speedX, phase, size } = velocities[i];

      // Mutate in-place using pre-allocated axis vectors — zero heap allocations
      positions[i].applyAxisAngle(AXIS_Y, speedY);
      positions[i].applyAxisAngle(AXIS_X, speedX * 0.3);

      // Radial breathe: compute target radius, normalize into scratch, scale
      const r = radius + 0.25 * Math.sin(t * 0.4 + phase);
      scratch.copy(positions[i]).normalize().multiplyScalar(r);

      dummy.position.copy(scratch);
      dummy.scale.setScalar(size + 0.003 * Math.abs(Math.sin(t * 0.6 + phase)));
      dummy.updateMatrix();
      meshRef.current.setMatrixAt(i, dummy.matrix);
    }
    meshRef.current.instanceMatrix.needsUpdate = true;
  });

  return (
    <instancedMesh ref={meshRef} args={[null, null, actualCount]}>
      <sphereGeometry args={[1, 4, 4]} />
      <meshStandardMaterial
        color="#00f5ff"
        emissive="#00f5ff"
        emissiveIntensity={2}
        transparent
        opacity={0.6}
        toneMapped={false}
      />
    </instancedMesh>
  );
}
