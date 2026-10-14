import React, { useEffect, useRef } from 'react';
import * as THREE from 'three';

export default function LLMNeuralShield({ height = '300px', isScanning = false, lastProbeResult = null }) {
  const mountRef = useRef(null);

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;

    const width = mount.clientWidth;
    const heightPx = mount.clientHeight || 300;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / heightPx, 0.1, 1000);
    camera.position.set(0, 0, 18);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, heightPx);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    mount.appendChild(renderer.domElement);

    // Neural Group
    const neuralGroup = new THREE.Group();
    scene.add(neuralGroup);

    // Inner Neural Core
    const coreGeo = new THREE.DodecahedronGeometry(3.5, 2);
    const coreMat = new THREE.MeshStandardMaterial({
      color: 0x8b5cf6,
      emissive: 0x6d28d9,
      emissiveIntensity: 0.5,
      wireframe: true,
      transparent: true,
      opacity: 0.8,
    });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    neuralGroup.add(coreMesh);

    // Outer Defense Shield Bubble
    const shieldGeo = new THREE.IcosahedronGeometry(5.2, 3);
    const shieldMat = new THREE.MeshBasicMaterial({
      color: 0x00f0ff,
      wireframe: true,
      transparent: true,
      opacity: 0.35,
    });
    const shieldMesh = new THREE.Mesh(shieldGeo, shieldMat);
    neuralGroup.add(shieldMesh);

    // Neural Nodes (Points on sphere)
    const pointsCount = 60;
    const pointsGeo = new THREE.BufferGeometry();
    const positions = new Float32Array(pointsCount * 3);
    for (let i = 0; i < pointsCount; i++) {
      const u = Math.random();
      const v = Math.random();
      const theta = u * 2.0 * Math.PI;
      const phi = Math.acos(2.0 * v - 1.0);
      const r = 3.5;
      const sinPhi = Math.sin(phi);
      positions[i * 3] = r * sinPhi * Math.cos(theta);
      positions[i * 3 + 1] = r * sinPhi * Math.sin(theta);
      positions[i * 3 + 2] = r * Math.cos(phi);
    }
    pointsGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    const pointsMat = new THREE.PointsMaterial({
      color: 0x38bdf8,
      size: 0.35,
      transparent: true,
      opacity: 0.9,
    });
    const neuralNodes = new THREE.Points(pointsGeo, pointsMat);
    neuralGroup.add(neuralNodes);

    // Light
    const light = new THREE.PointLight(0xa855f7, 2, 30);
    light.position.set(0, 0, 5);
    scene.add(light);

    const cyanLight = new THREE.PointLight(0x00f0ff, 1.5, 30);
    cyanLight.position.set(5, 5, 5);
    scene.add(cyanLight);

    let animationFrameId;
    let clock = new THREE.Timer();

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate);
      const elapsed = clock.getElapsed();

      neuralGroup.rotation.y = elapsed * 0.4;
      neuralGroup.rotation.x = Math.sin(elapsed * 0.3) * 0.2;

      // Pulse shield
      const pulse = 1 + Math.sin(elapsed * 2.5) * 0.04;
      shieldMesh.scale.set(pulse, pulse, pulse);

      if (isScanning) {
        shieldMesh.material.color.setHex(0xf59e0b); // Amber during active probe
        coreMesh.material.emissiveIntensity = 1.0 + Math.sin(elapsed * 10) * 0.6;
      } else if (lastProbeResult && !lastProbeResult.passed) {
        shieldMesh.material.color.setHex(0xff0055); // Red breached
      } else {
        shieldMesh.material.color.setHex(0x00f0ff); // Cyan secure
      }

      renderer.render(scene, camera);
    };

    animate();

    const handleResize = () => {
      if (!mount) return;
      const w = mount.clientWidth;
      const h = mount.clientHeight || 300;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      cancelAnimationFrame(animationFrameId);
      if (mount && renderer.domElement) {
        mount.removeChild(renderer.domElement);
      }
      renderer.dispose();
    };
  }, [isScanning, lastProbeResult]);

  return (
    <div className="relative w-full rounded-xl overflow-hidden cyber-glass border border-purple-500/20 scanline" style={{ height }}>
      <div ref={mountRef} className="w-full h-full" />
      <div className="absolute top-3 left-4 pointer-events-none">
        <div className="flex items-center gap-2">
          <span className="inline-block w-2.5 h-2.5 rounded-full bg-purple-400 animate-pulse" />
          <span className="font-orbitron text-xs font-bold tracking-widest text-purple-400">
            3D LLM NEURAL GUARD SHIELD
          </span>
        </div>
        <p className="text-[11px] text-slate-400 font-mono mt-0.5">
          Real-time Adversarial Probe Deflection Matrix (Garak)
        </p>
      </div>

      <div className="absolute bottom-3 right-4 pointer-events-none text-right font-mono text-[11px] bg-slate-950/80 px-2.5 py-1 rounded border border-purple-900/50">
        <span className="text-slate-400">Shield Status: </span>
        <span className={isScanning ? 'text-amber-400 font-bold animate-pulse' : lastProbeResult && !lastProbeResult.passed ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
          {isScanning ? 'TESTING PROBE BEAMS...' : lastProbeResult && !lastProbeResult.passed ? 'DEFENSE BREACH DETECTED' : 'GUARDRAIL ACTIVE (PROTECTED)'}
        </span>
      </div>
    </div>
  );
}
