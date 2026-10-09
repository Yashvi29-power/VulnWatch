import React, { useEffect, useRef } from 'react';
import * as THREE from 'three';
import { useVulnStore } from '../../state/useVulnStore';

export default function HolographicCluster({ height = '360px' }) {
  const mountRef = useRef(null);
  const { containers, selectedContainerId, setSelectedContainerId, playCyberSound } = useVulnStore();

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;

    const width = mount.clientWidth;
    const heightPx = mount.clientHeight || 360;

    // Scene, Camera, Renderer
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(50, width / heightPx, 0.1, 1000);
    camera.position.set(0, 15, 30);
    camera.lookAt(0, 0, 0);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, heightPx);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    mount.appendChild(renderer.domElement);

    // Group for entire cluster to rotate gently
    const clusterGroup = new THREE.Group();
    scene.add(clusterGroup);

    // Ambient & Point Lights
    const ambientLight = new THREE.AmbientLight(0x00f0ff, 0.6);
    scene.add(ambientLight);

    const coreLight = new THREE.PointLight(0x00ffff, 2, 50);
    coreLight.position.set(0, 0, 0);
    scene.add(coreLight);

    // Central Core Sphere (Unified Correlation Engine Core)
    const coreGeo = new THREE.IcosahedronGeometry(2.2, 2);
    const coreMat = new THREE.MeshBasicMaterial({
      color: 0x00f0ff,
      wireframe: true,
      transparent: true,
      opacity: 0.65,
    });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    clusterGroup.add(coreMesh);

    // Inner glowing sphere
    const innerGeo = new THREE.SphereGeometry(1.2, 16, 16);
    const innerMat = new THREE.MeshBasicMaterial({
      color: 0x38bdf8,
      transparent: true,
      opacity: 0.8,
    });
    const innerMesh = new THREE.Mesh(innerGeo, innerMat);
    clusterGroup.add(innerMesh);

    // Orbiting Grid Rings
    const ringGeo = new THREE.RingGeometry(11.8, 12, 64);
    const ringMat = new THREE.MeshBasicMaterial({
      color: 0x0ea5e9,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.2,
    });
    const ringMesh = new THREE.Mesh(ringGeo, ringMat);
    ringMesh.rotation.x = Math.PI / 2;
    clusterGroup.add(ringMesh);

    // Container Nodes in Orbit
    const nodeMeshes = [];
    const containerList = containers.length > 0 ? containers : [
      { id: 'cnt-payment-01', name: 'payment-gateway', status: 'COMPROMISED' },
      { id: 'cnt-auth-02', name: 'auth-gateway', status: 'SUSPICIOUS' },
      { id: 'cnt-llm-rag-03', name: 'llm-rag-agent', status: 'SUSPICIOUS' },
      { id: 'cnt-db-cluster-04', name: 'db-primary', status: 'RUNNING' },
      { id: 'cnt-frontend-05', name: 'frontend-proxy', status: 'RUNNING' },
    ];

    const radius = 12;
    containerList.forEach((cnt, idx) => {
      const angle = (idx / containerList.length) * Math.PI * 2;
      const x = Math.cos(angle) * radius;
      const z = Math.sin(angle) * radius;
      const y = Math.sin(idx * 1.5) * 2;

      // Color by status
      let nodeColor = 0x10b981; // Green
      if (cnt.status === 'COMPROMISED') nodeColor = 0xff0055; // Crimson Red
      else if (cnt.status === 'SUSPICIOUS') nodeColor = 0xf59e0b; // Amber
      else if (cnt.status === 'ISOLATED') nodeColor = 0x8b5cf6; // Purple

      // Node Sphere
      const nodeGeo = new THREE.SphereGeometry(1.1, 24, 24);
      const nodeMat = new THREE.MeshStandardMaterial({
        color: nodeColor,
        emissive: nodeColor,
        emissiveIntensity: 0.6,
        roughness: 0.2,
        metalness: 0.8,
      });
      const nodeMesh = new THREE.Mesh(nodeGeo, nodeMat);
      nodeMesh.position.set(x, y, z);
      nodeMesh.userData = { containerId: cnt.id, name: cnt.name, status: cnt.status };
      clusterGroup.add(nodeMesh);
      nodeMeshes.push(nodeMesh);

      // Outer Pulsing Ring for Node
      const haloGeo = new THREE.TorusGeometry(1.6, 0.05, 8, 32);
      const haloMat = new THREE.MeshBasicMaterial({
        color: nodeColor,
        transparent: true,
        opacity: 0.7,
      });
      const haloMesh = new THREE.Mesh(haloGeo, haloMat);
      haloMesh.position.set(x, y, z);
      haloMesh.rotation.x = Math.PI / 2;
      clusterGroup.add(haloMesh);

      // Connecting Laser Line to Core
      const points = [new THREE.Vector3(0, 0, 0), new THREE.Vector3(x, y, z)];
      const lineGeo = new THREE.BufferGeometry().setFromPoints(points);
      const lineMat = new THREE.LineBasicMaterial({
        color: nodeColor,
        transparent: true,
        opacity: 0.35,
      });
      const line = new THREE.Line(lineGeo, lineMat);
      clusterGroup.add(line);
    });

    // Orbiting Background Cyber Particles
    const particleCount = 180;
    const particleGeo = new THREE.BufferGeometry();
    const particlePositions = new Float32Array(particleCount * 3);
    for (let i = 0; i < particleCount * 3; i += 3) {
      particlePositions[i] = (Math.random() - 0.5) * 40;
      particlePositions[i + 1] = (Math.random() - 0.5) * 20;
      particlePositions[i + 2] = (Math.random() - 0.5) * 40;
    }
    particleGeo.setAttribute('position', new THREE.BufferAttribute(particlePositions, 3));
    const particleMat = new THREE.PointsMaterial({
      color: 0x00f0ff,
      size: 0.3,
      transparent: true,
      opacity: 0.6,
    });
    const particles = new THREE.Points(particleGeo, particleMat);
    scene.add(particles);

    // Raycaster for mouse interaction
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2();

    const onPointerDown = (event) => {
      const rect = renderer.domElement.getBoundingClientRect();
      mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;

      raycaster.setFromCamera(mouse, camera);
      const intersects = raycaster.intersectObjects(nodeMeshes);
      if (intersects.length > 0) {
        const clickedNode = intersects[0].object;
        const cId = clickedNode.userData.containerId;
        setSelectedContainerId(cId);
        playCyberSound('beep');
      }
    };

    renderer.domElement.addEventListener('pointerdown', onPointerDown);

    // Animation Loop
    let animationFrameId;
    let clock = new THREE.Clock();

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate);
      const elapsedTime = clock.getElapsedTime();

      // Gentle cluster rotation
      clusterGroup.rotation.y = elapsedTime * 0.15;
      coreMesh.rotation.y = -elapsedTime * 0.3;
      coreMesh.rotation.x = elapsedTime * 0.2;

      // Particle subtle motion
      particles.rotation.y = elapsedTime * 0.05;

      // Highlight selected container mesh
      nodeMeshes.forEach((mesh) => {
        if (mesh.userData.containerId === selectedContainerId) {
          mesh.scale.set(1.4, 1.4, 1.4);
          mesh.material.emissiveIntensity = 1.0 + Math.sin(elapsedTime * 6) * 0.4;
        } else {
          mesh.scale.set(1.0, 1.0, 1.0);
          mesh.material.emissiveIntensity = 0.5;
        }
      });

      renderer.render(scene, camera);
    };

    animate();

    // Resize Handler
    const handleResize = () => {
      if (!mount) return;
      const w = mount.clientWidth;
      const h = mount.clientHeight || 360;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      renderer.domElement.removeEventListener('pointerdown', onPointerDown);
      cancelAnimationFrame(animationFrameId);
      if (mount && renderer.domElement) {
        mount.removeChild(renderer.domElement);
      }
      renderer.dispose();
    };
  }, [containers, selectedContainerId, setSelectedContainerId, playCyberSound]);

  return (
    <div className="relative w-full rounded-xl overflow-hidden cyber-glass border border-cyan-500/20 scanline" style={{ height }}>
      {/* 3D Canvas Mount */}
      <div ref={mountRef} className="w-full h-full cursor-grab active:cursor-grabbing" />

      {/* Futuristic HUD Overlay */}
      <div className="absolute top-3 left-4 pointer-events-none">
        <div className="flex items-center gap-2">
          <span className="inline-block w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping" />
          <span className="font-orbitron text-xs font-bold tracking-widest text-cyan-400">
            3D CLUSTER MESH TOPOLOGY
          </span>
        </div>
        <p className="text-[11px] text-slate-400 font-mono mt-0.5">
          Live eBPF & SBOM Telemetry Orbit | Click node to inspect
        </p>
      </div>

      {/* Legend */}
      <div className="absolute bottom-3 left-4 pointer-events-none flex items-center gap-3 bg-slate-950/80 px-3 py-1.5 rounded-lg border border-slate-800 text-[11px] font-mono">
        <span className="flex items-center gap-1.5 text-rose-400">
          <span className="w-2 h-2 rounded-full bg-rose-500" /> Compromised (CVE Active)
        </span>
        <span className="flex items-center gap-1.5 text-amber-400">
          <span className="w-2 h-2 rounded-full bg-amber-500" /> Suspicious
        </span>
        <span className="flex items-center gap-1.5 text-emerald-400">
          <span className="w-2 h-2 rounded-full bg-emerald-500" /> Hardened / Secure
        </span>
      </div>

      <div className="absolute bottom-3 right-4 pointer-events-none text-right font-mono text-[11px] text-cyan-400/80 bg-slate-950/80 px-2.5 py-1 rounded border border-cyan-900/50">
        Active Node: <span className="text-white font-bold">{selectedContainerId}</span>
      </div>
    </div>
  );
}
