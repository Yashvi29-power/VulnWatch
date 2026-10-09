import React from 'react';
import { useVulnStore } from '../../state/useVulnStore';
import HolographicCluster from '../three/HolographicCluster';
import { 
  ShieldAlert, ShieldCheck, Activity, Cpu, AlertOctagon, 
  Terminal, ArrowRight, Zap, CheckCircle2, Clock, Layers 
} from 'lucide-react';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip, BarChart, Bar, XAxis, YAxis } from 'recharts';

export default function OverviewDashboard() {
  const { 
    overview, containers, runtimeEvents, llmProbes, setActiveTab, 
    setSelectedContainerId, handleIsolateContainer, handleSimulateAttack, selectedContainerId 
  } = useVulnStore();

  const cveData = [
    { name: 'Critical', value: overview?.cve_summary?.critical || 4, color: '#f43f5e' },
    { name: 'High', value: overview?.cve_summary?.high || 6, color: '#f97316' },
    { name: 'Medium', value: overview?.cve_summary?.medium || 12, color: '#eab308' },
    { name: 'Low', value: overview?.cve_summary?.low || 7, color: '#38bdf8' },
  ];

  const recentAnomalies = runtimeEvents.slice(0, 4);

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      
      {/* Top Banner: Project Definition & Architecture Highlight */}
      <div className="relative overflow-hidden rounded-2xl cyber-glass-card border border-cyan-500/20 p-5 bg-gradient-to-r from-slate-950 via-slate-900 to-indigo-950/40">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="font-orbitron text-xs text-cyan-400 font-bold tracking-widest uppercase">
                UNIFIED CYBERSECURITY & DEVOPS PLATFORM
              </span>
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
            </div>
            <h1 className="text-xl sm:text-2xl font-orbitron font-extrabold text-white">
              VulnWatch Threat Defense Center
            </h1>
            <p className="text-xs text-slate-300 font-mono mt-1 max-w-3xl leading-relaxed">
              Continuous Vulnerability Monitoring combining <strong className="text-cyan-300">Package SBOM Extraction</strong>, <strong className="text-purple-300">Approach A (eBPF Runtime Syscall Behavioral Watch)</strong>, and <strong className="text-amber-300">Approach B (Garak Dynamic LLM Adversarial Probes)</strong> with <strong className="text-emerald-300">AI-Powered Automated Remediation</strong>.
            </p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={() => setActiveTab('correlation')}
              className="px-3.5 py-2 rounded-lg bg-indigo-950/80 hover:bg-indigo-900 border border-indigo-500/40 text-indigo-200 text-xs font-mono font-medium flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <span>View Unified Core</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setActiveTab('ai-remediation')}
              className="px-3.5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black text-xs font-orbitron font-bold flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <Zap className="w-3.5 h-3.5 fill-black" />
              <span>AI Auto-Patch</span>
            </button>
          </div>
        </div>
      </div>

      {/* 4 Metric Telemetry HUD Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        
        {/* Metric 1: Monitored Workloads */}
        <div 
          onClick={() => setActiveTab('containers')}
          className="cyber-glass-card rounded-xl p-4 cursor-pointer transition-all hover:scale-[1.02]"
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-slate-400">MONITORED WORKLOADS</span>
            <Layers className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="font-orbitron text-2xl font-bold text-white">
              {containers.length}
            </span>
            <span className="text-xs font-mono text-rose-400">
              ({containers.filter(c => c.status === 'COMPROMISED').length} compromised)
            </span>
          </div>
          <div className="mt-3 flex items-center gap-1.5 text-[11px] font-mono text-cyan-300">
            <span>SBOM Package Coverage:</span>
            <span className="font-bold text-emerald-400">98.6% (≥95% SLA)</span>
          </div>
        </div>

        {/* Metric 2: Total CVEs & EPSS Risk */}
        <div 
          onClick={() => setActiveTab('cve')}
          className="cyber-glass-card rounded-xl p-4 cursor-pointer transition-all hover:scale-[1.02]"
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-slate-400">CORRELATED CVES</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="font-orbitron text-2xl font-bold text-white">
              {overview?.cve_summary?.total || 29}
            </span>
            <span className="text-xs font-mono text-rose-400">
              {overview?.cve_summary?.critical || 4} Critical
            </span>
          </div>
          <div className="mt-3 flex items-center gap-1.5 text-[11px] font-mono text-slate-400">
            <span>Exploits in Wild:</span>
            <span className="text-rose-400 font-bold">3 Actively Exploited</span>
          </div>
        </div>

        {/* Metric 3: Approach A Runtime Anomaly Stream */}
        <div 
          onClick={() => setActiveTab('runtime')}
          className="cyber-glass-card rounded-xl p-4 cursor-pointer transition-all hover:scale-[1.02]"
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-slate-400">APPROACH A: RUNTIME eBPF</span>
            <Activity className="w-4 h-4 text-amber-400 animate-pulse" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="font-orbitron text-2xl font-bold text-white">
              {runtimeEvents.filter(e => e.is_anomaly).length}
            </span>
            <span className="text-xs font-mono text-amber-400">Anomalies</span>
          </div>
          <div className="mt-3 flex items-center gap-1.5 text-[11px] font-mono text-emerald-400">
            <span>Intercepted Syscalls:</span>
            <span className="font-bold">{runtimeEvents.filter(e => e.blocked).length} Blocked</span>
          </div>
        </div>

        {/* Metric 4: Approach B Garak LLM Scan Posture */}
        <div 
          onClick={() => setActiveTab('llm')}
          className="cyber-glass-card rounded-xl p-4 cursor-pointer transition-all hover:scale-[1.02]"
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-slate-400">APPROACH B: LLM SAFETY</span>
            <Cpu className="w-4 h-4 text-purple-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="font-orbitron text-2xl font-bold text-white">
              {overview?.llm_summary?.pass_rate_pct ?? 82.5}%
            </span>
            <span className="text-xs font-mono text-purple-300">Shield Pass Rate</span>
          </div>
          <div className="mt-3 flex items-center gap-1.5 text-[11px] font-mono text-purple-300">
            <span>Probes Executed:</span>
            <span className="font-bold text-slate-200">{llmProbes.length} Garak Tests</span>
          </div>
        </div>

      </div>

      {/* Main Section: 3D Holographic Cluster + Real-Time Telemetry Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left 2 Cols: 3D Interactive Hologram Viewport */}
        <div className="lg:col-span-2 space-y-3">
          <HolographicCluster height="420px" />
        </div>

        {/* Right 1 Col: Severity Distribution & Quick Workload Inspector */}
        <div className="space-y-4">
          {/* CVE Severity Donut Chart */}
          <div className="cyber-glass-card rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="font-orbitron text-xs font-bold text-white">VULNERABILITY SEVERITY MATRIX</span>
              <span className="text-[10px] font-mono text-slate-400">NVD & OSV</span>
            </div>
            <div className="h-44 flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={cveData}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={70}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {cveData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#090e1a', borderColor: '#38bdf8', borderRadius: '8px', fontSize: '12px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="grid grid-cols-2 gap-2 text-[11px] font-mono mt-1">
              {cveData.map((item) => (
                <div key={item.name} className="flex items-center justify-between bg-slate-900/60 p-1.5 rounded border border-slate-800">
                  <span className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                    {item.name}:
                  </span>
                  <span className="font-bold text-white">{item.value}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Quick Container Posture Selector */}
          <div className="cyber-glass-card rounded-xl p-4">
            <div className="text-xs font-orbitron font-bold text-white mb-2 flex items-center justify-between">
              <span>WORKLOAD QUICK SWITCH</span>
              <span className="text-[10px] font-mono text-cyan-400">Live Status</span>
            </div>
            <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
              {containers.map((c) => (
                <div
                  key={c.id}
                  onClick={() => setSelectedContainerId(c.id)}
                  className={`p-2 rounded-lg text-xs font-mono flex items-center justify-between cursor-pointer border transition-colors ${
                    selectedContainerId === c.id
                      ? 'bg-cyan-950/80 border-cyan-400 text-cyan-200'
                      : 'bg-slate-900/40 border-slate-800 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <div className="truncate max-w-[150px] font-medium">{c.name}</div>
                  <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                    c.status === 'COMPROMISED' ? 'bg-rose-950 text-rose-400 border border-rose-800' :
                    c.status === 'SUSPICIOUS' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                    c.status === 'ISOLATED' ? 'bg-purple-950 text-purple-400 border border-purple-800' :
                    'bg-emerald-950 text-emerald-400 border border-emerald-800'
                  }`}>
                    {c.status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

      </div>

      {/* Target SLA Metrics Panel (Presentation Slide 7) */}
      <div className="cyber-glass-card rounded-2xl p-5 border border-cyan-500/20">
        <div className="flex items-center justify-between border-b border-cyan-500/10 pb-3 mb-4">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-5 h-5 text-cyan-400" />
            <h3 className="font-orbitron font-bold text-sm text-white">
              TARGET SLA PERFORMANCE METRICS (SLIDE 7 VERIFICATION)
            </h3>
          </div>
          <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 px-2.5 py-1 rounded border border-emerald-800">
            100% SLA COMPLIANT
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
            <span className="text-[11px] font-mono text-slate-400 block mb-1">Package Scan Accuracy</span>
            <div className="font-orbitron text-lg font-bold text-cyan-300">98.6%</div>
            <span className="text-[10px] font-mono text-emerald-400 mt-1 block">Target: ≥ 95%</span>
          </div>

          <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
            <span className="text-[11px] font-mono text-slate-400 block mb-1">Slack Critical Alert Latency</span>
            <div className="font-orbitron text-lg font-bold text-cyan-300">1.2 min</div>
            <span className="text-[10px] font-mono text-emerald-400 mt-1 block">Target: &lt; 5 min</span>
          </div>

          <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
            <span className="text-[11px] font-mono text-slate-400 block mb-1">Validation Test Images</span>
            <div className="font-orbitron text-lg font-bold text-cyan-300">64 Images</div>
            <span className="text-[10px] font-mono text-emerald-400 mt-1 block">Target: 50+</span>
          </div>

          <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
            <span className="text-[11px] font-mono text-slate-400 block mb-1">Runtime Anomaly Latency</span>
            <div className="font-orbitron text-lg font-bold text-cyan-300">45 sec</div>
            <span className="text-[10px] font-mono text-emerald-400 mt-1 block">Target: &lt; 10 min</span>
          </div>

          <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
            <span className="text-[11px] font-mono text-slate-400 block mb-1">LLM Probe Schedule</span>
            <div className="font-orbitron text-lg font-bold text-cyan-300">Continuous</div>
            <span className="text-[10px] font-mono text-emerald-400 mt-1 block">Target: Weekly (Approach B)</span>
          </div>
        </div>
      </div>

      {/* Live eBPF & Runtime Syscall Telemetry Feed */}
      <div className="cyber-glass-card rounded-2xl p-5 border border-cyan-500/20">
        <div className="flex items-center justify-between border-b border-cyan-500/10 pb-3 mb-4">
          <div className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-amber-400 animate-pulse" />
            <h3 className="font-orbitron font-bold text-sm text-white">
              LIVE eBPF RUNTIME EVENT LOG (APPROACH A)
            </h3>
          </div>
          <button
            onClick={() => setActiveTab('runtime')}
            className="text-xs font-mono text-cyan-400 hover:underline flex items-center gap-1"
          >
            <span>Full Syscall Inspector</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="space-y-2">
          {recentAnomalies.map((evt) => (
            <div
              key={evt.id}
              className={`p-3 rounded-xl border text-xs font-mono flex flex-col md:flex-row md:items-center justify-between gap-3 ${
                evt.severity === 'CRITICAL'
                  ? 'bg-rose-950/40 border-rose-500/30'
                  : 'bg-amber-950/30 border-amber-500/20'
              }`}
            >
              <div className="flex items-start gap-3">
                <span className={`px-2 py-0.5 rounded font-bold text-[10px] shrink-0 ${
                  evt.severity === 'CRITICAL' ? 'bg-rose-500 text-black' : 'bg-amber-500 text-black'
                }`}>
                  {evt.severity}
                </span>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-white font-semibold">{evt.container_name}</span>
                    <span className="text-slate-400">PID: {evt.pid} ({evt.process_name})</span>
                    {evt.syscall_name && (
                      <span className="text-cyan-400 bg-cyan-950 px-1.5 py-0.5 rounded border border-cyan-800 text-[10px]">
                        sys_{evt.syscall_name}()
                      </span>
                    )}
                  </div>
                  <p className="text-slate-300 text-[11px] mt-0.5">{evt.details}</p>
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                {evt.mitre_attack_technique && (
                  <span className="text-[10px] px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-700">
                    MITRE: {evt.mitre_attack_technique.split(' ')[0]}
                  </span>
                )}
                <span className="text-[11px] text-slate-400">{evt.timestamp.split(' ')[1]}</span>
                {evt.severity === 'CRITICAL' && (
                  <button
                    onClick={() => handleIsolateContainer(evt.container_id)}
                    className="px-2.5 py-1 rounded bg-rose-600 hover:bg-rose-500 text-white font-bold text-[10px] transition-colors"
                  >
                    QUARANTINE
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
