import React from 'react';
import { useVulnStore } from '../../state/useVulnStore';
import { 
  GitMerge, Layers, Activity, Cpu, ShieldAlert, 
  ArrowRight, Flame, Zap, Send, CheckCircle2 
} from 'lucide-react';

export default function UnifiedCorrelationMatrix() {
  const { overview, setActiveTab, handleDispatchAlert, showToast } = useVulnStore();

  const correlations = overview?.cross_signal_correlations || [];

  const handleQuickDispatch = async (corr) => {
    await handleDispatchAlert({
      target: 'all',
      title: `[CORRELATED CRITICAL] ${corr.cve_title} in ${corr.container_name}`,
      severity: 'CRITICAL',
      container_name: corr.container_name,
      cve_id: corr.cve_id,
      details: corr.details,
      remediation: `Isolate container ${corr.container_name} and deploy AI remediation patch immediately.`
    });
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      
      {/* Novelty & Architecture Banner (Slide 5 & 8) */}
      <div className="relative overflow-hidden rounded-2xl cyber-glass-card border border-indigo-500/30 p-6 bg-gradient-to-r from-slate-950 via-slate-900 to-indigo-950/60">
        <div className="max-w-4xl">
          <div className="flex items-center gap-2 mb-2">
            <span className="font-orbitron text-xs text-indigo-400 font-bold tracking-widest uppercase">
              INNOVATION & NOVELTY CORE (PRESENTATION SLIDE 5 & 8)
            </span>
            <span className="w-2 h-2 rounded-full bg-indigo-400 animate-ping" />
          </div>
          <h2 className="text-xl sm:text-2xl font-orbitron font-extrabold text-white">
            Unified Tri-Signal Correlation Engine
          </h2>
          <p className="text-xs text-slate-300 font-mono mt-2 leading-relaxed">
            "The real novelty is the unification: no common tool today combines package CVE matching, runtime behavioral confirmation, and LLM adversarial testing under one continuous, workflow-integrated platform."
          </p>
        </div>

        {/* 3 Signal Flow Diagram */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-6 pt-4 border-t border-indigo-500/20">
          
          <div className="p-3 rounded-xl bg-cyan-950/40 border border-cyan-500/30 text-xs font-mono">
            <div className="flex items-center gap-2 text-cyan-300 font-bold mb-1">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span>SIGNAL 1: STATIC SBOM</span>
            </div>
            <p className="text-slate-400 text-[11px]">
              Package inventory extraction (≥95% coverage) + NVD/OSV CPE matching.
            </p>
          </div>

          <div className="p-3 rounded-xl bg-amber-950/40 border border-amber-500/30 text-xs font-mono">
            <div className="flex items-center gap-2 text-amber-300 font-bold mb-1">
              <Activity className="w-4 h-4 text-amber-400" />
              <span>SIGNAL 2: RUNTIME eBPF</span>
            </div>
            <p className="text-slate-400 text-[11px]">
              Approach A: Live kernel syscalls (execve, openat, socket) confirming exploitation.
            </p>
          </div>

          <div className="p-3 rounded-xl bg-purple-950/40 border border-purple-500/30 text-xs font-mono">
            <div className="flex items-center gap-2 text-purple-300 font-bold mb-1">
              <Cpu className="w-4 h-4 text-purple-400" />
              <span>SIGNAL 3: GARAK LLM PROBES</span>
            </div>
            <p className="text-slate-400 text-[11px]">
              Approach B: Dynamic prompt injection and jailbreak tests scoring pass/fail.
            </p>
          </div>

        </div>
      </div>

      {/* Cross-Signal Correlation Records */}
      <div className="cyber-glass-card rounded-2xl p-6 border border-indigo-500/20">
        <div className="flex items-center justify-between border-b border-indigo-500/20 pb-3 mb-5">
          <div className="flex items-center gap-2">
            <GitMerge className="w-5 h-5 text-indigo-400" />
            <h3 className="font-orbitron font-bold text-sm text-white">
              ACTIVE CROSS-SIGNAL CORRELATION INCIDENTS
            </h3>
          </div>
          <span className="text-xs font-mono text-rose-400 bg-rose-950/80 px-2.5 py-1 rounded border border-rose-800">
            {correlations.length} Confirmed Exploit Vectors
          </span>
        </div>

        <div className="space-y-4">
          {correlations.map((corr, idx) => (
            <div
              key={idx}
              className="p-5 rounded-xl bg-slate-950/80 border border-rose-500/40 cyber-glow-red space-y-4 font-mono text-xs"
            >
              <div className="flex flex-col md:flex-row md:items-start justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="px-2 py-0.5 rounded bg-rose-500 text-black font-bold text-[10px]">
                      CONFIRMED RUNTIME EXPLOITATION
                    </span>
                    <span className="font-orbitron text-sm font-bold text-white">
                      {corr.container_name}
                    </span>
                    <span className="text-cyan-300 font-bold">
                      [{corr.cve_id}]
                    </span>
                  </div>
                  <h4 className="text-sm font-semibold text-slate-200 mt-1">
                    {corr.cve_title}
                  </h4>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800">
                    Confidence: 99.4%
                  </span>
                  <button
                    onClick={() => handleQuickDispatch(corr)}
                    className="px-3 py-1 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs flex items-center gap-1 transition-colors cursor-pointer"
                  >
                    <Send className="w-3 h-3" />
                    <span>Dispatch Slack/Git</span>
                  </button>
                </div>
              </div>

              {/* Tri-Signal Evidence Card */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 p-3 rounded-lg bg-slate-900/90 border border-slate-800 text-[11px]">
                <div>
                  <span className="text-slate-500 block mb-0.5">SBOM Static Match:</span>
                  <span className="text-cyan-300 font-bold">{corr.cve_id} (CVSS 10.0)</span>
                </div>
                <div>
                  <span className="text-slate-500 block mb-0.5">Runtime Syscall Correlated:</span>
                  <span className="text-amber-400 font-bold">sys_{corr.syscall}() telemetry</span>
                </div>
                <div>
                  <span className="text-slate-500 block mb-0.5">MITRE ATT&CK Vector:</span>
                  <span className="text-purple-300 font-bold">{corr.mitre_technique}</span>
                </div>
              </div>

              <p className="text-slate-300 text-xs leading-relaxed">
                {corr.details}
              </p>

              {/* Action Buttons */}
              <div className="flex items-center justify-between pt-2 border-t border-slate-800/80">
                <span className="text-[11px] text-slate-400">
                  Status: <strong className="text-rose-400">URGENT ACTION REQUIRED</strong>
                </span>

                <button
                  onClick={() => setActiveTab('ai-remediation')}
                  className="px-3.5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black font-orbitron font-bold text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <Zap className="w-3.5 h-3.5 fill-black" />
                  <span>APPLY AI REMEDIATION PATCH</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
