import React, { useState } from 'react';
import { useVulnStore } from '../../state/useVulnStore';
import { 
  ShieldAlert, ShieldCheck, Activity, Cpu, Sparkles, Volume2, 
  VolumeX, RefreshCw, Users, Terminal, Play, AlertTriangle, CheckCircle2 
} from 'lucide-react';

export default function Navbar() {
  const { 
    overview, refreshAll, isLoading, isCopilotOpen, setIsCopilotOpen, 
    soundEnabled, setSoundEnabled, handleSimulateAttack, selectedContainerId,
    toastMessage, activeTab, setActiveTab 
  } = useVulnStore();

  const [showTeamModal, setShowTeamModal] = useState(false);
  const [showSimMenu, setShowSimMenu] = useState(false);

  const healthScore = overview?.cluster_health_score ?? 78;

  return (
    <>
      <header className="sticky top-0 z-40 w-full border-b border-cyan-500/20 cyber-glass">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          
          {/* Brand Logo & Presentation Header */}
          <div className="flex items-center gap-3">
            <div className="relative flex items-center justify-center w-10 h-10 rounded-lg bg-cyan-950/80 border border-cyan-400/40 cyber-glow-cyan">
              <ShieldAlert className="w-6 h-6 text-cyan-400" />
              <div className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-orbitron font-extrabold text-lg tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-sky-200 to-indigo-400">
                  VULNWATCH
                </span>
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                  v1.0 • DevSecOps
                </span>
              </div>
              <p className="text-[10px] text-slate-400 font-mono hidden md:block">
                Continuous Vulnerability Monitoring & Runtime Behavior Analysis
              </p>
            </div>
          </div>

          {/* Center Cluster Health Posture Pill */}
          <div className="hidden lg:flex items-center gap-3 px-4 py-1.5 rounded-full bg-slate-900/90 border border-slate-800 shadow-inner">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-slate-400">Cluster Posture:</span>
              <span className={`font-orbitron text-sm font-bold ${healthScore > 75 ? 'text-emerald-400' : healthScore > 50 ? 'text-amber-400' : 'text-rose-400'}`}>
                {healthScore} / 100
              </span>
            </div>
            <div className="w-20 h-2 bg-slate-800 rounded-full overflow-hidden">
              <div 
                className={`h-full transition-all duration-700 ${healthScore > 75 ? 'bg-emerald-400' : healthScore > 50 ? 'bg-amber-400' : 'bg-rose-500'}`}
                style={{ width: `${healthScore}%` }}
              />
            </div>
          </div>

          {/* Right Action Controls */}
          <div className="flex items-center gap-2">
            {/* Dynamic Attack Simulator Quick Menu */}
            <div className="relative">
              <button
                onClick={() => setShowSimMenu(!showSimMenu)}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono font-medium rounded-lg bg-rose-950/60 hover:bg-rose-900/80 border border-rose-500/30 text-rose-300 transition-colors cursor-pointer"
                title="Simulate dynamic runtime attack (Approach A validation)"
              >
                <AlertTriangle className="w-3.5 h-3.5 text-rose-400 animate-pulse" />
                <span className="hidden sm:inline">Simulate Attack</span>
              </button>

              {showSimMenu && (
                <div className="absolute right-0 mt-2 w-64 rounded-xl cyber-glass-card border border-rose-500/30 p-2 shadow-2xl z-50 animate-in fade-in zoom-in-95">
                  <div className="text-[11px] font-mono text-slate-400 px-2 py-1 border-b border-slate-800 mb-1">
                    TARGET: <span className="text-rose-400 font-bold">{selectedContainerId}</span>
                  </div>
                  <button
                    onClick={() => { handleSimulateAttack(selectedContainerId, 'log4shell'); setShowSimMenu(false); }}
                    className="w-full text-left px-2.5 py-1.5 text-xs font-mono text-slate-200 hover:bg-rose-950/50 hover:text-rose-300 rounded flex items-center justify-between transition-colors"
                  >
                    <span>1. Log4Shell JNDI RCE</span>
                    <span className="text-[10px] text-rose-400">CRITICAL</span>
                  </button>
                  <button
                    onClick={() => { handleSimulateAttack(selectedContainerId, 'reverse_shell'); setShowSimMenu(false); }}
                    className="w-full text-left px-2.5 py-1.5 text-xs font-mono text-slate-200 hover:bg-rose-950/50 hover:text-rose-300 rounded flex items-center justify-between transition-colors"
                  >
                    <span>2. Outbound Reverse Shell</span>
                    <span className="text-[10px] text-rose-400">CRITICAL</span>
                  </button>
                  <button
                    onClick={() => { handleSimulateAttack(selectedContainerId, 'shadow_read'); setShowSimMenu(false); }}
                    className="w-full text-left px-2.5 py-1.5 text-xs font-mono text-slate-200 hover:bg-amber-950/50 hover:text-amber-300 rounded flex items-center justify-between transition-colors"
                  >
                    <span>3. /etc/shadow Credential Read</span>
                    <span className="text-[10px] text-amber-400">HIGH</span>
                  </button>
                  <button
                    onClick={() => { handleSimulateAttack(selectedContainerId, 'priv_esc'); setShowSimMenu(false); }}
                    className="w-full text-left px-2.5 py-1.5 text-xs font-mono text-slate-200 hover:bg-amber-950/50 hover:text-amber-300 rounded flex items-center justify-between transition-colors"
                  >
                    <span>4. Sudo Buffer Overflow (setuid)</span>
                    <span className="text-[10px] text-amber-400">HIGH</span>
                  </button>
                  <button
                    onClick={() => { handleSimulateAttack(selectedContainerId, 'crypto_miner'); setShowSimMenu(false); }}
                    className="w-full text-left px-2.5 py-1.5 text-xs font-mono text-slate-200 hover:bg-cyan-950/50 hover:text-cyan-300 rounded flex items-center justify-between transition-colors"
                  >
                    <span>5. XMRig Crypto Miner Loop</span>
                    <span className="text-[10px] text-cyan-400">MEDIUM</span>
                  </button>
                </div>
              )}
            </div>

            {/* AI Security Copilot Button (Review feedback requirement) */}
            <button
              onClick={() => {
                setActiveTab('ai-remediation');
                setIsCopilotOpen(true);
              }}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono font-medium rounded-lg border transition-colors cursor-pointer ${
                isCopilotOpen && activeTab === 'ai-remediation'
                  ? 'bg-indigo-900 border-indigo-400/60 text-indigo-200 cyber-glow-purple'
                  : 'bg-indigo-950/80 hover:bg-indigo-900 border-indigo-400/40 text-indigo-300 cyber-glow-purple'
              }`}
            >
              <Sparkles className="w-3.5 h-3.5 text-indigo-400 animate-spin" style={{ animationDuration: '6s' }} />
              <span>AI Copilot</span>
            </button>

            {/* Sound Toggle */}
            <button
              onClick={() => setSoundEnabled(!soundEnabled)}
              className="p-2 text-slate-400 hover:text-cyan-300 hover:bg-slate-900 rounded-lg transition-colors cursor-pointer"
              title={soundEnabled ? "Mute Cyber HUD Sounds" : "Enable Cyber HUD Sounds"}
            >
              {soundEnabled ? <Volume2 className="w-4 h-4 text-cyan-400" /> : <VolumeX className="w-4 h-4" />}
            </button>

            {/* Refresh Sync */}
            <button
              onClick={refreshAll}
              disabled={isLoading}
              className="p-2 text-slate-400 hover:text-cyan-300 hover:bg-slate-900 rounded-lg transition-colors cursor-pointer"
              title="Refresh Cluster Telemetry"
            >
              <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
            </button>

            {/* Team Info Modal Button */}
            <button
              onClick={() => setShowTeamModal(true)}
              className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-mono rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 transition-colors cursor-pointer"
              title="Project Team Details"
            >
              <Users className="w-3.5 h-3.5 text-cyan-400" />
              <span className="hidden xl:inline">SGP Team</span>
            </button>
          </div>

        </div>
      </header>

      {/* Floating Alert Toast */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 max-w-md p-4 rounded-xl cyber-glass border shadow-2xl animate-in slide-in-from-bottom-5 transition-all">
          <div className="flex items-start gap-3">
            {toastMessage.type === 'alert' || toastMessage.type === 'error' ? (
              <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            ) : (
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            )}
            <div>
              <div className="text-xs font-orbitron font-bold text-white mb-0.5 uppercase tracking-wide">
                {toastMessage.type === 'alert' ? 'SECURITY ALERT TRIGGERED' : 'SYSTEM NOTIFICATION'}
              </div>
              <p className="text-xs font-mono text-slate-300 leading-relaxed">
                {toastMessage.text}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Team Details Modal */}
      {showTeamModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg rounded-2xl cyber-glass-card border border-cyan-500/30 p-6 shadow-2xl relative">
            <div className="flex items-center justify-between border-b border-cyan-500/20 pb-4 mb-4">
              <div className="flex items-center gap-2">
                <Users className="w-5 h-5 text-cyan-400" />
                <h3 className="font-orbitron font-bold text-lg text-white">SGP Sem 5 Team Information</h3>
              </div>
              <button 
                onClick={() => setShowTeamModal(false)}
                className="text-slate-400 hover:text-white text-lg font-mono px-2 py-1 rounded"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 mb-6">
              <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800">
                <span className="text-xs text-cyan-400 font-mono font-bold block mb-1">PROJECT TITLE:</span>
                <p className="text-sm font-semibold text-slate-200">
                  VulnWatch: Continuous Vulnerability Monitoring & Runtime Behavior Analysis for Containerized Applications
                </p>
                <p className="text-xs text-slate-400 font-mono mt-1">Domain: CyberSecurity & DevOps</p>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div className="p-2.5 rounded bg-slate-900/60 border border-slate-800 text-xs font-mono">
                  <span className="text-slate-400">Student 1:</span>
                  <div className="text-cyan-300 font-bold mt-0.5">24DCS136_Yashvi Thakkar</div>
                </div>
                <div className="p-2.5 rounded bg-slate-900/60 border border-slate-800 text-xs font-mono">
                  <span className="text-slate-400">Student 2:</span>
                  <div className="text-cyan-300 font-bold mt-0.5">24DCS076_Mantra Patel</div>
                </div>
                <div className="p-2.5 rounded bg-slate-900/60 border border-slate-800 text-xs font-mono">
                  <span className="text-slate-400">Student 3:</span>
                  <div className="text-cyan-300 font-bold mt-0.5">24DCS089_Tirth Patel</div>
                </div>
                <div className="p-2.5 rounded bg-slate-900/60 border border-slate-800 text-xs font-mono">
                  <span className="text-slate-400">Student 4:</span>
                  <div className="text-cyan-300 font-bold mt-0.5">24DCS098_Mitesh Patil</div>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-indigo-950/40 border border-indigo-500/20 text-xs font-mono text-indigo-300">
                <span className="font-bold text-white block mb-0.5">Review Feedback Integration:</span>
                "Explore the integration of AI to automate selected features, streamline processes, and enhance the overall user experience." — Implemented via VulnWatch AI Automated Remediation & Triage.
              </div>
            </div>

            <button
              onClick={() => setShowTeamModal(false)}
              className="w-full py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-black font-orbitron font-bold text-xs transition-colors"
            >
              CLOSE WINDOW
            </button>
          </div>
        </div>
      )}
    </>
  );
}
