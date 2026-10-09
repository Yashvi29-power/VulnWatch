import React, { useState } from 'react';
import { useVulnStore } from '../../state/useVulnStore';
import { api } from '../../services/api';
import { 
  Sparkles, Zap, CheckCircle2, Terminal, Code2, 
  Send, AlertTriangle, Play, RefreshCw, ShieldCheck 
} from 'lucide-react';

export default function AIRemediationView() {
  const { 
    remediations, containers, selectedContainerId, 
    handleApplyRemediation, isLoading, showToast 
  } = useVulnStore();

  const [chatInput, setChatInput] = useState('');
  const [chatMessages, setChatMessages] = useState([
    {
      sender: 'ai',
      text: "👋 Hello! I am **VulnWatch AI**, your DevSecOps & Runtime Security Copilot. I automatically synthesize Dockerfile patches, investigate eBPF syscall anomalies, and score Garak LLM vulnerabilities. How can I assist you with your cluster today?"
    }
  ]);
  const [isAiReplying, setIsAiReplying] = useState(false);
  const [generatingPatch, setGeneratingPatch] = useState(false);

  const handleSendMessage = async (e) => {
    e?.preventDefault();
    if (!chatInput.trim()) return;

    const userMsg = chatInput.trim();
    setChatMessages((prev) => [...prev, { sender: 'user', text: userMsg }]);
    setChatInput('');
    setIsAiReplying(true);

    try {
      const res = await api.chatAI(userMsg, selectedContainerId);
      setChatMessages((prev) => [
        ...prev,
        {
          sender: 'ai',
          text: res.reply,
          suggestedActions: res.suggested_actions,
          cves: res.referenced_cves,
          mitre: res.mitre_tags
        }
      ]);
    } catch (err) {
      setChatMessages((prev) => [
        ...prev,
        { sender: 'ai', text: `⚠️ Error contacting AI engine: ${err.message}` }
      ]);
    } finally {
      setIsAiReplying(false);
    }
  };

  const handleQuickQuestion = (q) => {
    setChatInput(q);
  };

  const handleGenerateNewPatch = async (containerId) => {
    setGeneratingPatch(true);
    try {
      await api.generateRemediation(containerId);
      showToast(`AI Remediation Plan synthesized for ${containerId}!`, 'success');
      window.location.reload();
    } catch (err) {
      showToast(`Generation failed: ${err.message}`, 'error');
    } finally {
      setGeneratingPatch(false);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      
      {/* Header with Review Feedback Badge */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="font-orbitron text-xs text-emerald-400 font-bold tracking-widest uppercase">
              REVIEW FEEDBACK REQUIREMENT
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
              AI INTEGRATION ACTIVE
            </span>
          </div>
          <h2 className="font-orbitron font-bold text-xl text-white flex items-center gap-2">
            <Sparkles className="w-6 h-6 text-emerald-400" />
            <span>AI AUTOMATED REMEDIATION & SECURITY COPILOT</span>
          </h2>
          <p className="text-xs text-slate-300 font-mono mt-1">
            Autonomous patch generation, Dockerfile diff remediation, and natural language threat triage.
          </p>
        </div>

        <button
          onClick={() => handleGenerateNewPatch(selectedContainerId)}
          disabled={generatingPatch}
          className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-black font-orbitron font-bold text-xs flex items-center gap-1.5 transition-colors cursor-pointer shrink-0"
        >
          {generatingPatch ? <RefreshCw className="w-3.5 h-3.5 animate-spin fill-black" /> : <Zap className="w-3.5 h-3.5 fill-black" />}
          <span>SYNTHESIZE NEW AI PATCH</span>
        </button>
      </div>

      {/* 2 Column Layout: AI Patches (Left) + Interactive Copilot Chat (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left 7 Cols: Active AI Remediation Plans & Diffs */}
        <div className="lg:col-span-7 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-orbitron font-bold text-sm text-white flex items-center gap-2">
              <Code2 className="w-4 h-4 text-cyan-400" />
              <span>AI-GENERATED REMEDIATION PATCHES</span>
            </h3>
            <span className="text-xs font-mono text-slate-400">
              {remediations.length} Active Plans
            </span>
          </div>

          <div className="space-y-4">
            {remediations.map((plan) => {
              const isApplied = plan.status === 'APPLIED';
              return (
                <div
                  key={plan.id}
                  className={`cyber-glass-card rounded-2xl p-5 border transition-all ${
                    isApplied
                      ? 'border-emerald-500/40 bg-emerald-950/10'
                      : 'border-cyan-500/30 bg-slate-950/80 cyber-glow-cyan'
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 mb-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-orbitron font-bold text-sm text-white">
                          {plan.title}
                        </span>
                        {isApplied ? (
                          <span className="px-2 py-0.5 rounded bg-emerald-500 text-black font-bold text-[10px] font-mono">
                            APPLIED & VERIFIED
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded bg-amber-500 text-black font-bold text-[10px] font-mono">
                            READY FOR DEPLOYMENT
                          </span>
                        )}
                      </div>
                      <span className="text-[11px] font-mono text-slate-400 mt-0.5 block">
                        Target: <strong className="text-cyan-300">{plan.container_id}</strong> | Confidence: <strong className="text-emerald-400">{Math.round(plan.confidence_score * 100)}%</strong>
                      </span>
                    </div>

                    {!isApplied && (
                      <button
                        onClick={() => handleApplyRemediation(plan.id)}
                        disabled={isLoading}
                        className="px-4 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-black font-orbitron font-bold text-xs flex items-center gap-1.5 transition-colors cursor-pointer shrink-0"
                      >
                        <Zap className="w-3.5 h-3.5 fill-black" />
                        <span>DEPLOY PATCH</span>
                      </button>
                    )}
                  </div>

                  {/* Root Cause Analysis */}
                  <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 text-xs font-mono mb-3">
                    <span className="text-cyan-400 font-bold block mb-1">🔍 ROOT CAUSE ANALYSIS:</span>
                    <p className="text-slate-300 leading-relaxed">{plan.root_cause_analysis}</p>
                    {plan.mitre_technique && (
                      <span className="text-[10px] text-indigo-300 mt-2 block">
                        MITRE ATT&CK: <strong>{plan.mitre_technique}</strong>
                      </span>
                    )}
                  </div>

                  {/* Unified Diff Patch Viewer */}
                  <div className="space-y-1 mb-3">
                    <span className="text-[11px] font-mono text-slate-400 block">Proposed Code & Config Diff:</span>
                    <div className="rounded-lg bg-slate-950 border border-slate-800 p-3 overflow-x-auto text-[11px] font-mono">
                      <pre className="text-slate-200">
                        {plan.diff_patch.split('\n').map((line, lIdx) => {
                          let lineClass = 'text-slate-400';
                          if (line.startsWith('+')) lineClass = 'text-emerald-400 bg-emerald-950/40 font-bold';
                          if (line.startsWith('-')) lineClass = 'text-rose-400 bg-rose-950/40 line-through';
                          if (line.startsWith('@@')) lineClass = 'text-cyan-400';
                          return (
                            <div key={lIdx} className={lineClass}>
                              {line}
                            </div>
                          );
                        })}
                      </pre>
                    </div>
                  </div>

                  {/* Step-by-Step Commands */}
                  <div className="space-y-1">
                    <span className="text-[11px] font-mono text-slate-400 block">DevOps Execution Script:</span>
                    <div className="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800 font-mono text-[11px] text-cyan-300 space-y-1">
                      {plan.commands_to_execute.map((cmd, cIdx) => (
                        <div key={cIdx} className="flex items-center gap-2">
                          <span className="text-slate-500">$</span>
                          <code>{cmd}</code>
                        </div>
                      ))}
                    </div>
                  </div>

                </div>
              );
            })}
          </div>
        </div>

        {/* Right 5 Cols: Interactive CyberSec Copilot Chat Terminal */}
        <div className="lg:col-span-5 cyber-glass-card rounded-2xl p-5 border border-indigo-500/30 flex flex-col h-[640px]">
          
          <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
            <div className="flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-indigo-400 animate-spin" style={{ animationDuration: '8s' }} />
              <div>
                <h3 className="font-orbitron font-bold text-sm text-white">
                  VULNWATCH COPILOT
                </h3>
                <span className="text-[10px] font-mono text-slate-400">Autonomous CyberSec Assistant</span>
              </div>
            </div>
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
          </div>

          {/* Chat Messages Log */}
          <div className="flex-1 overflow-y-auto space-y-3 pr-1 text-xs font-mono">
            {chatMessages.map((msg, idx) => (
              <div
                key={idx}
                className={`p-3.5 rounded-xl ${
                  msg.sender === 'user'
                    ? 'bg-cyan-950/80 border border-cyan-500/30 ml-6 text-slate-200'
                    : 'bg-slate-900/90 border border-slate-800 mr-2 text-slate-300'
                }`}
              >
                <div className="text-[10px] font-bold mb-1 text-slate-400 flex items-center justify-between">
                  <span>{msg.sender === 'user' ? 'OPERATOR' : 'VULNWATCH AI'}</span>
                </div>
                <div className="whitespace-pre-wrap leading-relaxed">
                  {msg.text}
                </div>

                {msg.mitre && msg.mitre.length > 0 && (
                  <div className="flex items-center gap-1.5 flex-wrap mt-2 pt-2 border-t border-slate-800">
                    {msg.mitre.map((m, mIdx) => (
                      <span key={mIdx} className="text-[10px] px-1.5 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800">
                        {m}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}

            {isAiReplying && (
              <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-xs font-mono text-cyan-400 flex items-center gap-2 animate-pulse">
                <Sparkles className="w-4 h-4 animate-spin" />
                <span>AI analyzing cluster telemetry & synthesizing guidance...</span>
              </div>
            )}
          </div>

          {/* Quick Questions Chips */}
          <div className="py-2 flex items-center gap-1.5 overflow-x-auto no-scrollbar text-[11px] font-mono text-slate-400 border-t border-slate-800 mt-2">
            <button
              onClick={() => handleQuickQuestion("Explain the Log4j RCE active in our cluster.")}
              className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-cyan-300 shrink-0 cursor-pointer"
            >
              Log4Shell Analysis
            </button>
            <button
              onClick={() => handleQuickQuestion("What LLM guardrails are failing in Garak?")}
              className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-purple-300 shrink-0 cursor-pointer"
            >
              LLM Safety Status
            </button>
            <button
              onClick={() => handleQuickQuestion("How do I isolate rogue PID 4189?")}
              className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-rose-300 shrink-0 cursor-pointer"
            >
              Isolate Rogue PID
            </button>
          </div>

          {/* Chat Input Bar */}
          <form onSubmit={handleSendMessage} className="flex items-center gap-2 pt-1">
            <input
              type="text"
              placeholder="Ask AI Copilot about threats, CVEs, or fixes..."
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              className="flex-1 px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs font-mono text-white placeholder:text-slate-500 outline-none focus:border-cyan-400"
            />
            <button
              type="submit"
              disabled={isAiReplying || !chatInput.trim()}
              className="p-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-black font-bold transition-colors cursor-pointer shrink-0 disabled:opacity-50"
            >
              <Send className="w-4 h-4 fill-black" />
            </button>
          </form>

        </div>

      </div>

    </div>
  );
}
