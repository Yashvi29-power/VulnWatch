import React from 'react';
import { useVulnStore } from '../../state/useVulnStore';
import { 
  LayoutDashboard, Layers, Database, Activity, 
  Cpu, GitMerge, Sparkles, Send, ShieldCheck 
} from 'lucide-react';

export default function NavTabs() {
  const { activeTab, setActiveTab, overview, runtimeEvents, llmProbes, containers } = useVulnStore();

  const compromisedCount = containers.filter(c => c.status === 'COMPROMISED' || c.status === 'SUSPICIOUS').length;
  const criticalEventsCount = runtimeEvents.filter(e => e.severity === 'CRITICAL').length;
  const failedProbesCount = llmProbes.filter(p => !p.passed).length;

  const tabs = [
    {
      id: 'overview',
      label: 'Overview & 3D HUD',
      icon: LayoutDashboard,
      badge: null,
    },
    {
      id: 'containers',
      label: 'Containers & SBOM',
      icon: Layers,
      badge: containers.length > 0 ? `${containers.length} pods` : null,
      badgeColor: 'bg-cyan-950 text-cyan-400 border-cyan-800'
    },
    {
      id: 'cve',
      label: 'CVE & NVD Feed',
      icon: Database,
      badge: overview?.cve_summary?.critical ? `${overview.cve_summary.critical} Crit` : null,
      badgeColor: 'bg-rose-950 text-rose-400 border-rose-800'
    },
    {
      id: 'runtime',
      label: 'Approach A: Runtime eBPF',
      icon: Activity,
      badge: criticalEventsCount > 0 ? `${criticalEventsCount} Alerts` : null,
      badgeColor: 'bg-rose-950 text-rose-400 border-rose-800 animate-pulse'
    },
    {
      id: 'llm',
      label: 'Approach B: Garak LLM Scan',
      icon: Cpu,
      badge: failedProbesCount > 0 ? `${failedProbesCount} Breaches` : null,
      badgeColor: 'bg-purple-950 text-purple-400 border-purple-800'
    },
    {
      id: 'correlation',
      label: 'Unified Correlation Core',
      icon: GitMerge,
      badge: 'Novelty',
      badgeColor: 'bg-indigo-950 text-indigo-300 border-indigo-700'
    },
    {
      id: 'ai-remediation',
      label: 'AI Auto-Patch & Copilot',
      icon: Sparkles,
      badge: 'AI Powered',
      badgeColor: 'bg-emerald-950 text-emerald-400 border-emerald-800'
    },
    {
      id: 'devops',
      label: 'DevOps & Alert Dispatch',
      icon: Send,
      badge: 'Slack/Git',
      badgeColor: 'bg-slate-900 text-slate-400 border-slate-700'
    },
  ];

  return (
    <div className="w-full border-b border-cyan-500/10 bg-slate-950/60 backdrop-blur-md px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto flex items-center gap-1 overflow-x-auto py-2.5 no-scrollbar">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-mono font-medium transition-all whitespace-nowrap cursor-pointer ${
                isActive
                  ? 'bg-cyan-950/90 text-cyan-300 border border-cyan-500/40 cyber-glow-cyan shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
              }`}
            >
              <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
              <span>{tab.label}</span>
              {tab.badge && (
                <span className={`text-[10px] px-1.5 py-0.2 rounded border font-mono ${tab.badgeColor}`}>
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
}
