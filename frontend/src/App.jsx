import React from 'react';
import { VulnProvider, useVulnStore } from './state/useVulnStore';
import Navbar from './components/layout/Navbar';
import NavTabs from './components/layout/NavTabs';
import OverviewDashboard from './components/dashboard/OverviewDashboard';
import ContainerManager from './components/containers/ContainerManager';
import CVEDatabaseExplorer from './components/cve/CVEDatabaseExplorer';
import RuntimeSyscallMonitor from './components/runtime/RuntimeSyscallMonitor';
import GarakLLMScanner from './components/llm/GarakLLMScanner';
import UnifiedCorrelationMatrix from './components/correlation/UnifiedCorrelationMatrix';
import AIRemediationView from './components/ai/AIRemediationView';
import DevOpsIntegrations from './components/integrations/DevOpsIntegrations';
import { ShieldCheck, Heart, Terminal, Sparkles } from 'lucide-react';

function DashboardContent() {
  const { activeTab, setActiveTab } = useVulnStore();

  const renderActiveView = () => {
    switch (activeTab) {
      case 'overview':
        return <OverviewDashboard />;
      case 'containers':
        return <ContainerManager />;
      case 'cve':
        return <CVEDatabaseExplorer />;
      case 'runtime':
        return <RuntimeSyscallMonitor />;
      case 'llm':
        return <GarakLLMScanner />;
      case 'correlation':
        return <UnifiedCorrelationMatrix />;
      case 'ai-remediation':
        return <AIRemediationView />;
      case 'devops':
        return <DevOpsIntegrations />;
      default:
        return <OverviewDashboard />;
    }
  };

  return (
    <div className="min-h-screen bg-[#050811] text-slate-100 flex flex-col cyber-grid-bg selection:bg-cyan-500 selection:text-black">
      {/* Top Futuristic HUD Header */}
      <Navbar />

      {/* Navigation HUD Tabs */}
      <NavTabs />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {renderActiveView()}
      </main>

      {/* Futuristic Cyber Footer */}
      <footer className="w-full border-t border-cyan-500/10 bg-slate-950/80 py-4 px-4 sm:px-6 lg:px-8 mt-12 text-xs font-mono text-slate-400">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="font-orbitron font-bold text-cyan-400">VULNWATCH</span>
            <span>• Continuous Vulnerability Monitoring & Runtime Behavior Analysis</span>
          </div>

          <div className="flex items-center gap-3 text-slate-400">
            <span>Domain: <strong className="text-slate-300">CyberSecurity & DevOps</strong></span>
            <span>|</span>
            <span>SGP Sem 5 Team: <strong className="text-cyan-300">24DCS136, 24DCS076, 24DCS089, 24DCS098</strong></span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default function App() {
  return (
    <VulnProvider>
      <DashboardContent />
    </VulnProvider>
  );
}
