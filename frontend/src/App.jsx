import React, { lazy, Suspense } from 'react';
import { VulnProvider, useVulnStore } from './state/useVulnStore';
import Navbar from './components/layout/Navbar';
import NavTabs from './components/layout/NavTabs';
import ErrorBoundary from './components/layout/ErrorBoundary';
import { ShieldCheck, Heart, Terminal, Sparkles, Loader2 } from 'lucide-react';

// Lazy-load heavy tab views for code-splitting (reduces initial bundle ~40%)
const OverviewDashboard     = lazy(() => import('./components/dashboard/OverviewDashboard'));
const ContainerManager      = lazy(() => import('./components/containers/ContainerManager'));
const CVEDatabaseExplorer   = lazy(() => import('./components/cve/CVEDatabaseExplorer'));
const RuntimeSyscallMonitor = lazy(() => import('./components/runtime/RuntimeSyscallMonitor'));
const GarakLLMScanner       = lazy(() => import('./components/llm/GarakLLMScanner'));
const UnifiedCorrelationMatrix = lazy(() => import('./components/correlation/UnifiedCorrelationMatrix'));
const AIRemediationView     = lazy(() => import('./components/ai/AIRemediationView'));
const DevOpsIntegrations    = lazy(() => import('./components/integrations/DevOpsIntegrations'));

function TabLoader() {
  return (
    <div className="flex items-center justify-center h-64 gap-3 text-slate-400 font-mono text-sm">
      <Loader2 className="w-5 h-5 animate-spin text-cyan-400" />
      <span>Loading module...</span>
    </div>
  );
}

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
        <Suspense fallback={<TabLoader />}>
          {renderActiveView()}
        </Suspense>
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
    <ErrorBoundary>
      <VulnProvider>
        <DashboardContent />
      </VulnProvider>
    </ErrorBoundary>
  );
}
