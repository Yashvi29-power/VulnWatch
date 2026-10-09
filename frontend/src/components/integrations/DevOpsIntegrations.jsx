import React, { useState } from 'react';
import { useVulnStore } from '../../state/useVulnStore';
import { api } from '../../services/api';
import { 
  Send, ShieldAlert, CheckCircle2, ExternalLink, 
  Bell, Settings, RefreshCw, AlertTriangle, MessageSquare, GitBranch 
} from 'lucide-react';

// Custom Crisp Brand Icons
const SlackIcon = ({ className = "w-4 h-4" }) => (
  <svg className={className} viewBox="0 0 24 24" fill="currentColor">
    <path d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zM6.313 15.165a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313zM8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52H8.834zM8.834 6.313a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312zM18.956 8.834a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zM17.688 8.834a2.528 2.528 0 0 1-2.523 2.521 2.527 2.527 0 0 1-2.52-2.521V2.522A2.527 2.527 0 0 1 15.165 0a2.528 2.528 0 0 1 2.523 2.522v6.312zM15.165 18.956a2.528 2.528 0 0 1 2.523 2.522A2.528 2.528 0 0 1 15.165 24a2.527 2.527 0 0 1-2.52-2.522v-2.522h2.52zM15.165 17.688a2.527 2.527 0 0 1-2.52-2.523 2.526 2.526 0 0 1 2.52-2.52h6.313A2.527 2.527 0 0 1 24 15.165a2.528 2.528 0 0 1-2.522 2.523h-6.313z"/>
  </svg>
);

const GitHubIcon = ({ className = "w-4 h-4" }) => (
  <svg className={className} viewBox="0 0 24 24" fill="currentColor">
    <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
  </svg>
);

export default function DevOpsIntegrations() {
  const { 
    integrationSettings, dispatchedAlerts, handleDispatchAlert, 
    containers, selectedContainerId, showToast 
  } = useVulnStore();

  const [slackUrl, setSlackUrl] = useState(integrationSettings?.slack_webhook_url || '');
  const [slackChannel, setSlackChannel] = useState(integrationSettings?.slack_channel || '#security-alerts');
  const [githubRepo, setGithubRepo] = useState(integrationSettings?.github_repo || 'yashv-org/vulnwatch-monitored-app');
  const [isSaving, setIsSaving] = useState(false);
  const [isDispatching, setIsDispatching] = useState(false);

  // Dispatch custom alert form state
  const [alertTitle, setAlertTitle] = useState('Log4Shell JNDI RCE Exploit Detected');
  const [alertSeverity, setAlertSeverity] = useState('CRITICAL');
  const [alertTarget, setAlertTarget] = useState('all');
  const [alertDetails, setAlertDetails] = useState('Runtime eBPF agent confirmed unauthorized /bin/sh child spawn and outbound C2 socket connection on port 4444.');

  const handleSaveSettings = async (e) => {
    e.preventDefault();
    setIsSaving(true);
    try {
      await api.updateIntegrationSettings({
        slack_webhook_url: slackUrl,
        slack_channel: slackChannel,
        slack_enabled: true,
        github_repo: githubRepo,
        github_token_configured: true,
        github_auto_issue: true,
        min_alert_severity: 'HIGH'
      });
      showToast('DevOps integration parameters saved successfully', 'success');
    } catch (err) {
      showToast(`Save failed: ${err.message}`, 'error');
    } finally {
      setIsSaving(false);
    }
  };

  const handleTriggerDispatch = async (e) => {
    e.preventDefault();
    setIsDispatching(true);
    try {
      const selectedCnt = containers.find(c => c.id === selectedContainerId) || containers[0];
      await handleDispatchAlert({
        target: alertTarget,
        title: alertTitle,
        severity: alertSeverity,
        container_name: selectedCnt?.name || 'payment-gateway-service',
        cve_id: 'CVE-2021-44228',
        details: alertDetails,
        remediation: 'Quarantine container and execute automated Temurin JDK 17 Dockerfile patch.'
      });
    } finally {
      setIsDispatching(false);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      
      {/* Header */}
      <div>
        <h2 className="font-orbitron font-bold text-lg text-white flex items-center gap-2">
          <Send className="w-5 h-5 text-cyan-400" />
          <span>AUTOMATED RESPONSE & DEVOPS INTEGRATIONS</span>
        </h2>
        <p className="text-xs text-slate-400 font-mono mt-0.5">
          Automated alert dispatch to Slack and GitHub Issues for both traditional container CVEs and AI/LLM findings
        </p>
      </div>

      {/* 2 Column Grid: Integration Settings & Live Test Dispatcher */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Left Col: Slack & GitHub Config */}
        <div className="cyber-glass-card rounded-2xl p-6 border border-cyan-500/20 space-y-5">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="font-orbitron font-bold text-sm text-white flex items-center gap-2">
              <Settings className="w-4 h-4 text-cyan-400" />
              <span>INTEGRATION CREDENTIALS</span>
            </h3>
            <span className="text-xs font-mono text-emerald-400 flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> Ready & Active
            </span>
          </div>

          <form onSubmit={handleSaveSettings} className="space-y-4 text-xs font-mono">
            {/* Slack Section */}
            <div className="space-y-2 p-3.5 rounded-xl bg-slate-900/60 border border-slate-800">
              <div className="flex items-center gap-2 text-cyan-300 font-bold">
                <SlackIcon className="w-4 h-4 text-cyan-400" />
                <span>Slack Webhook Integration</span>
              </div>
              <div>
                <label className="text-slate-400 block mb-1">Incoming Webhook URL:</label>
                <input
                  type="text"
                  placeholder="https://hooks.slack.com/services/..."
                  value={slackUrl}
                  onChange={(e) => setSlackUrl(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-200 outline-none focus:border-cyan-400"
                />
              </div>
              <div>
                <label className="text-slate-400 block mb-1">Alert Channel:</label>
                <input
                  type="text"
                  value={slackChannel}
                  onChange={(e) => setSlackChannel(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-200 outline-none focus:border-cyan-400"
                />
              </div>
            </div>

            {/* GitHub Section */}
            <div className="space-y-2 p-3.5 rounded-xl bg-slate-900/60 border border-slate-800">
              <div className="flex items-center gap-2 text-indigo-300 font-bold">
                <GitHubIcon className="w-4 h-4 text-indigo-400" />
                <span>GitHub Issues Auto-Creation</span>
              </div>
              <div>
                <label className="text-slate-400 block mb-1">Target Repository (org/repo):</label>
                <input
                  type="text"
                  value={githubRepo}
                  onChange={(e) => setGithubRepo(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-200 outline-none focus:border-cyan-400"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isSaving}
              className="w-full py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-black font-orbitron font-bold text-xs transition-colors cursor-pointer"
            >
              {isSaving ? 'SAVING CONFIGURATION...' : 'SAVE INTEGRATION SETTINGS'}
            </button>
          </form>
        </div>

        {/* Right Col: Instant Alert Dispatch Tester */}
        <div className="cyber-glass-card rounded-2xl p-6 border border-rose-500/20 space-y-5">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="font-orbitron font-bold text-sm text-white flex items-center gap-2">
              <Bell className="w-4 h-4 text-rose-400" />
              <span>DISPATCH LIVE SECURITY ALERT</span>
            </h3>
            <span className="text-[11px] font-mono text-slate-400">SLA Latency: &lt; 1.2 min</span>
          </div>

          <form onSubmit={handleTriggerDispatch} className="space-y-3.5 text-xs font-mono">
            <div>
              <label className="text-slate-400 block mb-1">Alert Incident Title:</label>
              <input
                type="text"
                value={alertTitle}
                onChange={(e) => setAlertTitle(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 outline-none focus:border-cyan-400"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-slate-400 block mb-1">Severity Level:</label>
                <select
                  value={alertSeverity}
                  onChange={(e) => setAlertSeverity(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-rose-400 font-bold outline-none focus:border-cyan-400"
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Dispatch Target:</label>
                <select
                  value={alertTarget}
                  onChange={(e) => setAlertTarget(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-cyan-300 outline-none focus:border-cyan-400"
                >
                  <option value="all">Slack + GitHub (All)</option>
                  <option value="slack">Slack Webhook Only</option>
                  <option value="github">GitHub Issues Only</option>
                </select>
              </div>
            </div>

            <div>
              <label className="text-slate-400 block mb-1">Technical Incident Details & Evidence:</label>
              <textarea
                rows={3}
                value={alertDetails}
                onChange={(e) => setAlertDetails(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 outline-none focus:border-cyan-400 resize-none"
              />
            </div>

            <button
              type="submit"
              disabled={isDispatching}
              className="w-full py-2.5 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-orbitron font-bold text-xs flex items-center justify-center gap-2 transition-colors cursor-pointer"
            >
              {isDispatching ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
              <span>DISPATCH DEVOPS ALERT</span>
            </button>
          </form>
        </div>

      </div>

      {/* Dispatched Alerts History Log */}
      <div className="cyber-glass-card rounded-2xl p-6 border border-cyan-500/20">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
          <div className="flex items-center gap-2">
            <Bell className="w-5 h-5 text-cyan-400" />
            <h3 className="font-orbitron font-bold text-sm text-white">
              DISPATCHED ALERTS & GITHUB ISSUES AUDIT LOG
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-400">
            Total Dispatched: <strong className="text-cyan-300">{dispatchedAlerts.length}</strong>
          </span>
        </div>

        <div className="space-y-3">
          {dispatchedAlerts.map((alt) => (
            <div
              key={alt.id}
              className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 text-xs font-mono space-y-2"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                    alt.severity === 'CRITICAL' ? 'bg-rose-500 text-black' : 'bg-amber-500 text-black'
                  }`}>
                    {alt.severity}
                  </span>
                  <span className="font-orbitron text-xs text-white font-bold">{alt.title}</span>
                  <span className="text-slate-400">[{alt.container_name}]</span>
                </div>

                <div className="flex items-center gap-3 text-slate-400 text-[11px]">
                  <span>{alt.timestamp}</span>
                  {alt.slack_sent && (
                    <span className="text-emerald-400 flex items-center gap-1">
                      <SlackIcon className="w-3 h-3 text-emerald-400" /> Slack Sent
                    </span>
                  )}
                  {alt.github_created && (
                    <span className="text-indigo-400 flex items-center gap-1">
                      <GitHubIcon className="w-3 h-3 text-indigo-400" /> Issue Created
                    </span>
                  )}
                </div>
              </div>

              <p className="text-slate-300 text-[11px] leading-relaxed">
                {alt.details}
              </p>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
