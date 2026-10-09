import { useState, useEffect, useCallback, createContext, useContext } from 'react';
import { api } from '../services/api';
import confetti from 'canvas-confetti';

const VulnContext = createContext(null);

export function VulnProvider({ children }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [overview, setOverview] = useState(null);
  const [containers, setContainers] = useState([]);
  const [selectedContainerId, setSelectedContainerId] = useState('cnt-payment-01');
  const [cves, setCves] = useState([]);
  const [runtimeEvents, setRuntimeEvents] = useState([]);
  const [llmTargets, setLlmTargets] = useState([]);
  const [llmProbes, setLlmProbes] = useState([]);
  const [remediations, setRemediations] = useState([]);
  const [integrationSettings, setIntegrationSettings] = useState(null);
  const [dispatchedAlerts, setDispatchedAlerts] = useState([]);
  const [isCopilotOpen, setIsCopilotOpen] = useState(false);
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [toastMessage, setToastMessage] = useState(null);
  const [latestRuntimeScanReport, setLatestRuntimeScanReport] = useState(null);
  const [isAutoScanning, setIsAutoScanning] = useState(true);
  const [isDynamicScanning, setIsDynamicScanning] = useState(false);

  // Trigger cyber audio sound effect
  const playCyberSound = useCallback((type = 'beep') => {
    if (!soundEnabled) return;
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);

      if (type === 'alert') {
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(880, ctx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(220, ctx.currentTime + 0.3);
        gain.gain.setValueAtTime(0.15, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.3);
        osc.start();
        osc.stop(ctx.currentTime + 0.3);
      } else if (type === 'success') {
        osc.type = 'sine';
        osc.frequency.setValueAtTime(440, ctx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(880, ctx.currentTime + 0.2);
        gain.gain.setValueAtTime(0.1, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.2);
        osc.start();
        osc.stop(ctx.currentTime + 0.2);
      } else {
        osc.type = 'sine';
        osc.frequency.setValueAtTime(587.33, ctx.currentTime);
        gain.gain.setValueAtTime(0.05, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.08);
        osc.start();
        osc.stop(ctx.currentTime + 0.08);
      }
    } catch (e) {
      // Audio context might be restricted before user gesture
    }
  }, [soundEnabled]);

  const showToast = useCallback((msg, type = 'info') => {
    setToastMessage({ text: msg, type, id: Date.now() });
    if (type === 'error' || type === 'alert') playCyberSound('alert');
    else if (type === 'success') playCyberSound('success');
    else playCyberSound('beep');
    setTimeout(() => setToastMessage(null), 4000);
  }, [playCyberSound]);

  const refreshAll = useCallback(async () => {
    try {
      const [ov, cnts, cveList, events, targets, probes, rems, settings, alerts] = await Promise.allSettled([
        api.getOverview(),
        api.getContainers(),
        api.getAllCVEs(),
        api.getRuntimeEvents(),
        api.getLLMTargets(),
        api.getLLMProbes(),
        api.getRemediations(),
        api.getIntegrationSettings(),
        api.getAlertHistory()
      ]);

      if (ov.status === 'fulfilled') setOverview(ov.value);
      if (cnts.status === 'fulfilled') setContainers(cnts.value);
      if (cveList.status === 'fulfilled') setCves(cveList.value);
      if (events.status === 'fulfilled') setRuntimeEvents(events.value);
      if (targets.status === 'fulfilled') setLlmTargets(targets.value);
      if (probes.status === 'fulfilled') setLlmProbes(probes.value);
      if (rems.status === 'fulfilled') setRemediations(rems.value);
      if (settings.status === 'fulfilled') setIntegrationSettings(settings.value);
      if (alerts.status === 'fulfilled') setDispatchedAlerts(alerts.value);
    } catch (err) {
      console.error('Failed to sync state:', err);
    }
  }, []);

  // Initial load & periodic background telemetry polling
  useEffect(() => {
    refreshAll();
    const interval = setInterval(refreshAll, 6000);
    return () => clearInterval(interval);
  }, [refreshAll]);

  // Actions
  const handleSimulateAttack = async (containerId, attackType) => {
    setIsLoading(true);
    try {
      const res = await api.simulateAttack(containerId, attackType);
      showToast(`Dynamic Exploitation Simulated: ${attackType.toUpperCase()} triggered on ${containerId}!`, 'alert');
      await refreshAll();
      return res;
    } catch (err) {
      showToast(`Simulation failed: ${err.message}`, 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const handleIsolateContainer = async (containerId) => {
    setIsLoading(true);
    try {
      const res = await api.isolateContainer(containerId);
      showToast(`Container ${containerId} quarantined from cluster network.`, 'success');
      await refreshAll();
      return res;
    } catch (err) {
      showToast(`Isolation failed: ${err.message}`, 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const handleRestoreContainer = async (containerId) => {
    setIsLoading(true);
    try {
      const res = await api.restoreContainer(containerId);
      showToast(`Container ${containerId} restored to active cluster.`, 'success');
      await refreshAll();
      return res;
    } catch (err) {
      showToast(`Restore failed: ${err.message}`, 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const handleRunLLMProbe = async (targetId, probeName, customPayload) => {
    setIsLoading(true);
    try {
      const res = await api.runLLMProbe(targetId, probeName, customPayload);
      const passed = res.probe_result.passed;
      showToast(
        `Garak Probe Finished: ${res.probe_result.probe_name} -> ${passed ? 'PASSED (Shielded)' : 'FAILED (Vulnerable)'}`,
        passed ? 'success' : 'alert'
      );
      await refreshAll();
      return res;
    } catch (err) {
      showToast(`Probe failed: ${err.message}`, 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const handleApplyRemediation = async (planId) => {
    setIsLoading(true);
    try {
      const res = await api.applyRemediation(planId);
      confetti({ particleCount: 100, spread: 70, origin: { y: 0.6 } });
      showToast(`Remediation Plan ${planId} successfully deployed! Workload posture restored.`, 'success');
      await refreshAll();
      return res;
    } catch (err) {
      showToast(`Remediation failed: ${err.message}`, 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDispatchAlert = async (payload) => {
    try {
      const res = await api.dispatchAlert(payload);
      showToast(`Alert dispatched to ${payload.target.toUpperCase()} (Slack & GitHub)`, 'success');
      await refreshAll();
      return res;
    } catch (err) {
      showToast(`Dispatch failed: ${err.message}`, 'error');
    }
  };

  const handleScanContainerRuntime = async (containerId) => {
    setIsDynamicScanning(true);
    playCyberSound('beep');
    try {
      const res = await api.scanContainerRuntime(containerId);
      setLatestRuntimeScanReport(res);
      const risk = res.exploit_risk_score;
      showToast(
        `Dynamic Runtime Scan Complete: ${res.container_name} -> Exploit Risk: ${risk}% (${res.runtime_status})`,
        risk > 70 ? 'alert' : risk > 30 ? 'alert' : 'success'
      );
      await refreshAll();
      return res;
    } catch (err) {
      showToast(`Dynamic Runtime Scan failed: ${err.message}`, 'error');
    } finally {
      setIsDynamicScanning(false);
    }
  };

  const handleScanAllWorkloads = async () => {
    setIsDynamicScanning(true);
    playCyberSound('beep');
    try {
      const res = await api.scanAllWorkloadsRuntime();
      showToast(`Cluster-wide Dynamic Runtime Scan completed across ${res.length} workloads!`, 'success');
      if (res.length > 0) {
        const targetReport = res.find(r => r.container_id === selectedContainerId) || res[0];
        setLatestRuntimeScanReport(targetReport);
      }
      await refreshAll();
      return res;
    } catch (err) {
      showToast(`Cluster scan failed: ${err.message}`, 'error');
    } finally {
      setIsDynamicScanning(false);
    }
  };

  const handleKillPID = async (containerId, pid) => {
    setIsLoading(true);
    try {
      const res = await api.killProcessPID(containerId, pid);
      showToast(`SIGKILL dispatched: Rogue process PID ${pid} terminated.`, 'success');
      await handleScanContainerRuntime(containerId);
      await refreshAll();
      return res;
    } catch (err) {
      showToast(`Kill PID failed: ${err.message}`, 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const handleBlockSocket = async (containerId, remoteIp) => {
    setIsLoading(true);
    try {
      const res = await api.blockNetworkSocket(containerId, remoteIp);
      showToast(`eBPF Socket Blocked: Egress traffic to ${remoteIp} dropped.`, 'success');
      await handleScanContainerRuntime(containerId);
      await refreshAll();
      return res;
    } catch (err) {
      showToast(`Block socket failed: ${err.message}`, 'error');
    } finally {
      setIsLoading(false);
    }
  };

  // Continuous Dynamic Auto-Scan Interval
  useEffect(() => {
    if (!isAutoScanning || !selectedContainerId) return;
    const interval = setInterval(() => {
      api.scanContainerRuntime(selectedContainerId)
        .then((report) => {
          setLatestRuntimeScanReport(report);
        })
        .catch(() => {});
    }, 7000);
    return () => clearInterval(interval);
  }, [isAutoScanning, selectedContainerId]);

  const selectedContainer = containers.find((c) => c.id === selectedContainerId) || containers[0];

  return (
    <VulnContext.Provider
      value={{
        activeTab,
        setActiveTab,
        overview,
        containers,
        selectedContainerId,
        setSelectedContainerId,
        selectedContainer,
        cves,
        runtimeEvents,
        llmTargets,
        llmProbes,
        remediations,
        integrationSettings,
        dispatchedAlerts,
        isCopilotOpen,
        setIsCopilotOpen,
        soundEnabled,
        setSoundEnabled,
        isLoading,
        toastMessage,
        latestRuntimeScanReport,
        setLatestRuntimeScanReport,
        isAutoScanning,
        setIsAutoScanning,
        isDynamicScanning,
        showToast,
        playCyberSound,
        refreshAll,
        handleSimulateAttack,
        handleIsolateContainer,
        handleRestoreContainer,
        handleRunLLMProbe,
        handleApplyRemediation,
        handleDispatchAlert,
        handleScanContainerRuntime,
        handleScanAllWorkloads,
        handleKillPID,
        handleBlockSocket,
      }}
    >
      {children}
    </VulnContext.Provider>
  );
}

export function useVulnStore() {
  const context = useContext(VulnContext);
  if (!context) {
    throw new Error('useVulnStore must be used within a VulnProvider');
  }
  return context;
}
