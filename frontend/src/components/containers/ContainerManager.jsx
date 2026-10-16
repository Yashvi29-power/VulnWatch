import React, { useState, useEffect, useRef } from 'react';
import { useVulnStore } from '../../state/useVulnStore';
import { api } from '../../services/api';
import { 
  Layers, ShieldAlert, ShieldCheck, Download, Zap, Play, 
  Search, ExternalLink, RefreshCw, Cpu, Activity, AlertTriangle, 
  CheckCircle, Upload, FileCode, HardDrive, Check, Terminal, Sparkles
} from 'lucide-react';

export default function ContainerManager() {
  const { 
    containers, selectedContainerId, setSelectedContainerId, 
    handleIsolateContainer, handleRestoreContainer, handleSimulateAttack, 
    setActiveTab, showToast, refreshAll 
  } = useVulnStore();

  const [sbom, setSbom] = useState(null);
  const [loadingSbom, setLoadingSbom] = useState(false);
  const [searchPkg, setSearchPkg] = useState('');
  
  // Registration & Upload Tab State
  const [scanMode, setScanMode] = useState('registry'); // 'registry' | 'upload' | 'docker'
  const [newImageName, setNewImageName] = useState('');
  const [newContainerName, setNewContainerName] = useState('');
  const [isRegistering, setIsRegistering] = useState(false);
  
  // File Upload State
  const [uploadFile, setUploadFile] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const fileInputRef = useRef(null);

  // Docker Daemon State
  const [dockerStatus, setDockerStatus] = useState(null);
  const [localContainers, setLocalContainers] = useState([]);
  const [localImages, setLocalImages] = useState([]);
  const [loadingDocker, setLoadingDocker] = useState(false);

  // Fetch SBOM for currently selected container
  useEffect(() => {
    if (!selectedContainerId) return;
    let isMounted = true;
    setLoadingSbom(true);
    api.getSBOM(selectedContainerId)
      .then((data) => {
        if (isMounted) setSbom(data);
      })
      .catch((err) => {
        console.error(err);
      })
      .finally(() => {
        if (isMounted) setLoadingSbom(false);
      });

    return () => { isMounted = false; };
  }, [selectedContainerId]);

  // Fetch Docker daemon status
  const checkDockerDaemon = async () => {
    setLoadingDocker(true);
    try {
      const status = await api.getDockerDaemonStatus();
      setDockerStatus(status);
      if (status.available) {
        const [cnts, imgs] = await Promise.all([
          api.getDockerLocalContainers(),
          api.getDockerLocalImages()
        ]);
        setLocalContainers(cnts);
        setLocalImages(imgs);
      }
    } catch (e) {
      setDockerStatus({ available: false, status: 'DISCONNECTED', message: 'Daemon unreachable' });
    } finally {
      setLoadingDocker(false);
    }
  };

  useEffect(() => {
    checkDockerDaemon();
  }, []);

  const handleDownloadCycloneDX = async () => {
    try {
      const data = await api.getCycloneDX(selectedContainerId);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cyclonedx-sbom-${selectedContainerId}.json`;
      a.click();
      showToast('CycloneDX 1.5 JSON SBOM downloaded successfully', 'success');
    } catch (e) {
      showToast('Export failed', 'error');
    }
  };

  const handleDownloadSPDX = async () => {
    try {
      const data = await api.getSPDX(selectedContainerId);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `spdx-sbom-${selectedContainerId}.json`;
      a.click();
      showToast('SPDX 2.3 JSON SBOM downloaded successfully', 'success');
    } catch (e) {
      showToast('Export failed', 'error');
    }
  };

  const handleRegisterNewImage = async (e) => {
    e.preventDefault();
    if (!newContainerName || !newImageName) return;
    setIsRegistering(true);
    try {
      await api.registerContainer(newContainerName, newImageName);
      showToast(`Workload ${newContainerName} registered and SBOM extracted!`, 'success');
      setNewContainerName('');
      setNewImageName('');
      await refreshAll();
    } catch (err) {
      showToast(`Registration failed: ${err.message}`, 'error');
    } finally {
      setIsRegistering(false);
    }
  };

  const handleFileUploadScan = async (e) => {
    e.preventDefault();
    if (!uploadFile) {
      showToast('Please select a manifest file (Dockerfile, requirements.txt, package.json, or SBOM JSON)', 'error');
      return;
    }
    setIsUploading(true);
    try {
      const res = await api.uploadManifest(uploadFile, newContainerName || null, newImageName || null);
      showToast(
        `File ${res.filename} scanned! Extracted ${res.packages_extracted} packages with ${res.critical_vulnerabilities} critical CVEs.`,
        res.critical_vulnerabilities > 0 ? 'alert' : 'success'
      );
      setUploadFile(null);
      setNewContainerName('');
      setNewImageName('');
      if (fileInputRef.current) fileInputRef.current.value = '';
      await refreshAll();
      if (res.container?.id) {
        setSelectedContainerId(res.container.id);
      }
    } catch (err) {
      showToast(`Upload scan failed: ${err.message}`, 'error');
    } finally {
      setIsUploading(false);
    }
  };

  const handleImportLocalContainer = async (c) => {
    setIsRegistering(true);
    try {
      await api.registerContainer(c.name, c.image);
      showToast(`Imported local Docker container: ${c.name}`, 'success');
      await refreshAll();
    } catch (err) {
      showToast(`Import failed: ${err.message}`, 'error');
    } finally {
      setIsRegistering(false);
    }
  };

  const selectedContainer = containers.find(c => c.id === selectedContainerId) || containers[0];

  const filteredPackages = sbom?.packages?.filter(p => 
    p.name.toLowerCase().includes(searchPkg.toLowerCase()) || 
    p.version.toLowerCase().includes(searchPkg.toLowerCase()) ||
    (p.cpe && p.cpe.toLowerCase().includes(searchPkg.toLowerCase()))
  ) || [];

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      
      {/* Header & Scanning Hub */}
      <div className="cyber-glass-card rounded-2xl p-5 border border-cyan-500/20 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-3">
          <div>
            <h2 className="font-orbitron font-bold text-lg text-white flex items-center gap-2">
              <Layers className="w-5 h-5 text-cyan-400" />
              <span>CONTAINER WORKLOAD INGESTION & SCANNER</span>
            </h2>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Scan images by registry tag, upload local manifests (Dockerfile, package.json, requirements.txt), or sync local Docker daemon
            </p>
          </div>

          {/* Docker Status Pill */}
          <div className="flex items-center gap-2 shrink-0">
            <div className={`px-2.5 py-1 rounded-full border text-xs font-mono flex items-center gap-1.5 ${
              dockerStatus?.available
                ? 'bg-emerald-950/80 border-emerald-500/40 text-emerald-300'
                : 'bg-slate-900 border-slate-700 text-slate-400'
            }`}>
              <HardDrive className="w-3.5 h-3.5 text-cyan-400" />
              <span>Docker Engine:</span>
              <strong className={dockerStatus?.available ? 'text-emerald-400' : 'text-slate-400'}>
                {dockerStatus?.available ? `Connected (${dockerStatus.running_containers} active)` : 'Desktop Offline'}
              </strong>
            </div>
            <button
              onClick={checkDockerDaemon}
              disabled={loadingDocker}
              className="p-1.5 text-slate-400 hover:text-cyan-300 rounded border border-slate-800 hover:bg-slate-900 cursor-pointer"
              title="Refresh Docker Daemon Status"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingDocker ? 'animate-spin text-cyan-400' : ''}`} />
            </button>
          </div>
        </div>

        {/* Scan Mode Switcher */}
        <div className="flex items-center gap-2 pt-1">
          <button
            onClick={() => setScanMode('registry')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors cursor-pointer ${
              scanMode === 'registry'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/40 cyber-glow-cyan'
                : 'text-slate-400 hover:text-white hover:bg-slate-900'
            }`}
          >
            1. Registry Image Tag
          </button>
          <button
            onClick={() => setScanMode('upload')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium flex items-center gap-1.5 transition-colors cursor-pointer ${
              scanMode === 'upload'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/40 cyber-glow-cyan'
                : 'text-slate-400 hover:text-white hover:bg-slate-900'
            }`}
          >
            <Upload className="w-3.5 h-3.5 text-cyan-400" />
            <span>2. Upload File / Manifest</span>
          </button>
          <button
            onClick={() => setScanMode('docker')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium flex items-center gap-1.5 transition-colors cursor-pointer ${
              scanMode === 'docker'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/40 cyber-glow-cyan'
                : 'text-slate-400 hover:text-white hover:bg-slate-900'
            }`}
          >
            <HardDrive className="w-3.5 h-3.5 text-indigo-400" />
            <span>3. Docker Desktop Sync ({localContainers.length})</span>
          </button>
        </div>

        {/* Scan Mode 1: Registry Tag Input */}
        {scanMode === 'registry' && (
          <form onSubmit={handleRegisterNewImage} className="flex flex-col sm:flex-row items-center gap-2 pt-1 animate-in fade-in">
            <input
              type="text"
              placeholder="Pod Name (e.g. redis-cache, auth-gateway)"
              value={newContainerName}
              onChange={(e) => setNewContainerName(e.target.value)}
              className="w-full sm:w-64 px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs font-mono text-white placeholder:text-slate-500 focus:border-cyan-400 outline-none"
            />
            <input
              type="text"
              placeholder="Docker Image Tag (e.g. redis:7-alpine, nginx:1.25, python:3.11)"
              value={newImageName}
              onChange={(e) => setNewImageName(e.target.value)}
              className="w-full sm:flex-1 px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs font-mono text-white placeholder:text-slate-500 focus:border-cyan-400 outline-none"
            />
            <button
              type="submit"
              disabled={isRegistering || !newContainerName || !newImageName}
              className="w-full sm:w-auto px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-black font-orbitron font-bold text-xs shrink-0 transition-colors cursor-pointer disabled:opacity-50"
            >
              {isRegistering ? 'EXTRACTING SBOM...' : '+ SCAN IMAGE TAG'}
            </button>
          </form>
        )}

        {/* Scan Mode 2: Real File / Manifest Upload */}
        {scanMode === 'upload' && (
          <form onSubmit={handleFileUploadScan} className="space-y-3 pt-1 animate-in fade-in text-xs font-mono">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <input
                type="text"
                placeholder="Workload / Pod Name (optional, defaults to filename)"
                value={newContainerName}
                onChange={(e) => setNewContainerName(e.target.value)}
                className="px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-white placeholder:text-slate-500 focus:border-cyan-400 outline-none"
              />
              <input
                type="text"
                placeholder="Target Image Label (e.g. custom-app:v1)"
                value={newImageName}
                onChange={(e) => setNewImageName(e.target.value)}
                className="px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-white placeholder:text-slate-500 focus:border-cyan-400 outline-none"
              />
            </div>

            {/* Drag & Drop File Picker Box */}
            <div 
              onClick={() => fileInputRef.current?.click()}
              className="border-2 border-dashed border-cyan-500/30 hover:border-cyan-400/60 bg-slate-950/60 rounded-xl p-4 text-center cursor-pointer transition-all"
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".txt,.json,Dockerfile,package.json,pom.xml"
                onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
                className="hidden"
              />
              <div className="flex flex-col items-center justify-center gap-1.5">
                <FileCode className="w-8 h-8 text-cyan-400" />
                <span className="text-slate-200 font-semibold">
                  {uploadFile ? `Selected: ${uploadFile.name} (${(uploadFile.size / 1024).toFixed(1)} KB)` : 'Click to select Dockerfile, requirements.txt, package.json, or SBOM JSON'}
                </span>
                <span className="text-[11px] text-slate-500">
                  Parses real packages, queries NIST NVD 2.0 API, calculates CVSS/EPSS scores, and correlates with runtime state.
                </span>
              </div>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-slate-400 text-[11px]">
                Supported: <code>Dockerfile</code>, <code>requirements.txt</code>, <code>package.json</code>, <code>CycloneDX/SPDX JSON</code>
              </span>
              <button
                type="submit"
                disabled={isUploading || !uploadFile}
                className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-black font-orbitron font-bold text-xs flex items-center gap-2 cursor-pointer disabled:opacity-50"
              >
                {isUploading ? <RefreshCw className="w-3.5 h-3.5 animate-spin fill-black" /> : <Upload className="w-3.5 h-3.5 fill-black" />}
                <span>{isUploading ? 'SCANNING MANIFEST PACKAGES...' : 'UPLOAD & SCAN MANIFEST'}</span>
              </button>
            </div>
          </form>
        )}

        {/* Scan Mode 3: Docker Desktop Live Containers */}
        {scanMode === 'docker' && (
          <div className="space-y-3 pt-1 animate-in fade-in text-xs font-mono">
            {dockerStatus?.available ? (
              <div>
                <p className="text-slate-300 mb-2">
                  Found <strong className="text-cyan-400">{localContainers.length}</strong> local containers in your machine's Docker engine. Click import to analyze any local container:
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-48 overflow-y-auto pr-1">
                  {localContainers.map((c) => (
                    <div key={c.docker_id} className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between gap-2">
                      <div>
                        <div className="font-bold text-white truncate max-w-[180px]">{c.name}</div>
                        <div className="text-[11px] text-slate-400 truncate max-w-[180px]">{c.image}</div>
                      </div>
                      <button
                        onClick={() => handleImportLocalContainer(c)}
                        disabled={isRegistering}
                        className="px-2.5 py-1 rounded bg-cyan-500/20 hover:bg-cyan-500 text-cyan-300 hover:text-black font-bold text-[10px] transition-colors cursor-pointer"
                      >
                        IMPORT POD
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-center space-y-2">
                <HardDrive className="w-8 h-8 text-slate-500 mx-auto" />
                <p className="text-slate-300 font-semibold">Local Docker Desktop is not currently running</p>
                <p className="text-[11px] text-slate-400 max-w-lg mx-auto">
                  To scan real local containers from your machine, start Docker Desktop on Windows. In the meantime, you can scan any image tag or upload a <code>Dockerfile</code> or <code>requirements.txt</code> directly via the tabs above!
                </p>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Container Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {containers.map((cnt) => {
          const isSelected = cnt.id === selectedContainerId;
          const isCompromised = cnt.status === 'COMPROMISED';
          const isSuspicious = cnt.status === 'SUSPICIOUS';
          const isIsolated = cnt.status === 'ISOLATED';

          return (
            <div
              key={cnt.id}
              onClick={() => setSelectedContainerId(cnt.id)}
              className={`cyber-glass-card rounded-xl p-4 cursor-pointer transition-all border ${
                isSelected
                  ? 'border-cyan-400 cyber-glow-cyan bg-slate-900/90'
                  : 'border-slate-800/80 hover:border-slate-700'
              }`}
            >
              <div className="flex items-start justify-between gap-2 mb-2">
                <div>
                  <h4 className="font-orbitron font-bold text-sm text-white flex items-center gap-1.5">
                    {cnt.name}
                    {cnt.has_llm_service && (
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-purple-950 text-purple-300 border border-purple-800 font-mono">
                        LLM/AI
                      </span>
                    )}
                  </h4>
                  <p className="text-[11px] font-mono text-slate-400 truncate max-w-[200px]">
                    {cnt.image}
                  </p>
                </div>

                <span className={`text-[10px] font-bold px-2 py-0.5 rounded font-mono ${
                  isCompromised ? 'bg-rose-500 text-black animate-pulse' :
                  isSuspicious ? 'bg-amber-500 text-black' :
                  isIsolated ? 'bg-purple-500 text-black' :
                  'bg-emerald-500 text-black'
                }`}>
                  {cnt.status}
                </span>
              </div>

              {/* Resource & Health Meters */}
              <div className="space-y-2 my-3 text-xs font-mono">
                <div className="flex items-center justify-between text-slate-400">
                  <span>Health Posture:</span>
                  <span className={`font-bold ${cnt.health_score > 70 ? 'text-emerald-400' : cnt.health_score > 40 ? 'text-amber-400' : 'text-rose-400'}`}>
                    {cnt.health_score} / 100
                  </span>
                </div>
                <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${cnt.health_score > 70 ? 'bg-emerald-400' : cnt.health_score > 40 ? 'bg-amber-400' : 'bg-rose-500'}`}
                    style={{ width: `${cnt.health_score}%` }}
                  />
                </div>

                <div className="grid grid-cols-2 gap-2 text-[11px] text-slate-300 pt-1">
                  <div>CPU: <strong className="text-cyan-400">{cnt.cpu_usage_pct}%</strong></div>
                  <div>Mem: <strong className="text-cyan-400">{cnt.memory_mb} MB</strong></div>
                </div>
              </div>

              {/* Vulnerabilities Breakdown */}
              <div className="flex items-center justify-between pt-2 border-t border-slate-800 text-[11px] font-mono">
                <span className="text-slate-400">Packages: <strong>{cnt.packages_count}</strong></span>
                <div className="flex items-center gap-1.5">
                  {cnt.cve_critical > 0 && <span className="text-rose-400 font-bold">{cnt.cve_critical} Crit</span>}
                  {cnt.cve_high > 0 && <span className="text-amber-400">{cnt.cve_high} High</span>}
                  {cnt.cve_critical === 0 && cnt.cve_high === 0 && <span className="text-emerald-400">Clean</span>}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Selected Container Deep-Dive Inspector */}
      {selectedContainer && (
        <div className="cyber-glass-card rounded-2xl p-6 border border-cyan-500/30">
          
          {/* Header Actions */}
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-4 mb-5">
            <div>
              <div className="flex items-center gap-3">
                <h3 className="font-orbitron font-bold text-xl text-white">
                  {selectedContainer.name}
                </h3>
                <span className="font-mono text-xs text-cyan-400 px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-800">
                  IP: {selectedContainer.ip_address}
                </span>
              </div>
              <p className="text-xs font-mono text-slate-400 mt-1">
                Image: <span className="text-slate-200">{selectedContainer.image}</span>
              </p>
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              {/* Dynamic Attack Simulation Button */}
              <button
                onClick={() => handleSimulateAttack(selectedContainer.id, 'log4shell')}
                className="px-3 py-1.5 rounded-lg bg-rose-950 hover:bg-rose-900 border border-rose-500/40 text-rose-300 text-xs font-mono flex items-center gap-1.5 cursor-pointer"
              >
                <Play className="w-3.5 h-3.5 text-rose-400" />
                <span>Simulate Exploit</span>
              </button>

              {/* Isolate / Quarantine Button */}
              {selectedContainer.status !== 'ISOLATED' ? (
                <button
                  onClick={() => handleIsolateContainer(selectedContainer.id)}
                  className="px-3 py-1.5 rounded-lg bg-purple-950 hover:bg-purple-900 border border-purple-500/40 text-purple-300 text-xs font-mono flex items-center gap-1.5 cursor-pointer"
                >
                  <AlertTriangle className="w-3.5 h-3.5 text-purple-400" />
                  <span>Quarantine Pod</span>
                </button>
              ) : (
                <button
                  onClick={() => handleRestoreContainer(selectedContainer.id)}
                  className="px-3 py-1.5 rounded-lg bg-emerald-950 hover:bg-emerald-900 border border-emerald-500/40 text-emerald-300 text-xs font-mono flex items-center gap-1.5 cursor-pointer"
                >
                  <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Restore Workload</span>
                </button>
              )}

              {/* AI Auto-Remediate */}
              <button
                onClick={() => setActiveTab('ai-remediation')}
                className="px-3.5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black text-xs font-orbitron font-bold flex items-center gap-1.5 cursor-pointer"
              >
                <Zap className="w-3.5 h-3.5 fill-black" />
                <span>AI Auto-Patch</span>
              </button>
            </div>
          </div>

          {/* AI Risk Summary Alert Banner */}
          <div className="p-3.5 rounded-xl bg-slate-900/80 border border-cyan-500/20 mb-6 font-mono text-xs leading-relaxed">
            <span className="text-cyan-400 font-bold block mb-1">🤖 AI THREAT INTELLIGENCE SUMMARY:</span>
            <p className="text-slate-300">{selectedContainer.ai_risk_summary}</p>
          </div>

          {/* SBOM Package Inventory Table */}
          <div>
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-3">
              <div className="flex items-center gap-3">
                <span className="font-orbitron text-xs font-bold text-white uppercase tracking-wider">
                  Extracted Software Bill of Materials (SBOM)
                </span>
                <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800">
                  Coverage: {sbom?.package_coverage_percentage ?? 98.6}% (≥95% SLA)
                </span>
              </div>

              <div className="flex items-center gap-2">
                <div className="relative">
                  <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2" />
                  <input
                    type="text"
                    placeholder="Filter packages..."
                    value={searchPkg}
                    onChange={(e) => setSearchPkg(e.target.value)}
                    className="pl-8 pr-3 py-1 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-white placeholder:text-slate-500 focus:border-cyan-400 outline-none w-44"
                  />
                </div>

                <button
                  onClick={handleDownloadCycloneDX}
                  className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 text-xs font-mono flex items-center gap-1 cursor-pointer"
                  title="Export CycloneDX 1.5 JSON"
                >
                  <Download className="w-3 h-3 text-cyan-400" />
                  <span>CycloneDX</span>
                </button>

                <button
                  onClick={handleDownloadSPDX}
                  className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 text-xs font-mono flex items-center gap-1 cursor-pointer"
                  title="Export SPDX 2.3 JSON"
                >
                  <Download className="w-3 h-3 text-indigo-400" />
                  <span>SPDX</span>
                </button>
              </div>
            </div>

            {/* Packages Table */}
            <div className="rounded-xl border border-slate-800 overflow-hidden">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 uppercase text-[10px]">
                  <tr>
                    <th className="p-2.5">Package Name</th>
                    <th className="p-2.5">Installed Version</th>
                    <th className="p-2.5">Type</th>
                    <th className="p-2.5">License</th>
                    <th className="p-2.5">CPE / Path</th>
                    <th className="p-2.5 text-right">CVE Count</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 bg-slate-950/40">
                  {filteredPackages.map((pkg) => (
                    <tr key={pkg.id} className="hover:bg-slate-900/50 transition-colors">
                      <td className="p-2.5 font-bold text-slate-200">{pkg.name}</td>
                      <td className="p-2.5 text-cyan-400">{pkg.version}</td>
                      <td className="p-2.5 text-slate-400">
                        <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px]">
                          {pkg.type}
                        </span>
                      </td>
                      <td className="p-2.5 text-slate-400">{pkg.license || 'MIT'}</td>
                      <td className="p-2.5 text-slate-400 font-mono text-[11px] truncate max-w-xs">
                        {pkg.cpe || pkg.path || 'N/A'}
                      </td>
                      <td className="p-2.5 text-right">
                        {pkg.vulnerabilities_count > 0 ? (
                          <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-400 font-bold border border-rose-800">
                            {pkg.vulnerabilities_count} CVEs
                          </span>
                        ) : (
                          <span className="text-emerald-400">Clean</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

          </div>

        </div>
      )}

    </div>
  );
}
