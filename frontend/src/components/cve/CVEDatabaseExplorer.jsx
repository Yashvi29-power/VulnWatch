import React, { useState } from 'react';
import { useVulnStore } from '../../state/useVulnStore';
import { api } from '../../services/api';
import { 
  Database, Search, ShieldAlert, AlertTriangle, 
  ExternalLink, Zap, Flame, CheckCircle, RefreshCw 
} from 'lucide-react';

export default function CVEDatabaseExplorer() {
  const { cves, setActiveTab, showToast } = useVulnStore();
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState(null);
  const [isSearching, setIsSearching] = useState(false);

  const handleSearchNVD = async (e) => {
    e.preventDefault();
    if (!searchQuery.trim()) {
      setSearchResults(null);
      return;
    }
    setIsSearching(true);
    try {
      const res = await api.searchCVEs(searchQuery.trim());
      setSearchResults(res);
      showToast(`Found ${res.length} matching vulnerabilities in NVD & OSV Feed`, 'success');
    } catch (err) {
      showToast(`NVD Search error: ${err.message}`, 'error');
    } finally {
      setIsSearching(false);
    }
  };

  const displayList = searchResults || cves;

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      
      {/* Header & Live NVD Search */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="font-orbitron font-bold text-lg text-white flex items-center gap-2">
            <Database className="w-5 h-5 text-rose-400" />
            <span>NATIONAL VULNERABILITY DATABASE (NVD) & CVE FEED</span>
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Real-time CVE polling, CPE-based matching, and EPSS Exploitability Probability Scoring
          </p>
        </div>

        {/* Live NVD Query Form */}
        <form onSubmit={handleSearchNVD} className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search CVE ID, package, or keyword..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9 pr-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs font-mono text-white placeholder:text-slate-500 focus:border-cyan-400 outline-none w-72"
            />
          </div>
          <button
            type="submit"
            disabled={isSearching}
            className="px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-orbitron font-bold text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            {isSearching ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
            <span>POLL NVD</span>
          </button>
        </form>
      </div>

      {/* EPSS Highlights Banner */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl cyber-glass-card border border-rose-500/30">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-mono text-slate-400">HIGHEST EPSS PROBABILITY</span>
            <Flame className="w-4 h-4 text-rose-400 animate-pulse" />
          </div>
          <div className="font-orbitron text-xl font-bold text-rose-400">97.4%</div>
          <p className="text-[11px] font-mono text-slate-300 mt-1">
            Log4Shell (CVE-2021-44228) — Actively exploited in wild
          </p>
        </div>

        <div className="p-4 rounded-xl cyber-glass-card border border-amber-500/30">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-mono text-slate-400">RCE & PRIV-ESC MATCHES</span>
            <ShieldAlert className="w-4 h-4 text-amber-400" />
          </div>
          <div className="font-orbitron text-xl font-bold text-amber-400">4 Critical</div>
          <p className="text-[11px] font-mono text-slate-300 mt-1">
            Spring4Shell, Sudo Baron Samedit, LangChain RCE
          </p>
        </div>

        <div className="p-4 rounded-xl cyber-glass-card border border-cyan-500/30">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-mono text-slate-400">AI AUTO-PATCHABLE</span>
            <Zap className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="font-orbitron text-xl font-bold text-cyan-400">100% Fixed</div>
          <p className="text-[11px] font-mono text-slate-300 mt-1">
            Direct Dockerfile & package diff remediation available
          </p>
        </div>
      </div>

      {/* CVE Records Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {displayList.map((cve) => {
          const isCritical = cve.severity === 'CRITICAL' || cve.cvss_score >= 9.0;
          const epssPct = cve.epss_score ? Math.round(cve.epss_score * 100) : 75;

          return (
            <div
              key={cve.cve_id}
              className={`cyber-glass-card rounded-xl p-5 border transition-all ${
                isCritical ? 'border-rose-500/30 hover:border-rose-500/60' : 'border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-start justify-between gap-2 mb-2">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-orbitron font-bold text-sm text-cyan-300">{cve.cve_id}</span>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded font-mono ${
                      isCritical ? 'bg-rose-500 text-black' : 'bg-amber-500 text-black'
                    }`}>
                      CVSS {cve.cvss_score}
                    </span>
                  </div>
                  <h4 className="font-semibold text-xs text-white mt-1 leading-snug">
                    {cve.title || cve.cve_id}
                  </h4>
                </div>

                {cve.exploit_available && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 flex items-center gap-1 shrink-0">
                    <Flame className="w-3 h-3 text-rose-400" />
                    Exploit In Wild
                  </span>
                )}
              </div>

              <p className="text-xs text-slate-300 font-mono line-clamp-2 my-2 leading-relaxed">
                {cve.description}
              </p>

              {/* Package & Fixed Version */}
              <div className="grid grid-cols-2 gap-2 p-2.5 rounded-lg bg-slate-950/70 border border-slate-800/80 text-[11px] font-mono my-3">
                <div>
                  <span className="text-slate-500 block">Affected Package:</span>
                  <span className="text-rose-400 font-bold">{cve.affected_package || 'Dynamic match'}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Fixed Version:</span>
                  <span className="text-emerald-400 font-bold">{cve.fixed_version || 'Upgrade available'}</span>
                </div>
              </div>

              {/* EPSS Exploitability Probability Meter */}
              {cve.epss_score !== undefined && (
                <div className="space-y-1 mb-3 text-xs font-mono">
                  <div className="flex items-center justify-between text-slate-400">
                    <span>EPSS Exploitability Index:</span>
                    <strong className={epssPct > 70 ? 'text-rose-400' : 'text-amber-400'}>{epssPct}%</strong>
                  </div>
                  <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${epssPct > 70 ? 'bg-rose-500' : 'bg-amber-500'}`}
                      style={{ width: `${epssPct}%` }}
                    />
                  </div>
                </div>
              )}

              {/* Runtime Vector & AI Remediation Action */}
              <div className="flex items-center justify-between pt-2 border-t border-slate-800/80">
                <span className="text-[10px] font-mono text-slate-400 truncate max-w-[200px]">
                  Vector: {cve.runtime_vector || 'Network Socket / RCE'}
                </span>

                <button
                  onClick={() => setActiveTab('ai-remediation')}
                  className="px-3 py-1 rounded-lg bg-cyan-950 hover:bg-cyan-900 border border-cyan-500/40 text-cyan-300 text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <Zap className="w-3 h-3 text-cyan-400" />
                  <span>Generate AI Patch</span>
                </button>
              </div>
            </div>
          );
        })}
      </div>

    </div>
  );
}
