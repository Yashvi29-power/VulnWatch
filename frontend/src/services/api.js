/**
 * VulnWatch Frontend API Client
 * Connects to FastAPI Backend with full error handling and auto-reconnect
 */

const API_BASE = 'http://localhost:8000/api';

async function fetchJSON(endpoint, options = {}) {
  try {
    const res = await fetch(`${API_BASE}${endpoint}`, {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      ...options,
    });
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(errBody.detail || `Request failed with status ${res.status}`);
    }
    return await res.json();
  } catch (err) {
    console.warn(`API Error [${endpoint}]:`, err.message);
    throw err;
  }
}

export const api = {
  // Overview & Posture
  getOverview: () => fetchJSON('/overview'),

  // Containers
  getContainers: () => fetchJSON('/containers'),
  getContainer: (id) => fetchJSON(`/containers/${id}`),
  registerContainer: (name, image) =>
    fetchJSON(`/containers/register?name=${encodeURIComponent(name)}&image=${encodeURIComponent(image)}`, {
      method: 'POST',
    }),
  isolateContainer: (id) => fetchJSON(`/containers/${id}/isolate`, { method: 'POST' }),
  restoreContainer: (id) => fetchJSON(`/containers/${id}/restore`, { method: 'POST' }),

  // SBOM
  getSBOM: (containerId) => fetchJSON(`/containers/${containerId}/sbom`),
  getCycloneDX: (containerId) => fetchJSON(`/containers/${containerId}/sbom/cyclonedx`),
  getSPDX: (containerId) => fetchJSON(`/containers/${containerId}/sbom/spdx`),

  // CVE & NVD
  getContainerCVEs: (containerId) => fetchJSON(`/containers/${containerId}/cves`),
  getAllCVEs: () => fetchJSON('/cve/all'),
  searchCVEs: (query) => fetchJSON(`/cve/search?query=${encodeURIComponent(query)}`),

  // Approach A: Dynamic Runtime Vulnerability Scanner & eBPF
  getRuntimeEvents: (containerId, limit = 50) =>
    fetchJSON(`/runtime/events?${containerId ? `container_id=${containerId}&` : ''}limit=${limit}`),
  simulateAttack: (containerId, attackType) =>
    fetchJSON(`/runtime/simulate-attack?container_id=${encodeURIComponent(containerId)}&attack_type=${encodeURIComponent(attackType)}`, {
      method: 'POST',
    }),
  scanContainerRuntime: (containerId) =>
    fetchJSON(`/runtime/scan/${containerId}`, { method: 'POST' }),
  scanAllWorkloadsRuntime: () =>
    fetchJSON('/runtime/scan-all'),
  killProcessPID: (containerId, pid) =>
    fetchJSON(`/runtime/kill-pid/${containerId}/${pid}`, { method: 'POST' }),
  blockNetworkSocket: (containerId, remoteIp) =>
    fetchJSON(`/runtime/block-socket/${containerId}?remote_ip=${encodeURIComponent(remoteIp)}`, { method: 'POST' }),

  // Approach B: Dynamic LLM Safety
  getLLMTargets: () => fetchJSON('/llm/targets'),
  getLLMProbes: (targetId) => fetchJSON(`/llm/probes${targetId ? `?target_id=${targetId}` : ''}`),
  runLLMProbe: (targetId, probeName, customPayload) =>
    fetchJSON('/llm/run-probe', {
      method: 'POST',
      body: JSON.stringify({
        target_id: targetId,
        probe_name: probeName,
        custom_payload: customPayload,
      }),
    }),
  runLLMSuite: (targetId) =>
    fetchJSON(`/llm/run-suite?target_id=${encodeURIComponent(targetId)}`, { method: 'POST' }),

  // AI Security Copilot & Remediation
  chatAI: (message, containerId, contextType = 'general') =>
    fetchJSON('/ai/chat', {
      method: 'POST',
      body: JSON.stringify({ message, container_id: containerId, context_type: contextType }),
    }),
  generateRemediation: (containerId, cveId) =>
    fetchJSON(`/ai/remediation/generate?container_id=${encodeURIComponent(containerId)}${cveId ? `&cve_id=${encodeURIComponent(cveId)}` : ''}`, {
      method: 'POST',
    }),
  getRemediations: () => fetchJSON('/remediations'),
  applyRemediation: (planId) => fetchJSON(`/ai/remediation/${planId}/apply`, { method: 'POST' }),

  // DevOps Integrations
  getIntegrationSettings: () => fetchJSON('/integrations/settings'),
  updateIntegrationSettings: (settings) =>
    fetchJSON('/integrations/settings', { method: 'POST', body: JSON.stringify(settings) }),
  dispatchAlert: (payload) =>
    fetchJSON('/integrations/dispatch', { method: 'POST', body: JSON.stringify(payload) }),
  getAlertHistory: () => fetchJSON('/integrations/alerts'),
};
