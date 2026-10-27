/**
 * Frontend REST API client for DDoS Detection & Mitigation Engine.
 * Uses native fetch with clean error handling and json parsing.
 */

const API_BASE = '/api';

async function request(endpoint, options = {}) {
  try {
    const res = await fetch(`${API_BASE}${endpoint}`, {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      },
      ...options
    });

    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      throw new Error(errBody.error || `HTTP error ${res.status}`);
    }

    return await res.json();
  } catch (err) {
    console.warn(`[API Error] ${endpoint}:`, err.message);
    throw err;
  }
}

export const api = {
  // Telemetry & Stats
  getStats: () => request('/stats'),
  getTraffic: (filter = 'all', search = '', limit = 100) => 
    request(`/traffic?filter=${encodeURIComponent(filter)}&search=${encodeURIComponent(search)}&limit=${limit}`),
  getHistory: () => request('/traffic/history'),
  getThreatLevel: () => request('/threat-level'),

  // Alerts
  getAlerts: (filter = 'all') => request(`/alerts?filter=${encodeURIComponent(filter)}`),
  resolveAlert: (id) => request('/alerts/resolve', { method: 'POST', body: JSON.stringify({ id }) }),
  resolveAllAlerts: () => request('/alerts/resolve-all', { method: 'POST' }),

  // Simulation Controls
  startSimulation: () => request('/simulation/start', { method: 'POST' }),
  stopSimulation: () => request('/simulation/stop', { method: 'POST' }),
  resetSimulation: () => request('/simulation/reset', { method: 'POST' }),
  setMode: (mode) => request('/simulation/mode', { method: 'POST', body: JSON.stringify({ mode }) }),
  updateThresholds: (thresholds) => request('/simulation/thresholds', { method: 'POST', body: JSON.stringify(thresholds) }),

  // Mitigation
  getMitigationRules: () => request('/mitigation/rules'),
  getMitigationLogs: (limit = 50) => request(`/mitigation/logs?limit=${limit}`),
  getMitigationStats: () => request('/mitigation/stats'),
  blockIP: (ip, reason, durationSeconds = 0) => 
    request('/mitigation/block', { method: 'POST', body: JSON.stringify({ ip, reason, durationSeconds }) }),
  unblockIP: (ip) => request('/mitigation/unblock', { method: 'POST', body: JSON.stringify({ ip }) }),
  setRateLimiting: (enabled, threshold) => 
    request('/mitigation/rate-limit', { method: 'POST', body: JSON.stringify({ enabled, threshold }) }),
  setTrafficFiltering: (enabled) => 
    request('/mitigation/filter', { method: 'POST', body: JSON.stringify({ enabled }) }),
  setSynCookie: (enabled) => 
    request('/mitigation/syn-cookie', { method: 'POST', body: JSON.stringify({ enabled }) }),

  // Incidents (Phase 4 & 6)
  getIncidents: (status = 'ALL', severity = 'ALL', search = '') =>
    request(`/incidents?status=${encodeURIComponent(status)}&severity=${encodeURIComponent(severity)}&search=${encodeURIComponent(search)}`),
  getIncidentById: (id) => request(`/incidents/${encodeURIComponent(id)}`),
  updateIncidentStatus: (id, status, note, author) =>
    request(`/incidents/${encodeURIComponent(id)}/status`, { method: 'POST', body: JSON.stringify({ status, note, author }) }),
  addIncidentNote: (id, note, author) =>
    request(`/incidents/${encodeURIComponent(id)}/notes`, { method: 'POST', body: JSON.stringify({ note, author }) }),
  getIncidentExportUrl: (id) => `${API_BASE}/incidents/${encodeURIComponent(id)}/export/csv`,
  getAllIncidentsExportUrl: () => `${API_BASE}/incidents/export/csv`,
  getIncidentReportUrl: (id) => `${API_BASE}/incidents/${encodeURIComponent(id)}/report`,

  // Evaluation & Benchmarking (Phase 5)
  getBenchmark: () => request('/evaluation/benchmark'),
  runBenchmark: () => request('/evaluation/run', { method: 'POST' })
};
