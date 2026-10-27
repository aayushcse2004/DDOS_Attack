/**
 * DDoS Attack Detection and Mitigation Dashboard - Express Backend
 * Academic & Educational Defensive Cybersecurity Project
 */

const express = require('express');
const cors = require('cors');

const trafficEngine = require('./simulator/trafficEngine');
const detector = require('./detection/detector');
const mitigationManager = require('./mitigation/mitigationManager');
const incidentManager = require('./detection/incidentManager');
const evaluator = require('./evaluation/evaluator');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Request logging for debugging
app.use((req, res, next) => {
  if (req.method !== 'GET' || !req.url.startsWith('/api/stats')) {
    console.log(`[API] ${req.method} ${req.url}`);
  }
  next();
});

// --- System Telemetry & Stats APIs ---

app.get('/api/stats', (req, res) => {
  res.json({
    success: true,
    data: trafficEngine.getStats()
  });
});

app.get('/api/traffic', (req, res) => {
  const { filter = 'all', search = '', limit = 100 } = req.query;
  const packets = trafficEngine.getPackets(filter, search, limit);
  res.json({
    success: true,
    count: packets.length,
    data: packets
  });
});

app.get('/api/traffic/history', (req, res) => {
  res.json({
    success: true,
    data: trafficEngine.getTimeSeries()
  });
});

app.get('/api/threat-level', (req, res) => {
  const stats = trafficEngine.getStats();
  res.json({
    success: true,
    data: {
      threatLevel: stats.threatLevel,
      threatScore: stats.threatScore,
      badgeColor: stats.threatBadgeColor,
      description: stats.threatDescription,
      breakdown: stats.threatBreakdown,
      lastDetection: stats.lastDetection
    }
  });
});

// --- Alert System APIs ---

app.get('/api/alerts', (req, res) => {
  const { filter = 'all' } = req.query;
  res.json({
    success: true,
    data: detector.getAlerts(filter)
  });
});

app.post('/api/alerts/resolve', (req, res) => {
  const { id } = req.body;
  if (!id) {
    return res.status(400).json({ success: false, error: 'Alert ID is required.' });
  }
  const resolved = detector.resolveAlert(id);
  res.json({ success: resolved });
});

app.post('/api/alerts/resolve-all', (req, res) => {
  detector.resolveAllAlerts();
  res.json({ success: true, message: 'All active alerts marked resolved.' });
});

// --- Traffic Simulator Control APIs ---

app.post('/api/simulation/start', (req, res) => {
  trafficEngine.start();
  res.json({ success: true, isRunning: true, message: 'Simulation engine started.' });
});

app.post('/api/simulation/stop', (req, res) => {
  trafficEngine.stop();
  res.json({ success: true, isRunning: false, message: 'Simulation engine halted.' });
});

app.post('/api/simulation/reset', (req, res) => {
  trafficEngine.reset();
  res.json({ success: true, message: 'Simulation reset to pristine baseline state.' });
});

app.post('/api/simulation/mode', (req, res) => {
  const { mode } = req.body;
  const success = trafficEngine.setMode(mode);
  if (!success) {
    return res.status(400).json({
      success: false,
      error: 'Invalid mode. Allowed: normal, http_flood, syn_flood, udp_flood, icmp_flood, demo'
    });
  }
  res.json({ success: true, mode });
});

app.post('/api/simulation/thresholds', (req, res) => {
  const updated = detector.updateThresholds(req.body);
  res.json({ success: true, data: updated });
});

// --- Defensive Mitigation APIs ---

app.get('/api/mitigation/rules', (req, res) => {
  res.json({
    success: true,
    data: mitigationManager.getRules()
  });
});

app.post('/api/mitigation/block', (req, res) => {
  const { ip, reason, durationSeconds } = req.body;
  if (!ip) {
    return res.status(400).json({ success: false, error: 'IP address is required.' });
  }
  const rule = mitigationManager.blockIP(ip, reason || 'Manual SOC operator block', durationSeconds || 0);
  res.json({
    success: true,
    message: `IP ${ip} blocked successfully.${durationSeconds ? ` (TTL: ${durationSeconds}s)` : ''}`,
    rule,
    rules: mitigationManager.getRules()
  });
});

app.post('/api/mitigation/unblock', (req, res) => {
  const { ip } = req.body;
  if (!ip) {
    return res.status(400).json({ success: false, error: 'IP address is required.' });
  }
  const removed = mitigationManager.unblockIP(ip);
  res.json({
    success: removed,
    message: removed ? `IP ${ip} removed from blocklist.` : `IP ${ip} was not in blocklist.`,
    rules: mitigationManager.getRules()
  });
});

app.get('/api/mitigation/logs', (req, res) => {
  const { limit = 50 } = req.query;
  res.json({
    success: true,
    data: mitigationManager.getActionLogs(limit)
  });
});

app.get('/api/mitigation/stats', (req, res) => {
  res.json({
    success: true,
    data: mitigationManager.getTelemetry()
  });
});

app.post('/api/mitigation/rate-limit', (req, res) => {
  const { enabled, threshold } = req.body;
  const result = mitigationManager.setRateLimiting(enabled, threshold);
  res.json({
    success: true,
    data: result
  });
});

app.post('/api/mitigation/filter', (req, res) => {
  const { enabled } = req.body;
  const result = mitigationManager.setTrafficFiltering(enabled);
  res.json({
    success: true,
    data: result
  });
});

app.post('/api/mitigation/syn-cookie', (req, res) => {
  const { enabled } = req.body;
  const result = mitigationManager.setSynCookie(enabled);
  res.json({
    success: true,
    data: result
  });
});

// --- Incident Management APIs (Phases 4 & 6) ---

app.get('/api/incidents', (req, res) => {
  const { status = 'ALL', severity = 'ALL', search = '' } = req.query;
  const incidents = incidentManager.getIncidents({ status, severity, search });
  res.json({
    success: true,
    count: incidents.length,
    data: incidents
  });
});

app.get('/api/incidents/export/csv', (req, res) => {
  const csv = incidentManager.exportAllIncidentsCSV();
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="ddos-incidents-summary.csv"');
  res.send(csv);
});

app.get('/api/incidents/:id', (req, res) => {
  const incident = incidentManager.getIncidentById(req.params.id);
  if (!incident) {
    return res.status(404).json({ success: false, error: `Incident ${req.params.id} not found.` });
  }
  res.json({
    success: true,
    data: incident
  });
});

app.post('/api/incidents/:id/status', (req, res) => {
  const { status, note, author } = req.body;
  if (!status) {
    return res.status(400).json({ success: false, error: 'Status is required (OPEN, INVESTIGATING, MITIGATED, RESOLVED).' });
  }
  const updated = incidentManager.updateIncidentStatus(req.params.id, status, note, author);
  if (!updated) {
    return res.status(404).json({ success: false, error: `Incident ${req.params.id} not found.` });
  }
  res.json({
    success: true,
    message: `Incident ${req.params.id} updated to ${status}.`,
    data: updated
  });
});

app.post('/api/incidents/:id/notes', (req, res) => {
  const { note, author } = req.body;
  if (!note || !note.trim()) {
    return res.status(400).json({ success: false, error: 'Note text cannot be empty.' });
  }
  const updated = incidentManager.addNote(req.params.id, note.trim(), author || 'SOC Analyst');
  if (!updated) {
    return res.status(404).json({ success: false, error: `Incident ${req.params.id} not found.` });
  }
  res.json({
    success: true,
    data: updated
  });
});

app.get('/api/incidents/:id/export/csv', (req, res) => {
  const csv = incidentManager.exportIncidentCSV(req.params.id);
  if (!csv) {
    return res.status(404).json({ success: false, error: `Incident ${req.params.id} not found.` });
  }
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="${req.params.id}-forensics.csv"`);
  res.send(csv);
});

app.get('/api/incidents/:id/report', (req, res) => {
  const html = incidentManager.generateHtmlReport(req.params.id);
  res.setHeader('Content-Type', 'text/html');
  res.send(html);
});

// --- Benchmark & Scientific Evaluation APIs (Phase 5) ---

app.get('/api/evaluation/benchmark', (req, res) => {
  res.json({
    success: true,
    data: evaluator.getResults()
  });
});

app.post('/api/evaluation/run', (req, res) => {
  const results = evaluator.runBenchmark();
  res.json({
    success: true,
    message: 'Academic benchmark suite executed across labelled synthetic scenarios.',
    data: results
  });
});

// Global health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// 404 Handler for API routes
app.use('/api/*', (req, res) => {
  res.status(404).json({
    success: false,
    error: `Endpoint not found: ${req.method} ${req.baseUrl}`
  });
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('[Unhandled Server Error]', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error occurred.',
    message: err.message
  });
});

// Start Express Server
app.listen(PORT, () => {
  console.log(`[DDoS Shield Core] Backend server active on port ${PORT}`);
  console.log(`[DDoS Shield Core] REST API available at http://localhost:${PORT}/api/stats`);
});
