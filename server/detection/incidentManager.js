/**
 * Incident Management Module (Phase 4 & Phase 6)
 * Stores full incident forensics, timelines, investigation notes, and generates CSV & printable reports.
 */

class IncidentManager {
  constructor() {
    this.incidents = [];
    this.maxIncidents = 100;

    // Seed realistic forensic incidents so analysts immediately have data to explore
    this.seedHistoricalIncidents();
  }

  seedHistoricalIncidents() {
    const now = Date.now();
    const pastIncidents = [
      {
        id: 'INC-2026-0941',
        title: 'Distributed Layer 7 HTTP POST Flood on Authentication Gateway',
        attackType: 'HTTP Flood',
        severity: 'CRITICAL',
        status: 'RESOLVED',
        startTime: new Date(now - 7200000).toISOString(),
        endTime: new Date(now - 6900000).toISOString(),
        durationSeconds: 300,
        peakRps: 840,
        peakZScore: 5.4,
        volumeMB: 28.5,
        sourceIps: ['192.168.1.101', '192.168.1.102', '172.16.9.50'],
        targetAsset: { ip: '192.168.1.1', hostname: 'enterprise-core-gateway', service: 'HTTP/HTTPS Auth' },
        detectionReasons: [
          'Aggregate traffic rate (840 req/s) breached safety threshold (500 req/s).',
          'Statistical Anomaly: Traffic velocity surged +120% over moving baseline with Z-Score of +5.4.',
          'High-density requests concentrated on /api/v1/auth/login bypassing static page caching.'
        ],
        mitigationStatus: {
          actionTaken: 'IP_BLOCK_AND_RATE_LIMIT',
          rulesEnforced: ['Blocked 192.168.1.101 (Manual SOC)', 'Enforced Sliding-Window Rate Limit at 80 req/s'],
          mitigatedAt: new Date(now - 7080000).toISOString()
        },
        timeline: [
          { timestamp: new Date(now - 7200000).toISOString(), event: 'ATTACK_ONSET', description: 'Sudden velocity surge detected from multiple external IPs' },
          { timestamp: new Date(now - 7195000).toISOString(), event: 'DETECTION_TRIGGER', description: 'IDS flagged Z-Score +5.4 statistical anomaly and RPS threshold breach' },
          { timestamp: new Date(now - 7140000).toISOString(), event: 'SEVERITY_ESCALATION', description: 'Escalated to CRITICAL due to concurrent endpoint latency' },
          { timestamp: new Date(now - 7080000).toISOString(), event: 'MITIGATION_APPLIED', description: 'Rate limit enforced at 80 req/s; primary attacker IP blacklisted' },
          { timestamp: new Date(now - 6900000).toISOString(), event: 'INCIDENT_RESOLVED', description: 'Traffic normalized below baseline; incident marked resolved' }
        ],
        investigationNotes: [
          { timestamp: new Date(now - 7100000).toISOString(), author: 'SOC Lead Analyst', note: 'Botnet signature identified mimicking mobile user agents. Applied perimeter drops.' },
          { timestamp: new Date(now - 6900000).toISOString(), author: 'SecOps Engineer', note: 'Post-incident review complete. Normal baseline verified.' }
        ]
      },
      {
        id: 'INC-2026-0938',
        title: 'TCP SYN Handshake Exhaustion Attack on Core HTTPS Border',
        attackType: 'SYN Flood',
        severity: 'HIGH',
        status: 'MITIGATED',
        startTime: new Date(now - 14400000).toISOString(),
        endTime: new Date(now - 14100000).toISOString(),
        durationSeconds: 300,
        peakRps: 620,
        peakZScore: 4.1,
        volumeMB: 8.2,
        sourceIps: ['10.0.4.15', '10.0.4.18', '10.0.4.22'],
        targetAsset: { ip: '192.168.1.1', hostname: 'enterprise-core-gateway', service: 'HTTPS Port 443' },
        detectionReasons: [
          'TCP State Table Exhaustion: Disproportionate SYN-to-ACK ratio of 86.4% detected.',
          'Over 400 unacknowledged half-open TCP handshakes saturating connection backlog.'
        ],
        mitigationStatus: {
          actionTaken: 'SYN_COOKIE_ACTIVATION',
          rulesEnforced: ['Activated TCP SYN Cookie challenge filter', 'Blocked subnet 10.0.4.15'],
          mitigatedAt: new Date(now - 14350000).toISOString()
        },
        timeline: [
          { timestamp: new Date(now - 14400000).toISOString(), event: 'ATTACK_ONSET', description: 'Flurry of SYN flags observed without subsequent ACK packets' },
          { timestamp: new Date(now - 14380000).toISOString(), event: 'DETECTION_TRIGGER', description: 'TCP asymmetry trigger tripped at 86.4% SYN-ACK ratio' },
          { timestamp: new Date(now - 14350000).toISOString(), event: 'MITIGATION_APPLIED', description: 'SYN Cookies enabled; half-open backlog memory deallocated' },
          { timestamp: new Date(now - 14100000).toISOString(), event: 'STATUS_UPDATE', description: 'Attack dampened; continuing observation in MITIGATED state' }
        ],
        investigationNotes: [
          { timestamp: new Date(now - 14300000).toISOString(), author: 'Network SecOps', note: 'SYN Cookies successfully contained connection table exhaustion.' }
        ]
      }
    ];

    this.incidents = pastIncidents;
  }

  /**
   * Syncs active alert into a correlated incident record
   */
  syncFromAlert(alert) {
    if (!alert || !alert.id) return null;

    let incident = this.incidents.find(inc => inc.relatedAlertId === alert.id || inc.id === alert.incidentId);

    const now = new Date().toISOString();

    if (!incident) {
      incident = {
        id: `INC-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 900 + 100)}`,
        relatedAlertId: alert.id,
        title: alert.title || `Security Incident: ${alert.attackType || 'Volumetric'} Activity`,
        attackType: alert.attackType || 'Volumetric Flood',
        severity: alert.severity || 'HIGH',
        status: alert.status === 'resolved' ? 'RESOLVED' : 'OPEN',
        startTime: alert.timestamp || now,
        endTime: alert.status === 'resolved' ? (alert.resolvedAt || now) : null,
        durationSeconds: alert.durationSeconds || 1,
        peakRps: alert.peakRps || alert.currentRps || 0,
        peakZScore: alert.peakZScore || 0,
        volumeMB: alert.volumeMB || 0,
        sourceIps: alert.offendingIPs || [],
        targetAsset: { ip: '192.168.1.1', hostname: 'enterprise-core-gateway', service: 'Core Border Gateway' },
        detectionReasons: alert.detailedReasons || [alert.reason || 'Telemetry breach'],
        mitigationStatus: {
          actionTaken: 'EVALUATION_ACTIVE',
          rulesEnforced: [],
          mitigatedAt: null
        },
        timeline: [
          { timestamp: alert.timestamp || now, event: 'INCIDENT_CREATED', description: `Alert ${alert.id} ingested by Incident Management System` }
        ],
        investigationNotes: [
          { timestamp: now, author: 'IDS Automation', note: `Automated forensic correlation initiated for ${alert.attackType}.` }
        ]
      };
      this.incidents.unshift(incident);
      if (this.incidents.length > this.maxIncidents) this.incidents.pop();
    } else {
      // Update existing incident
      incident.durationSeconds = alert.durationSeconds || incident.durationSeconds;
      incident.peakRps = Math.max(incident.peakRps || 0, alert.peakRps || alert.currentRps || 0);
      incident.peakZScore = Math.max(incident.peakZScore || 0, alert.peakZScore || 0);
      if (alert.volumeMB) incident.volumeMB = Math.max(incident.volumeMB, alert.volumeMB);
      if (alert.offendingIPs) {
        incident.sourceIps = Array.from(new Set([...incident.sourceIps, ...alert.offendingIPs])).slice(0, 10);
      }
      if (alert.detailedReasons) incident.detectionReasons = alert.detailedReasons;
      if (alert.status === 'resolved' && incident.status !== 'RESOLVED') {
        incident.status = 'RESOLVED';
        incident.endTime = alert.resolvedAt || now;
        incident.timeline.push({
          timestamp: now,
          event: 'INCIDENT_RESOLVED',
          description: 'Incident marked resolved following attack mitigation or cessation'
        });
      }
    }

    return incident;
  }

  getIncidents(filter = {}) {
    let list = this.incidents;

    if (filter.status && filter.status !== 'ALL') {
      list = list.filter(i => i.status.toUpperCase() === filter.status.toUpperCase());
    }

    if (filter.severity && filter.severity !== 'ALL') {
      list = list.filter(i => i.severity.toUpperCase() === filter.severity.toUpperCase());
    }

    if (filter.search && filter.search.trim()) {
      const q = filter.search.toLowerCase();
      list = list.filter(i =>
        i.id.toLowerCase().includes(q) ||
        i.title.toLowerCase().includes(q) ||
        i.attackType.toLowerCase().includes(q) ||
        i.sourceIps.some(ip => ip.toLowerCase().includes(q))
      );
    }

    return list;
  }

  getIncidentById(id) {
    if (!id) return null;
    return this.incidents.find(i => i.id === id || i.relatedAlertId === id) || null;
  }

  updateIncidentStatus(id, newStatus, note, author = 'SOC Operator') {
    const incident = this.getIncidentById(id);
    if (!incident) return null;

    const prevStatus = incident.status;
    incident.status = newStatus;
    const now = new Date().toISOString();

    if (newStatus === 'RESOLVED' && !incident.endTime) {
      incident.endTime = now;
    }

    incident.timeline.push({
      timestamp: now,
      event: 'STATUS_CHANGE',
      description: `Status updated from ${prevStatus} to ${newStatus}${note ? `: ${note}` : ''}`
    });

    if (note) {
      incident.investigationNotes.push({
        timestamp: now,
        author,
        note
      });
    }

    return incident;
  }

  addNote(id, note, author = 'SOC Analyst') {
    const incident = this.getIncidentById(id);
    if (!incident) return null;

    const newNote = {
      timestamp: new Date().toISOString(),
      author,
      note
    };

    incident.investigationNotes.push(newNote);
    incident.timeline.push({
      timestamp: newNote.timestamp,
      event: 'INVESTIGATION_NOTE',
      description: `Note added by ${author}: ${note.substring(0, 60)}${note.length > 60 ? '...' : ''}`
    });

    return incident;
  }

  /**
   * Export single incident as RFC-4180 compliant CSV string
   */
  exportIncidentCSV(id) {
    const inc = this.getIncidentById(id);
    if (!inc) return null;

    const escape = (val) => {
      const s = String(val === null || val === undefined ? '' : val);
      return `"${s.replace(/"/g, '""')}"`;
    };

    const rows = [
      ['INCIDENT_METADATA', 'VALUE'],
      ['Incident ID', inc.id],
      ['Title', inc.title],
      ['Attack Vector', inc.attackType],
      ['Severity Level', inc.severity],
      ['Status', inc.status],
      ['Start Time', inc.startTime],
      ['End Time', inc.endTime || 'Ongoing'],
      ['Duration (Seconds)', inc.durationSeconds],
      ['Peak Ingress Rate (RPS)', inc.peakRps],
      ['Peak Anomaly Z-Score', inc.peakZScore],
      ['Volume (MB)', inc.volumeMB],
      ['Target Gateway IP', inc.targetAsset?.ip || '192.168.1.1'],
      ['Target Service', inc.targetAsset?.service || 'Core Gateway'],
      ['Offending Source IPs', inc.sourceIps.join('; ')],
      ['Detection Reasons', inc.detectionReasons.join(' | ')],
      ['Mitigation Rules', inc.mitigationStatus?.rulesEnforced?.join('; ') || 'None'],
      ['', ''],
      ['TIMELINE_TIMESTAMP', 'EVENT_TYPE', 'DESCRIPTION']
    ];

    inc.timeline.forEach(t => {
      rows.push([t.timestamp, t.event, t.description]);
    });

    rows.push(['', '', '']);
    rows.push(['NOTE_TIMESTAMP', 'AUTHOR', 'INVESTIGATION_NOTE']);

    inc.investigationNotes.forEach(n => {
      rows.push([n.timestamp, n.author, n.note]);
    });

    return rows.map(r => r.map(escape).join(',')).join('\r\n');
  }

  /**
   * Export all incidents as a summary CSV string
   */
  exportAllIncidentsCSV() {
    const escape = (val) => {
      const s = String(val === null || val === undefined ? '' : val);
      return `"${s.replace(/"/g, '""')}"`;
    };

    const headers = [
      'Incident ID',
      'Title',
      'Attack Type',
      'Severity',
      'Status',
      'Start Time',
      'End Time',
      'Duration (s)',
      'Peak RPS',
      'Peak Z-Score',
      'Volume (MB)',
      'Source IPs',
      'Primary Detection Reason'
    ];

    const rows = [headers];

    this.incidents.forEach(inc => {
      rows.push([
        inc.id,
        inc.title,
        inc.attackType,
        inc.severity,
        inc.status,
        inc.startTime,
        inc.endTime || 'Ongoing',
        inc.durationSeconds,
        inc.peakRps,
        inc.peakZScore,
        inc.volumeMB,
        inc.sourceIps.join('; '),
        inc.detectionReasons[0] || 'Nominal'
      ]);
    });

    return rows.map(r => r.map(escape).join(',')).join('\r\n');
  }

  /**
   * Generates a formal, printable HTML report dossier
   */
  generateHtmlReport(id) {
    const inc = this.getIncidentById(id);
    if (!inc) return '<h3>Incident not found</h3>';

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Forensic Incident Report - ${inc.id}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; color: #1e293b; line-height: 1.5; padding: 30px; max-width: 900px; margin: auto; }
    .header { border-bottom: 3px solid #0284c7; padding-bottom: 15px; margin-bottom: 25px; display: flex; justify-content: space-between; align-items: center; }
    .title { font-size: 20px; font-weight: bold; color: #0f172a; margin: 0; }
    .badge { padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: bold; }
    .badge-CRITICAL { background: #fee2e2; color: #b91c1c; border: 1px solid #f87171; }
    .badge-HIGH { background: #fef3c7; color: #b45309; border: 1px solid #fbbf24; }
    .badge-MEDIUM { background: #fef9c3; color: #854d0e; border: 1px solid #fde047; }
    .badge-LOW { background: #dcfce7; color: #15803d; border: 1px solid #86efac; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 20px; }
    .card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 15px; }
    .card h4 { margin: 0 0 8px 0; font-size: 12px; color: #64748b; text-transform: uppercase; }
    .card p { margin: 0; font-size: 14px; font-weight: 600; color: #0f172a; }
    table { width: 100%; border-collapse: collapse; margin-top: 15px; }
    th, td { border: 1px solid #e2e8f0; padding: 8px 12px; text-align: left; font-size: 13px; }
    th { background: #f1f5f9; color: #475569; }
    .reasons { background: #fff1f2; border: 1px solid #fecdd3; padding: 15px; border-radius: 6px; margin: 20px 0; }
    .reasons ul { margin: 5px 0 0 20px; padding: 0; }
    .timeline-item { border-left: 2px solid #0284c7; padding-left: 15px; margin-bottom: 12px; }
    .timeline-item .time { font-size: 11px; color: #64748b; }
    .timeline-item .event { font-weight: bold; font-size: 13px; color: #0f172a; }
    .timeline-item .desc { font-size: 12px; color: #334155; }
    @media print { body { padding: 0; } button { display: none; } }
  </style>
</head>
<body>
  <div style="text-align: right; margin-bottom: 10px;">
    <button onclick="window.print()" style="padding: 8px 16px; background: #0284c7; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;">Print / Save as PDF</button>
  </div>
  <div class="header">
    <div>
      <h1 class="title">CYBERSECURITY INCIDENT INVESTIGATION REPORT</h1>
      <div style="font-size: 12px; color: #64748b; margin-top: 4px;">DDoS Attack Detection & Mitigation Security Operations Center (SOC)</div>
    </div>
    <div>
      <span class="badge badge-${inc.severity}">${inc.severity}</span>
      <span style="font-size: 12px; margin-left: 8px; font-weight: bold; color: #475569;">STATUS: ${inc.status}</span>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <h4>Incident Reference</h4>
      <p>${inc.id}</p>
    </div>
    <div class="card">
      <h4>Attack Classification</h4>
      <p>${inc.attackType}</p>
    </div>
    <div class="card">
      <h4>Onset Timestamp</h4>
      <p>${new Date(inc.startTime).toUTCString()}</p>
    </div>
    <div class="card">
      <h4>Duration / End Time</h4>
      <p>${inc.durationSeconds} seconds (${inc.endTime ? new Date(inc.endTime).toUTCString() : 'Active Incident'})</p>
    </div>
    <div class="card">
      <h4>Peak Ingress Rate</h4>
      <p>${inc.peakRps} req/s (Z-Score: +${inc.peakZScore})</p>
    </div>
    <div class="card">
      <h4>Target Protected Gateway</h4>
      <p>${inc.targetAsset?.ip || '192.168.1.1'} (${inc.targetAsset?.hostname || 'core-gateway'})</p>
    </div>
  </div>

  <div class="reasons">
    <strong style="color: #9f1239;">Forensic Detection Explanations:</strong>
    <ul>
      ${inc.detectionReasons.map(r => `<li>${r}</li>`).join('')}
    </ul>
  </div>

  <h3>Offending Source IPs Identified</h3>
  <table>
    <thead>
      <tr>
        <th>Source IP</th>
        <th>Category</th>
        <th>Attributed Action</th>
      </tr>
    </thead>
    <tbody>
      ${inc.sourceIps.map(ip => `
        <tr>
          <td><code>${ip}</code></td>
          <td>Simulated Malicious Botnet Origin</td>
          <td>High-volume flood emitter</td>
        </tr>
      `).join('')}
    </tbody>
  </table>

  <h3 style="margin-top: 25px;">Incident Timeline</h3>
  <div>
    ${inc.timeline.map(t => `
      <div class="timeline-item">
        <div class="time">${new Date(t.timestamp).toUTCString()}</div>
        <div class="event">${t.event}</div>
        <div class="desc">${t.description}</div>
      </div>
    `).join('')}
  </div>

  <h3 style="margin-top: 25px;">SOC Analyst Notes</h3>
  <table>
    <thead>
      <tr>
        <th style="width: 25%;">Timestamp</th>
        <th style="width: 20%;">Author</th>
        <th>Forensic Finding / Action Note</th>
      </tr>
    </thead>
    <tbody>
      ${inc.investigationNotes.map(n => `
        <tr>
          <td>${new Date(n.timestamp).toUTCString()}</td>
          <td><strong>${n.author}</strong></td>
          <td>${n.note}</td>
        </tr>
      `).join('')}
    </tbody>
  </table>

  <div style="margin-top: 40px; padding-top: 15px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8; text-align: center;">
    Generated by DDoS Detection & Mitigation Dashboard • Academic & Educational Research Project • RFC-1918 Private Emulation Only
  </div>
</body>
</html>`;
  }
}

module.exports = new IncidentManager();
