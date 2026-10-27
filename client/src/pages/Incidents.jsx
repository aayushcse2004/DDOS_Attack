import React, { useState, useEffect } from 'react';
import { 
  FileText, 
  Search, 
  Filter, 
  AlertTriangle, 
  ShieldAlert, 
  ShieldCheck, 
  CheckCircle2, 
  Clock, 
  ArrowRight, 
  Download, 
  Printer, 
  Plus, 
  Send, 
  X, 
  ChevronRight,
  ExternalLink,
  Ban,
  Activity,
  Layers,
  Terminal,
  Cpu
} from 'lucide-react';
import { api } from '../services/api';
import { useSecurity } from '../context/SecurityContext';

export const Incidents = () => {
  const { blockIP, showToast } = useSecurity();

  const [incidents, setIncidents] = useState([]);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(false);

  // New Note state
  const [newNote, setNewNote] = useState('');
  const [noteAuthor, setNoteAuthor] = useState('SOC Analyst');

  // Status update modal state
  const [statusModalOpen, setStatusModalOpen] = useState(false);
  const [targetStatus, setTargetStatus] = useState('INVESTIGATING');
  const [statusChangeNote, setStatusChangeNote] = useState('');

  const fetchIncidents = async () => {
    try {
      setLoading(true);
      const res = await api.getIncidents(statusFilter, severityFilter, search);
      if (res.success) {
        setIncidents(res.data);
        // Refresh selected incident if currently open
        if (selectedIncident) {
          const updatedSelected = res.data.find(i => i.id === selectedIncident.id);
          if (updatedSelected) setSelectedIncident(updatedSelected);
        }
      }
    } catch (err) {
      console.warn('Failed to fetch incidents:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
    const interval = setInterval(fetchIncidents, 3000);
    return () => clearInterval(interval);
  }, [statusFilter, severityFilter, search]);

  const handleUpdateStatus = async (e) => {
    e.preventDefault();
    if (!selectedIncident) return;
    try {
      const res = await api.updateIncidentStatus(selectedIncident.id, targetStatus, statusChangeNote, noteAuthor);
      if (res.success) {
        showToast(`Incident ${selectedIncident.id} updated to ${targetStatus}`, 'success');
        setSelectedIncident(res.data);
        setStatusModalOpen(false);
        setStatusChangeNote('');
        fetchIncidents();
      }
    } catch (err) {
      showToast(`Failed to update status: ${err.message}`, 'error');
    }
  };

  const handleAddNote = async (e) => {
    e.preventDefault();
    if (!selectedIncident || !newNote.trim()) return;
    try {
      const res = await api.addIncidentNote(selectedIncident.id, newNote.trim(), noteAuthor);
      if (res.success) {
        showToast('Analyst forensic note recorded.', 'info');
        setSelectedIncident(res.data);
        setNewNote('');
        fetchIncidents();
      }
    } catch (err) {
      showToast(`Failed to add note: ${err.message}`, 'error');
    }
  };

  const handleQuickBlock = (ip) => {
    blockIP(ip, `Remediated via Incident ${selectedIncident?.id || 'Forensics'}`);
    showToast(`Firewall rule applied: Blocked ${ip}`, 'success');
  };

  // Severity style helper
  const getSeverityBadge = (severity) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
      case 'HIGH':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      case 'MEDIUM':
        return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40';
      default:
        return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40';
    }
  };

  // Status style helper
  const getStatusBadge = (status) => {
    switch (status) {
      case 'OPEN':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40 animate-pulse';
      case 'INVESTIGATING':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      case 'MITIGATED':
        return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40';
      case 'RESOLVED':
        return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const openCount = incidents.filter(i => i.status === 'OPEN').length;
  const investigatingCount = incidents.filter(i => i.status === 'INVESTIGATING').length;
  const resolvedCount = incidents.filter(i => i.status === 'RESOLVED').length;

  return (
    <div className="space-y-6">
      
      {/* Page Header */}
      <div className="cyber-panel p-5 rounded-xl border border-slate-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-mono font-bold text-white flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            <span>INCIDENT INVESTIGATION & FORENSIC TRIAGE</span>
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Structured security event records, chronological timelines, attribution, and forensic reporting
          </p>
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto">
          <a
            href={api.getAllIncidentsExportUrl()}
            download="ddos-incidents-summary.csv"
            className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 hover:border-cyan-500/40 text-slate-200 hover:text-cyan-300 font-mono text-xs flex items-center gap-1.5 transition-all shadow-sm"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>EXPORT ALL (CSV)</span>
          </a>
        </div>
      </div>

      {/* Metric Summary Ribbon */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono text-xs">
        <div className="cyber-panel p-4 rounded-xl border border-slate-800">
          <p className="text-slate-400 uppercase text-[10px]">Total Recorded</p>
          <p className="text-2xl font-bold text-white mt-1">{incidents.length}</p>
        </div>
        <div className="cyber-panel p-4 rounded-xl border border-rose-500/30 bg-rose-950/10">
          <p className="text-rose-400 uppercase text-[10px]">Active Open</p>
          <p className="text-2xl font-bold text-rose-300 mt-1">{openCount}</p>
        </div>
        <div className="cyber-panel p-4 rounded-xl border border-amber-500/30 bg-amber-950/10">
          <p className="text-amber-400 uppercase text-[10px]">Investigating</p>
          <p className="text-2xl font-bold text-amber-300 mt-1">{investigatingCount}</p>
        </div>
        <div className="cyber-panel p-4 rounded-xl border border-emerald-500/30 bg-emerald-950/10">
          <p className="text-emerald-400 uppercase text-[10px]">Resolved / Mitigated</p>
          <p className="text-2xl font-bold text-emerald-300 mt-1">{resolvedCount}</p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="cyber-panel p-4 rounded-xl border border-slate-800 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 font-mono text-xs">
        
        {/* Status Tabs */}
        <div className="flex flex-wrap items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded-lg">
          {['ALL', 'OPEN', 'INVESTIGATING', 'MITIGATED', 'RESOLVED'].map(st => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-3 py-1.5 rounded-md uppercase font-semibold text-[11px] transition-all ${
                statusFilter === st
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {st}
            </button>
          ))}
        </div>

        {/* Search Input */}
        <div className="flex items-center gap-2">
          <div className="relative flex-1 md:w-64">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Filter by ID, IP, vector..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/60"
            />
          </div>
        </div>
      </div>

      {/* Incident List */}
      <div className="space-y-3">
        {incidents.length === 0 ? (
          <div className="cyber-panel p-12 rounded-xl border border-slate-800 text-center font-mono">
            <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto mb-3 opacity-60" />
            <h3 className="text-sm font-bold text-white">No Incidents Matching Criteria</h3>
            <p className="text-xs text-slate-400 mt-1">Network traffic operating within nominal parameters or search yielded zero results.</p>
          </div>
        ) : (
          incidents.map(inc => (
            <div
              key={inc.id}
              className={`cyber-panel p-4 rounded-xl border transition-all hover:border-slate-700 ${
                inc.status === 'OPEN'
                  ? 'border-rose-500/40 bg-rose-950/10'
                  : inc.status === 'INVESTIGATING'
                  ? 'border-amber-500/40 bg-amber-950/10'
                  : 'border-slate-800 bg-slate-900/30'
              }`}
            >
              <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
                
                {/* Left: Metadata & Title */}
                <div className="space-y-1.5 flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs font-bold text-cyan-400 bg-slate-950 px-2 py-0.5 rounded border border-cyan-500/30">
                      {inc.id}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getSeverityBadge(inc.severity)}`}>
                      {inc.severity}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getStatusBadge(inc.status)}`}>
                      {inc.status}
                    </span>
                    <span className="text-[11px] font-mono text-slate-400">
                      Vector: <strong className="text-slate-200">{inc.attackType}</strong>
                    </span>
                  </div>

                  <h3 className="text-sm font-mono font-bold text-white truncate">
                    {inc.title}
                  </h3>

                  <p className="text-xs font-mono text-slate-300 line-clamp-1">
                    {inc.detectionReasons[0] || 'Nominal behavior observed.'}
                  </p>

                  {/* Telemetry stats pill */}
                  <div className="flex flex-wrap items-center gap-4 text-[11px] font-mono text-slate-400 pt-1">
                    <span>Started: <strong className="text-slate-300">{new Date(inc.startTime).toLocaleTimeString()}</strong></span>
                    <span>Duration: <strong className="text-slate-300">{inc.durationSeconds}s</strong></span>
                    <span>Peak Ingress: <strong className="text-cyan-300">{inc.peakRps} req/s</strong></span>
                    <span>Z-Score: <strong className="text-amber-300">+{inc.peakZScore}</strong></span>
                    <span>Sources: <strong className="text-slate-300">{inc.sourceIps.length} IPs</strong></span>
                  </div>
                </div>

                {/* Right: Actions */}
                <div className="flex flex-wrap items-center gap-2 shrink-0 w-full lg:w-auto pt-2 lg:pt-0 border-t lg:border-t-0 border-slate-800">
                  <button
                    onClick={() => setSelectedIncident(inc)}
                    className="px-3 py-1.5 rounded-lg bg-cyan-600/20 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-600/30 font-mono text-xs font-bold flex items-center gap-1.5 transition-all"
                  >
                    <span>INVESTIGATE</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>

                  <a
                    href={api.getIncidentExportUrl(inc.id)}
                    download={`${inc.id}-forensics.csv`}
                    className="p-1.5 rounded-lg bg-slate-900 border border-slate-700 hover:border-slate-500 text-slate-300 hover:text-white transition-all"
                    title="Export Incident CSV"
                  >
                    <Download className="w-4 h-4" />
                  </a>

                  <a
                    href={api.getIncidentReportUrl(inc.id)}
                    target="_blank"
                    rel="noreferrer"
                    className="p-1.5 rounded-lg bg-slate-900 border border-slate-700 hover:border-slate-500 text-slate-300 hover:text-white transition-all"
                    title="Print / Save PDF Report"
                  >
                    <Printer className="w-4 h-4" />
                  </a>
                </div>

              </div>
            </div>
          ))
        )}
      </div>

      {/* Forensic Detail & Investigation Drawer/Modal */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0B101E] border border-cyan-500/40 rounded-xl max-w-4xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden font-mono">
            
            {/* Modal Header */}
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/80">
              <div className="flex items-center gap-3">
                <span className="text-xs font-bold px-2.5 py-1 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                  {selectedIncident.id}
                </span>
                <span className={`px-2.5 py-0.5 rounded text-xs font-bold border ${getSeverityBadge(selectedIncident.severity)}`}>
                  {selectedIncident.severity}
                </span>
                <span className={`px-2.5 py-0.5 rounded text-xs font-bold border ${getStatusBadge(selectedIncident.status)}`}>
                  {selectedIncident.status}
                </span>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => setStatusModalOpen(true)}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold border border-slate-700"
                >
                  Change Status
                </button>
                <a
                  href={api.getIncidentReportUrl(selectedIncident.id)}
                  target="_blank"
                  rel="noreferrer"
                  className="px-2.5 py-1 rounded bg-cyan-600/30 border border-cyan-500/40 text-cyan-300 text-xs font-bold flex items-center gap-1"
                >
                  <Printer className="w-3.5 h-3.5" />
                  <span>PDF Report</span>
                </a>
                <button
                  onClick={() => setSelectedIncident(null)}
                  className="p-1 rounded text-slate-400 hover:text-white"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-6 text-xs">
              
              {/* Title & Target */}
              <div>
                <h3 className="text-base font-bold text-white">{selectedIncident.title}</h3>
                <p className="text-slate-400 mt-1">
                  Target Asset: <strong className="text-slate-200">{selectedIncident.targetAsset?.ip} ({selectedIncident.targetAsset?.hostname})</strong>
                </p>
              </div>

              {/* Forensic Metrics Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3 bg-slate-950 rounded border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase">Attack Vector</span>
                  <p className="text-sm font-bold text-white mt-0.5">{selectedIncident.attackType}</p>
                </div>
                <div className="p-3 bg-slate-950 rounded border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase">Peak Ingress Rate</span>
                  <p className="text-sm font-bold text-cyan-300 mt-0.5">{selectedIncident.peakRps} req/s</p>
                </div>
                <div className="p-3 bg-slate-950 rounded border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase">Anomaly Z-Score</span>
                  <p className="text-sm font-bold text-amber-300 mt-0.5">+{selectedIncident.peakZScore} σ</p>
                </div>
                <div className="p-3 bg-slate-950 rounded border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase">Total Duration</span>
                  <p className="text-sm font-bold text-emerald-300 mt-0.5">{selectedIncident.durationSeconds}s</p>
                </div>
              </div>

              {/* Forensic Explanations */}
              <div className="p-4 rounded-lg bg-rose-950/20 border border-rose-500/30">
                <h4 className="font-bold text-rose-300 mb-2 flex items-center gap-1.5">
                  <ShieldAlert className="w-4 h-4" />
                  <span>Detection Heuristic & Anomaly Justifications:</span>
                </h4>
                <ul className="space-y-1 list-disc list-inside text-slate-300">
                  {selectedIncident.detectionReasons.map((r, idx) => (
                    <li key={idx}>{r}</li>
                  ))}
                </ul>
              </div>

              {/* Offending IPs */}
              <div>
                <h4 className="font-bold text-slate-300 mb-2 flex items-center gap-1.5">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  <span>Offending Source IP Addresses ({selectedIncident.sourceIps.length})</span>
                </h4>
                <div className="flex flex-wrap gap-2">
                  {selectedIncident.sourceIps.map(ip => (
                    <div key={ip} className="flex items-center gap-2 px-2.5 py-1 rounded bg-slate-950 border border-slate-800">
                      <span className="text-slate-200">{ip}</span>
                      <button
                        onClick={() => handleQuickBlock(ip)}
                        className="text-[10px] px-1.5 py-0.5 rounded bg-rose-600/30 hover:bg-rose-600 text-rose-300 hover:text-white transition-all"
                        title="Block IP in firewall"
                      >
                        Block
                      </button>
                    </div>
                  ))}
                </div>
              </div>

              {/* Timeline */}
              <div>
                <h4 className="font-bold text-slate-300 mb-3 flex items-center gap-1.5">
                  <Clock className="w-4 h-4 text-cyan-400" />
                  <span>Chronological Incident Timeline</span>
                </h4>
                <div className="space-y-2 border-l border-cyan-500/40 pl-4 ml-2">
                  {selectedIncident.timeline.map((item, idx) => (
                    <div key={idx} className="relative">
                      <div className="absolute -left-[21px] top-1.5 w-2.5 h-2.5 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.8)]" />
                      <div className="text-[10px] text-slate-500">{new Date(item.timestamp).toLocaleTimeString()}</div>
                      <div className="font-bold text-slate-200">{item.event}</div>
                      <div className="text-slate-400">{item.description}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Notes & Analyst Thread */}
              <div>
                <h4 className="font-bold text-slate-300 mb-2">SOC Analyst Investigation Notes</h4>
                <div className="space-y-2 mb-3">
                  {selectedIncident.investigationNotes.length === 0 ? (
                    <p className="text-slate-500 italic">No analyst notes recorded yet.</p>
                  ) : (
                    selectedIncident.investigationNotes.map((n, idx) => (
                      <div key={idx} className="p-3 bg-slate-950 rounded border border-slate-800">
                        <div className="flex items-center justify-between text-[10px] text-slate-400 mb-1">
                          <strong className="text-cyan-400">{n.author}</strong>
                          <span>{new Date(n.timestamp).toLocaleTimeString()}</span>
                        </div>
                        <p className="text-slate-200">{n.note}</p>
                      </div>
                    ))
                  )}
                </div>

                {/* Add Note Form */}
                <form onSubmit={handleAddNote} className="flex gap-2">
                  <input
                    type="text"
                    placeholder="Add forensic investigation note..."
                    value={newNote}
                    onChange={(e) => setNewNote(e.target.value)}
                    className="flex-1 px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                  />
                  <button
                    type="submit"
                    className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold flex items-center gap-1.5"
                  >
                    <Send className="w-3.5 h-3.5" />
                    <span>Add Note</span>
                  </button>
                </form>
              </div>

            </div>

          </div>
        </div>
      )}

      {/* Status Change Modal */}
      {statusModalOpen && selectedIncident && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
          <div className="bg-[#0B101E] border border-cyan-500/40 rounded-xl max-w-md w-full p-5 font-mono text-xs">
            <h3 className="text-sm font-bold text-white mb-3">Update Incident Status ({selectedIncident.id})</h3>
            <form onSubmit={handleUpdateStatus} className="space-y-3">
              <div>
                <label className="text-slate-400 block mb-1">Target Status:</label>
                <select
                  value={targetStatus}
                  onChange={(e) => setTargetStatus(e.target.value)}
                  className="w-full p-2 bg-slate-950 border border-slate-800 rounded text-white"
                >
                  <option value="OPEN">OPEN</option>
                  <option value="INVESTIGATING">INVESTIGATING</option>
                  <option value="MITIGATED">MITIGATED</option>
                  <option value="RESOLVED">RESOLVED</option>
                </select>
              </div>
              <div>
                <label className="text-slate-400 block mb-1">Status Change Reason / Note:</label>
                <textarea
                  rows="3"
                  value={statusChangeNote}
                  onChange={(e) => setStatusChangeNote(e.target.value)}
                  placeholder="e.g. Mitigated via IP blacklist and perimeter rate limit..."
                  className="w-full p-2 bg-slate-950 border border-slate-800 rounded text-white"
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setStatusModalOpen(false)}
                  className="px-3 py-1.5 rounded bg-slate-800 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-bold"
                >
                  Apply Status
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

    </div>
  );
};
