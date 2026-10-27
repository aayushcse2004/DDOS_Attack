import React, { useState } from 'react';
import { 
  AlertTriangle, 
  CheckCircle2, 
  ShieldAlert, 
  ShieldCheck, 
  Ban, 
  Flame, 
  Clock, 
  Sliders, 
  CheckCheck,
  Filter
} from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';

export const Alerts = () => {
  const { alerts, resolveAlert, resolveAllAlerts, blockIP, toggleRateLimiting } = useSecurity();
  const [filter, setFilter] = useState('all'); // 'all' | 'active' | 'resolved'

  const filteredAlerts = alerts.filter(a => {
    if (filter === 'active') return a.status === 'active';
    if (filter === 'resolved') return a.status === 'resolved';
    return true;
  });

  const activeCount = alerts.filter(a => a.status === 'active').length;
  const resolvedCount = alerts.filter(a => a.status === 'resolved').length;

  const handleApplyRecommendation = (alert) => {
    if (alert.offendingIPs && alert.offendingIPs.length > 0) {
      alert.offendingIPs.forEach(ip => {
        blockIP(ip, `Remediated via Alert ${alert.id}: ${alert.attackType}`);
      });
    }
    toggleRateLimiting(true, 80);
    resolveAlert(alert.id);
  };

  const getSeverityStyle = (severity) => {
    switch (severity) {
      case 'CRITICAL':
        return {
          border: 'border-rose-500/50',
          bg: 'bg-rose-950/20',
          badge: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
          icon: ShieldAlert
        };
      case 'HIGH':
        return {
          border: 'border-amber-500/50',
          bg: 'bg-amber-950/20',
          badge: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
          icon: AlertTriangle
        };
      case 'MEDIUM':
        return {
          border: 'border-yellow-500/50',
          bg: 'bg-yellow-950/20',
          badge: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40',
          icon: AlertTriangle
        };
      default:
        return {
          border: 'border-cyan-500/50',
          bg: 'bg-slate-900/40',
          badge: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40',
          icon: ShieldCheck
        };
    }
  };

  return (
    <div className="space-y-6">
      
      {/* Alert Center Header */}
      <div className="cyber-panel p-5 rounded-xl border border-slate-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-mono font-bold text-white flex items-center gap-2">
            <Flame className="w-5 h-5 text-rose-400" />
            <span>INCIDENT TRIAGE & SECURITY ALERT CENTER</span>
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Automated anomaly detection triggers, forensic reasoning, and defensive remediations
          </p>
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto">
          {activeCount > 0 && (
            <button
              onClick={resolveAllAlerts}
              className="px-3 py-1.5 rounded-lg bg-emerald-600/20 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-600/30 text-xs font-mono font-semibold flex items-center gap-1.5 transition-all"
            >
              <CheckCheck className="w-3.5 h-3.5" />
              <span>RESOLVE ALL ({activeCount})</span>
            </button>
          )}
        </div>
      </div>

      {/* Summary Stats Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono text-xs">
        <div className="cyber-panel p-4 rounded-xl border border-slate-800 flex items-center justify-between">
          <div>
            <p className="text-slate-400 uppercase text-[10px]">Total Recorded Alerts</p>
            <p className="text-2xl font-bold text-white mt-1">{alerts.length}</p>
          </div>
          <AlertTriangle className="w-6 h-6 text-cyan-400 opacity-60" />
        </div>

        <div className="cyber-panel p-4 rounded-xl border border-rose-500/30 bg-rose-950/10 flex items-center justify-between">
          <div>
            <p className="text-rose-400 uppercase text-[10px]">Active Incidents</p>
            <p className="text-2xl font-bold text-rose-300 mt-1">{activeCount}</p>
          </div>
          <Flame className="w-6 h-6 text-rose-400 opacity-80" />
        </div>

        <div className="cyber-panel p-4 rounded-xl border border-emerald-500/30 bg-emerald-950/10 flex items-center justify-between">
          <div>
            <p className="text-emerald-400 uppercase text-[10px]">Remediated & Resolved</p>
            <p className="text-2xl font-bold text-emerald-300 mt-1">{resolvedCount}</p>
          </div>
          <CheckCircle2 className="w-6 h-6 text-emerald-400 opacity-80" />
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center gap-2 font-mono text-xs">
        <div className="flex items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded-lg">
          {['all', 'active', 'resolved'].map(t => (
            <button
              key={t}
              onClick={() => setFilter(t)}
              className={`px-3 py-1.5 rounded-md uppercase font-semibold text-[11px] transition-all ${
                filter === t
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {t} ({t === 'all' ? alerts.length : t === 'active' ? activeCount : resolvedCount})
            </button>
          ))}
        </div>
      </div>

      {/* Alerts Stream */}
      <div className="space-y-3 font-mono">
        {filteredAlerts.length === 0 ? (
          <div className="cyber-panel p-12 text-center rounded-xl border border-slate-800 text-slate-500 text-xs">
            <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto mb-2 opacity-60" />
            <p className="text-sm font-semibold text-slate-300">No alerts found in this view.</p>
            <p className="text-[11px] text-slate-500 mt-1">Simulate an attack from the dashboard to trigger security events.</p>
          </div>
        ) : (
          filteredAlerts.map(alert => {
            const style = getSeverityStyle(alert.severity);
            const Icon = style.icon;

            return (
              <div 
                key={alert.id}
                className={`cyber-panel p-5 rounded-xl border transition-all ${style.border} ${style.bg} ${
                  alert.status === 'resolved' ? 'opacity-60' : ''
                }`}
              >
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                  
                  {/* Left: Severity & Details */}
                  <div className="flex items-start gap-3 flex-1">
                    <div className={`p-2.5 rounded-lg border shrink-0 ${style.badge}`}>
                      <Icon className="w-5 h-5" />
                    </div>

                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${style.badge}`}>
                          {alert.severity} ALERT
                        </span>
                        <span className="text-xs font-bold text-white">{alert.title}</span>
                        <span className="text-[10px] text-slate-500 flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {new Date(alert.timestamp).toLocaleString()}
                        </span>
                        {alert.occurrenceCount > 1 && (
                          <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">
                            {alert.occurrenceCount}x repeated
                          </span>
                        )}
                      </div>

                      {/* Detection Rationale */}
                      <p className="text-xs text-slate-300 pt-1">
                        <span className="text-slate-500 uppercase text-[10px]">Detection Reason: </span>
                        {alert.reason}
                      </p>

                      {/* Recommended Mitigation */}
                      <p className="text-xs text-cyan-300">
                        <span className="text-slate-500 uppercase text-[10px]">Recommended Action: </span>
                        {alert.recommendedAction}
                      </p>

                      {/* Suspect IPs */}
                      {alert.offendingIPs && alert.offendingIPs.length > 0 && (
                        <div className="flex items-center gap-2 pt-1 text-[11px] text-slate-400">
                          <span>Flagged Sources:</span>
                          {alert.offendingIPs.map(ip => (
                            <span key={ip} className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-700 text-rose-300">
                              {ip}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Right: Actions */}
                  <div className="flex items-center gap-2 shrink-0 pt-2 lg:pt-0 border-t lg:border-t-0 border-slate-800">
                    {alert.status === 'active' ? (
                      <>
                        <button
                          onClick={() => handleApplyRecommendation(alert)}
                          className="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold shadow-md transition-all flex items-center gap-1.5"
                        >
                          <Ban className="w-3.5 h-3.5" />
                          <span>Apply Recommendation</span>
                        </button>
                        <button
                          onClick={() => resolveAlert(alert.id)}
                          className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition-all flex items-center gap-1"
                        >
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                          <span>Resolve</span>
                        </button>
                      </>
                    ) : (
                      <span className="px-3 py-1 rounded-md bg-emerald-950/60 text-emerald-400 border border-emerald-500/30 text-xs flex items-center gap-1.5">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>Resolved {alert.resolvedAt ? new Date(alert.resolvedAt).toLocaleTimeString() : ''}</span>
                      </span>
                    )}
                  </div>

                </div>
              </div>
            );
          })
        )}
      </div>

    </div>
  );
};
