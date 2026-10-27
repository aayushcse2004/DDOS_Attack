import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Ban, 
  CheckCircle2, 
  Sliders, 
  Filter, 
  Plus, 
  Trash2, 
  Cpu,
  Lock,
  Unlock,
  AlertTriangle,
  Clock,
  Activity,
  History,
  TrendingDown,
  Layers,
  ArrowRight
} from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';
import { api } from '../services/api';

export const Mitigation = () => {
  const { 
    mitigationRules, 
    blockIP, 
    unblockIP, 
    toggleRateLimiting, 
    toggleTrafficFiltering, 
    toggleSynCookie,
    stats,
    showToast 
  } = useSecurity();

  const [manualIP, setManualIP] = useState('');
  const [manualReason, setManualReason] = useState('Manual SOC containment policy');
  const [manualDuration, setManualDuration] = useState('0'); // 0 = permanent, or seconds
  const [rateLimitInput, setRateLimitInput] = useState(mitigationRules.rateLimiting?.threshold || 100);

  // Mitigation stats & action logs state
  const [mitigationStats, setMitigationStats] = useState(null);
  const [actionLogs, setActionLogs] = useState([]);

  const fetchMitigationTelemetry = async () => {
    try {
      const [statsRes, logsRes] = await Promise.allSettled([
        api.getMitigationStats(),
        api.getMitigationLogs(15)
      ]);
      if (statsRes.status === 'fulfilled' && statsRes.value.success) {
        setMitigationStats(statsRes.value.data);
      }
      if (logsRes.status === 'fulfilled' && logsRes.value.success) {
        setActionLogs(logsRes.value.data);
      }
    } catch (err) {
      console.warn('Failed to fetch mitigation telemetry:', err);
    }
  };

  useEffect(() => {
    fetchMitigationTelemetry();
    const interval = setInterval(fetchMitigationTelemetry, 2000);
    return () => clearInterval(interval);
  }, []);

  const handleManualBlock = async (e) => {
    e.preventDefault();
    if (!manualIP.trim()) return;
    try {
      const durationSec = Number(manualDuration) || 0;
      await api.blockIP(manualIP.trim(), manualReason, durationSec);
      showToast(`Blocked ${manualIP.trim()}${durationSec > 0 ? ` with ${durationSec}s TTL` : ' permanently'}`, 'success');
      setManualIP('');
      fetchMitigationTelemetry();
    } catch (err) {
      showToast('Failed to block IP: ' + err.message, 'error');
    }
  };

  const handleUpdateRateLimit = (e) => {
    e.preventDefault();
    toggleRateLimiting(true, Number(rateLimitInput));
  };

  // Telemetry fallback defaults
  const telem = mitigationStats || {
    totalIngressRequests: stats.totalRequests || 0,
    totalAllowedRequests: Math.max(0, (stats.totalRequests || 0) - (stats.blockedRequests || 0)),
    totalDroppedRequests: stats.blockedRequests || 0,
    totalBlockedByIp: 0,
    totalDroppedByRateLimit: 0,
    totalFilteredByDpi: 0,
    totalFilteredBySynCookie: 0,
    mitigationEffectivenessPercentage: stats.totalRequests > 0 ? Number(((stats.blockedRequests / stats.totalRequests) * 100).toFixed(1)) : 0
  };

  return (
    <div className="space-y-6">
      
      {/* Mitigation Module Header */}
      <div className="cyber-panel p-5 rounded-xl border border-slate-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-mono font-bold text-white flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            <span>DEFENSIVE MITIGATION & ACCESS CONTROL CENTER</span>
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Configure active firewall filters, TTL rule expirations, per-IP sliding-window rate limiters, and inspect before/after telemetry
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-emerald-300 flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>{telem.totalDroppedRequests.toLocaleString()} Requests Suppressed</span>
          </span>
        </div>
      </div>

      {/* Traffic Before & After Mitigation Telemetry Panel */}
      <div className="cyber-panel p-5 rounded-xl border border-slate-800 font-mono text-xs">
        <div className="flex items-center justify-between mb-4 border-b border-slate-800/80 pb-3">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white uppercase">TRAFFIC IMPACT ANALYSIS: BEFORE VS AFTER DEFENSE</h3>
          </div>
          <span className="text-[11px] px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
            {telem.mitigationEffectivenessPercentage}% Mitigation Filter Rate
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800">
            <span className="text-[10px] text-slate-400 uppercase">Total Ingress (Before)</span>
            <p className="text-2xl font-bold text-white mt-1">{telem.totalIngressRequests.toLocaleString()}</p>
            <p className="text-[10px] text-slate-500 mt-1">Raw arriving requests</p>
          </div>

          <div className="p-4 rounded-lg bg-emerald-950/20 border border-emerald-500/30">
            <span className="text-[10px] text-emerald-400 uppercase">Permitted Traffic (After)</span>
            <p className="text-2xl font-bold text-emerald-300 mt-1">{telem.totalAllowedRequests.toLocaleString()}</p>
            <p className="text-[10px] text-slate-400 mt-1">Delivered to Gateway Services</p>
          </div>

          <div className="p-4 rounded-lg bg-rose-950/20 border border-rose-500/30">
            <span className="text-[10px] text-rose-400 uppercase">Suppressed Traffic (Drops)</span>
            <p className="text-2xl font-bold text-rose-300 mt-1">{telem.totalDroppedRequests.toLocaleString()}</p>
            <p className="text-[10px] text-slate-400 mt-1">Intercepted at Border</p>
          </div>

          <div className="p-4 rounded-lg bg-cyan-950/20 border border-cyan-500/30">
            <span className="text-[10px] text-cyan-400 uppercase">Active Filter Ratio</span>
            <p className="text-2xl font-bold text-cyan-300 mt-1">{telem.mitigationEffectivenessPercentage}%</p>
            <p className="text-[10px] text-slate-400 mt-1">Attack Volume Neutralized</p>
          </div>
        </div>
      </div>

      {/* Defensive Policy Switches */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 font-mono text-xs">
        
        {/* Rate Limiter Control */}
        <div className="cyber-panel p-5 rounded-xl border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="font-bold text-white flex items-center gap-2">
                <Sliders className="w-4 h-4 text-cyan-400" />
                <span>Rate Limiting (Sliding Window)</span>
              </span>
              <button
                onClick={() => toggleRateLimiting(!mitigationRules.rateLimiting?.enabled, rateLimitInput)}
                className={`relative inline-flex h-5 w-10 items-center rounded-full transition-colors ${
                  mitigationRules.rateLimiting?.enabled ? 'bg-cyan-500' : 'bg-slate-700'
                }`}
              >
                <span
                  className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                    mitigationRules.rateLimiting?.enabled ? 'translate-x-5' : 'translate-x-1'
                  }`}
                />
              </button>
            </div>
            <p className="text-slate-400 text-[11px]">
              Throttles incoming bursts exceeding safe quota per source IP.
            </p>

            <form onSubmit={handleUpdateRateLimit} className="mt-4 space-y-2">
              <div className="flex items-center justify-between text-slate-300 text-[11px]">
                <span>Limit Threshold:</span>
                <span className="font-bold text-cyan-400">{rateLimitInput} req/s</span>
              </div>
              <input
                type="range"
                min="20"
                max="300"
                step="10"
                value={rateLimitInput}
                onChange={(e) => setRateLimitInput(e.target.value)}
                disabled={!mitigationRules.rateLimiting?.enabled}
                className="w-full accent-cyan-400 bg-slate-800 rounded cursor-pointer disabled:opacity-40"
              />
              <button
                type="submit"
                disabled={!mitigationRules.rateLimiting?.enabled}
                className="w-full py-1.5 rounded bg-cyan-600/80 hover:bg-cyan-600 disabled:opacity-40 text-white font-bold text-[11px] transition-all"
              >
                Update Rate Quota
              </button>
            </form>
          </div>
          <div className="mt-3 pt-2 border-t border-slate-800 text-[10px] text-slate-500 flex justify-between">
            <span>Status:</span>
            <span className={mitigationRules.rateLimiting?.enabled ? 'text-cyan-400 font-bold' : 'text-slate-400'}>
              {mitigationRules.rateLimiting?.enabled ? 'ACTIVE ENFORCEMENT' : 'DISABLED'}
            </span>
          </div>
        </div>

        {/* Deep Traffic Filtering (DPI) */}
        <div className="cyber-panel p-5 rounded-xl border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="font-bold text-white flex items-center gap-2">
                <Filter className="w-4 h-4 text-emerald-400" />
                <span>Deep Traffic Filtering (DPI)</span>
              </span>
              <button
                onClick={() => toggleTrafficFiltering(!mitigationRules.trafficFiltering?.enabled)}
                className={`relative inline-flex h-5 w-10 items-center rounded-full transition-colors ${
                  mitigationRules.trafficFiltering?.enabled ? 'bg-emerald-500' : 'bg-slate-700'
                }`}
              >
                <span
                  className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                    mitigationRules.trafficFiltering?.enabled ? 'translate-x-5' : 'translate-x-1'
                  }`}
                />
              </button>
            </div>
            <p className="text-slate-400 text-[11px]">
              Inspects packet payloads to drop amplified UDP and malformed ICMP ping floods.
            </p>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 text-[10px] text-slate-500 flex justify-between">
            <span>Status:</span>
            <span className={mitigationRules.trafficFiltering?.enabled ? 'text-emerald-400 font-bold' : 'text-slate-400'}>
              {mitigationRules.trafficFiltering?.enabled ? 'ACTIVE ENFORCEMENT' : 'DISABLED'}
            </span>
          </div>
        </div>

        {/* TCP SYN Cookie Defense */}
        <div className="cyber-panel p-5 rounded-xl border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="font-bold text-white flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-blue-400" />
                <span>TCP SYN Cookies Defense</span>
              </span>
              <button
                onClick={() => toggleSynCookie(!mitigationRules.synCookie?.enabled)}
                className={`relative inline-flex h-5 w-10 items-center rounded-full transition-colors ${
                  mitigationRules.synCookie?.enabled ? 'bg-blue-500' : 'bg-slate-700'
                }`}
              >
                <span
                  className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                    mitigationRules.synCookie?.enabled ? 'translate-x-5' : 'translate-x-1'
                  }`}
                />
              </button>
            </div>
            <p className="text-slate-400 text-[11px]">
              Protects TCP connection tables by validating initial sequence numbers without allocating memory.
            </p>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 text-[10px] text-slate-500 flex justify-between">
            <span>Status:</span>
            <span className={mitigationRules.synCookie?.enabled ? 'text-blue-400 font-bold' : 'text-slate-400'}>
              {mitigationRules.synCookie?.enabled ? 'ACTIVE ENFORCEMENT' : 'DISABLED'}
            </span>
          </div>
        </div>

      </div>

      {/* Manual IP Blacklist Inserter with TTL Selection */}
      <div className="cyber-panel p-5 rounded-xl border border-slate-800 font-mono text-xs">
        <h3 className="text-sm font-bold text-white flex items-center gap-2 mb-1">
          <Ban className="w-4 h-4 text-rose-400" />
          <span>FIREWALL ACCESS CONTROL RULE INSERTER (WITH TTL EXPIRATION)</span>
        </h3>
        <p className="text-slate-400 text-xs mb-3">Add source IP to containment blocklist with optional auto-expiration:</p>

        <form onSubmit={handleManualBlock} className="grid grid-cols-1 sm:grid-cols-4 gap-3">
          <input
            type="text"
            placeholder="IP Address (e.g. 192.168.1.101)"
            value={manualIP}
            onChange={(e) => setManualIP(e.target.value)}
            className="p-2.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
          <input
            type="text"
            placeholder="Reason for block"
            value={manualReason}
            onChange={(e) => setManualReason(e.target.value)}
            className="p-2.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
          <select
            value={manualDuration}
            onChange={(e) => setManualDuration(e.target.value)}
            className="p-2.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="0">Permanent (No TTL)</option>
            <option value="30">30 Seconds TTL</option>
            <option value="60">1 Minute TTL</option>
            <option value="300">5 Minutes TTL</option>
            <option value="900">15 Minutes TTL</option>
          </select>
          <button
            type="submit"
            className="py-2.5 px-4 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold flex items-center justify-center gap-2 transition-all shadow-md shadow-rose-600/20"
          >
            <Ban className="w-4 h-4" />
            <span>Block IP Address</span>
          </button>
        </form>
      </div>

      {/* Active IP Blocklist Table */}
      <div className="cyber-panel rounded-xl border border-slate-800 overflow-hidden font-mono text-xs">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Ban className="w-4 h-4 text-rose-400" />
            <span className="font-bold text-white uppercase text-xs">ACTIVE FIREWALL BLACKLIST RULES</span>
          </div>
          <span className="text-[11px] text-slate-400">
            {mitigationRules.blockedIPs?.length || 0} active rules
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="bg-slate-950/90 border-b border-slate-800 text-slate-400 text-[10px] uppercase">
              <tr>
                <th className="py-3 px-4">IP Address</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Requests Dropped</th>
                <th className="py-3 px-4">Enforcement Reason</th>
                <th className="py-3 px-4">Blocked At</th>
                <th className="py-3 px-4">TTL / Expiration</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {(!mitigationRules.blockedIPs || mitigationRules.blockedIPs.length === 0) ? (
                <tr>
                  <td colSpan="7" className="py-10 text-center text-slate-500">
                    No active IP blacklist rules. Click "Block IP" from Traffic logs or insert above.
                  </td>
                </tr>
              ) : (
                mitigationRules.blockedIPs.map(rule => (
                  <tr key={rule.ip} className="hover:bg-slate-800/30">
                    <td className="py-3 px-4 font-bold text-cyan-300">{rule.ip}</td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">
                        BLOCKED
                      </span>
                    </td>
                    <td className="py-3 px-4 text-white font-bold">{rule.interceptedCount.toLocaleString()}</td>
                    <td className="py-3 px-4 text-slate-300">{rule.reason}</td>
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {new Date(rule.blockedAt).toLocaleTimeString()}
                    </td>
                    <td className="py-3 px-4 text-[11px]">
                      {rule.expiresAt ? (
                        <span className="text-amber-400 flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          <span>Expires {new Date(rule.expiresAt).toLocaleTimeString()}</span>
                        </span>
                      ) : (
                        <span className="text-slate-400">Permanent</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => unblockIP(rule.ip)}
                        className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-emerald-400 border border-emerald-500/30 text-xs font-bold transition-all flex items-center gap-1.5 ml-auto"
                      >
                        <Unlock className="w-3.5 h-3.5" />
                        <span>Unblock</span>
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Mitigation Action Audit Trail Log */}
      <div className="cyber-panel rounded-xl border border-slate-800 overflow-hidden font-mono text-xs">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <History className="w-4 h-4 text-cyan-400" />
            <span className="font-bold text-white uppercase text-xs">DEFENSIVE MITIGATION ACTION AUDIT TRAIL</span>
          </div>
          <span className="text-[11px] text-slate-400">
            Immutable SOC Enforcement Log
          </span>
        </div>

        <div className="overflow-x-auto max-h-60">
          <table className="w-full text-left">
            <thead className="bg-slate-950/90 border-b border-slate-800 text-slate-400 text-[10px] uppercase sticky top-0">
              <tr>
                <th className="py-2.5 px-4">Timestamp</th>
                <th className="py-2.5 px-4">Action Type</th>
                <th className="py-2.5 px-4">Target IP / Resource</th>
                <th className="py-2.5 px-4">Reason / Policy Context</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {actionLogs.length === 0 ? (
                <tr>
                  <td colSpan="4" className="py-6 text-center text-slate-500">
                    No mitigation events logged yet.
                  </td>
                </tr>
              ) : (
                actionLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-800/30">
                    <td className="py-2 px-4 text-slate-400 text-[11px]">{new Date(log.timestamp).toLocaleTimeString()}</td>
                    <td className="py-2 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        log.action === 'BLOCK_IP' ? 'bg-rose-500/20 text-rose-300' :
                        log.action === 'UNBLOCK_IP' ? 'bg-emerald-500/20 text-emerald-300' :
                        log.action === 'RULE_EXPIRED' ? 'bg-amber-500/20 text-amber-300' :
                        'bg-cyan-500/20 text-cyan-300'
                      }`}>
                        {log.action}
                      </span>
                    </td>
                    <td className="py-2 px-4 font-bold text-slate-200">{log.ip || 'Global Perimeter'}</td>
                    <td className="py-2 px-4 text-slate-300 text-[11px]">{log.reason || JSON.stringify(log.details || {})}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
};
