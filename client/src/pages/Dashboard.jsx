import React, { useState } from 'react';
import { 
  Activity, 
  ShieldAlert, 
  Zap, 
  AlertOctagon, 
  ShieldCheck, 
  Sliders, 
  Flame, 
  Radio, 
  CheckCircle2, 
  ArrowRight,
  TrendingUp,
  Cpu
} from 'lucide-react';
import { 
  ResponsiveContainer, 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  Tooltip, 
  ReferenceLine,
  PieChart,
  Pie,
  Cell,
  Legend
} from 'recharts';
import { useSecurity } from '../context/SecurityContext';
import { StatCard } from '../components/StatCard';

export const Dashboard = ({ setActiveTab }) => {
  const { 
    stats, 
    timeSeries, 
    alerts, 
    setSimulationMode, 
    updateThresholds, 
    blockIP, 
    toggleRateLimiting,
    resolveAlert
  } = useSecurity();

  // Local state for threshold inputs
  const [localRpsThreshold, setLocalRpsThreshold] = useState(stats.thresholds?.rpsThreshold || 500);
  const [localVolumeThreshold, setLocalVolumeThreshold] = useState(stats.thresholds?.volumeThresholdMB || 20);

  const handleSaveThresholds = (e) => {
    e.preventDefault();
    updateThresholds({
      rpsThreshold: Number(localRpsThreshold),
      volumeThresholdMB: Number(localVolumeThreshold)
    });
  };

  // Pie chart breakdown data
  const pieData = [
    { name: 'Normal Traffic', value: Math.max(0, stats.currentRps - stats.currentSuspiciousRps), color: '#10B981' },
    { name: 'Suspicious Traffic', value: Math.max(0, stats.currentSuspiciousRps - stats.currentBlockedRps), color: '#F43F5E' },
    { name: 'Blocked / Mitigated', value: stats.currentBlockedRps, color: '#06B6D4' }
  ];

  const recentActiveAlerts = alerts.filter(a => a.status === 'active').slice(0, 3);

  return (
    <div className="space-y-6">
      
      {/* Top Banner: Detection Reason & Explainability */}
      <div className={`cyber-panel p-4 rounded-xl border flex flex-col md:flex-row items-start md:items-center justify-between gap-4 ${
        stats.threatLevel === 'CRITICAL' 
          ? 'border-rose-500/50 bg-rose-950/20' 
          : stats.threatLevel === 'HIGH'
          ? 'border-amber-500/50 bg-amber-950/20'
          : 'border-slate-800 bg-slate-900/40'
      }`}>
        <div className="flex items-start gap-3">
          <div className={`p-2.5 rounded-lg border shrink-0 ${
            stats.threatLevel === 'CRITICAL'
              ? 'bg-rose-500/20 text-rose-400 border-rose-500/40'
              : stats.threatLevel === 'HIGH'
              ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
              : 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40'
          }`}>
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Detection Engine Status:</span>
              <span className={`text-xs font-mono font-bold uppercase ${
                stats.lastDetection?.isPotentialDDoS ? 'text-rose-400' : 'text-emerald-400'
              }`}>
                {stats.lastDetection?.classification || 'Normal'}
              </span>
            </div>
            <p className="text-sm font-mono text-slate-200 mt-0.5">
              {stats.lastDetection?.primaryReason || 'All telemetry metrics within standard baseline operating limits.'}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0 w-full md:w-auto">
          {stats.lastDetection?.isPotentialDDoS && (
            <button
              onClick={() => toggleRateLimiting(true, 80)}
              className="w-full md:w-auto px-3.5 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-mono text-xs font-semibold shadow-lg shadow-rose-600/30 transition-all flex items-center justify-center gap-1.5"
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>Apply Recommended Defense</span>
            </button>
          )}
        </div>
      </div>

      {/* Multi-Factor Forensic Telemetry & Threat Breakdown Ribbon */}
      <div className="cyber-panel p-4 rounded-xl border border-slate-800 font-mono text-xs">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
          
          {/* Left: Multi-Factor Metrics */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 flex-1 w-full">
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800/80">
              <span className="text-[10px] text-slate-500 uppercase">Baseline EMA Rate</span>
              <p className="text-sm font-bold text-slate-200 mt-0.5">
                {stats.lastDetection?.multiFactorAnalysis?.statistical?.baselineEma || 38} req/s
              </p>
            </div>

            <div className="p-2.5 rounded bg-slate-950 border border-slate-800/80">
              <span className="text-[10px] text-slate-500 uppercase">Velocity Z-Score</span>
              <p className={`text-sm font-bold mt-0.5 ${
                (stats.lastDetection?.multiFactorAnalysis?.statistical?.zScore || 0) >= 2.5 ? 'text-rose-400' : 'text-emerald-400'
              }`}>
                {(stats.lastDetection?.multiFactorAnalysis?.statistical?.zScore || 0) >= 0 ? '+' : ''}
                {stats.lastDetection?.multiFactorAnalysis?.statistical?.zScore || 0} σ
              </p>
            </div>

            <div className="p-2.5 rounded bg-slate-950 border border-slate-800/80">
              <span className="text-[10px] text-slate-500 uppercase">Top Source Share</span>
              <p className="text-sm font-bold text-amber-300 mt-0.5">
                {Math.round((stats.lastDetection?.multiFactorAnalysis?.uniqueIPs?.concentrationRatio || 0) * 100)}%
                <span className="text-[10px] text-slate-400 font-normal ml-1">
                  ({stats.lastDetection?.multiFactorAnalysis?.uniqueIPs?.topTalkerIP || 'N/A'})
                </span>
              </p>
            </div>

            <div className="p-2.5 rounded bg-slate-950 border border-slate-800/80">
              <span className="text-[10px] text-slate-500 uppercase">TCP SYN Ratio</span>
              <p className={`text-sm font-bold mt-0.5 ${
                (stats.lastDetection?.multiFactorAnalysis?.protocol?.synAckRatio || 0) >= 0.70 ? 'text-rose-400' : 'text-slate-300'
              }`}>
                {Math.round((stats.lastDetection?.multiFactorAnalysis?.protocol?.synAckRatio || 0) * 100)}%
                <span className="text-[10px] text-slate-400 font-normal ml-1">SYN/ACK</span>
              </p>
            </div>
          </div>

          {/* Right: Transparent Threat Score Meter */}
          <div className="p-2.5 rounded bg-slate-950 border border-slate-800 shrink-0 w-full lg:w-auto">
            <div className="flex items-center justify-between gap-4 text-[11px] mb-1">
              <span className="text-slate-400 uppercase font-semibold">Threat Score Breakdown:</span>
              <span className="font-extrabold text-cyan-400">{stats.threatScore}/100 ({stats.threatLevel})</span>
            </div>
            <div className="flex items-center gap-2 text-[10px] text-slate-400">
              <span>Vol: <strong className="text-slate-200">+{stats.threatBreakdown?.volumetricContribution || 0}</strong></span>
              <span>• Anomaly: <strong className="text-slate-200">+{stats.threatBreakdown?.anomalyContribution || 0}</strong></span>
              <span>• Sig: <strong className="text-slate-200">+{stats.threatBreakdown?.signatureContribution || 0}</strong></span>
              <span>• Mitig: <strong className="text-emerald-400">-{stats.threatBreakdown?.mitigationDiscount || 0}</strong></span>
            </div>
          </div>

        </div>
      </div>

      {/* 7 Main Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Requests"
          value={stats.totalRequests}
          subtitle="Cumulative telemetry"
          icon={Radio}
          color="blue"
        />
        <StatCard
          title="Requests Per Second"
          value={stats.currentRps}
          badge={`${stats.currentRps > (stats.thresholds?.rpsThreshold || 500) ? 'OVER THRESHOLD' : 'STABLE'}`}
          subtitle={`Threshold: ${stats.thresholds?.rpsThreshold || 500} req/s`}
          icon={Activity}
          color={stats.currentRps > (stats.thresholds?.rpsThreshold || 500) ? 'rose' : 'emerald'}
        />
        <StatCard
          title="Suspicious Requests"
          value={stats.suspiciousRequests}
          subtitle={`${stats.currentSuspiciousRps} req/s anomalous`}
          icon={AlertOctagon}
          color="rose"
        />
        <StatCard
          title="Blocked Requests"
          value={stats.blockedRequests}
          subtitle={`${stats.currentBlockedRps} req/s suppressed`}
          icon={ShieldCheck}
          color="cyan"
        />
        <StatCard
          title="Current Threat Level"
          value={stats.threatLevel}
          subtitle={`Threat Index: ${stats.threatScore}/100`}
          icon={ShieldAlert}
          color={stats.threatLevel === 'CRITICAL' ? 'rose' : stats.threatLevel === 'HIGH' ? 'amber' : 'emerald'}
        />
        <StatCard
          title="Active Alerts"
          value={stats.activeAlertsCount}
          subtitle="Security notifications"
          icon={Flame}
          color={stats.activeAlertsCount > 0 ? 'amber' : 'emerald'}
        />
        <StatCard
          title="Detection Accuracy"
          value={`${stats.detectionAccuracy}%`}
          subtitle="Simulated Precision"
          icon={Zap}
          color="purple"
        />
        <div className="cyber-panel p-4 rounded-xl flex flex-col justify-between border-slate-800 bg-slate-900/30">
          <div>
            <p className="text-xs font-mono text-slate-400 uppercase">Interactive Demo</p>
            <p className="text-xs text-slate-300 mt-1">Simulate attack scenarios safely in-memory:</p>
          </div>
          <div className="grid grid-cols-2 gap-2 mt-2">
            <button
              onClick={() => setSimulationMode('normal')}
              className={`px-2 py-1.5 rounded text-[11px] font-mono border transition-all ${
                stats.mode === 'normal' 
                  ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/50' 
                  : 'bg-slate-800 text-slate-300 border-slate-700 hover:border-emerald-500/50'
              }`}
            >
              Normal Traffic
            </button>
            <button
              onClick={() => setSimulationMode('http_flood')}
              className={`px-2 py-1.5 rounded text-[11px] font-mono border transition-all ${
                stats.mode === 'http_flood' 
                  ? 'bg-rose-500/20 text-rose-300 border-rose-500/50' 
                  : 'bg-slate-800 text-slate-300 border-slate-700 hover:border-rose-500/50'
              }`}
            >
              HTTP Flood
            </button>
          </div>
        </div>
      </div>

      {/* Main Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Real-time Time vs RPS Area Chart (2 cols) */}
        <div className="lg:col-span-2 cyber-panel p-5 rounded-xl border border-slate-800">
          <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
            <div>
              <h2 className="text-sm font-mono font-bold text-white flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                <span>REAL-TIME TRAFFIC TELEMETRY (RPS)</span>
              </h2>
              <p className="text-xs text-slate-400 font-mono">Time vs Requests Per Second with Dynamic Threshold</p>
            </div>
            <div className="flex items-center gap-3 text-xs font-mono">
              <span className="flex items-center gap-1 text-cyan-400">
                <span className="w-2.5 h-2.5 rounded-sm bg-cyan-400" /> Total RPS
              </span>
              <span className="flex items-center gap-1 text-rose-400">
                <span className="w-2.5 h-2.5 rounded-sm bg-rose-400" /> Attack RPS
              </span>
              <span className="flex items-center gap-1 text-amber-400">
                <span className="w-2 h-0.5 bg-amber-400" /> Limit ({stats.thresholds?.rpsThreshold})
              </span>
            </div>
          </div>

          <div className="h-72 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeSeries} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="totalRpsGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#06B6D4" stopOpacity={0.0}/>
                  </linearGradient>
                  <linearGradient id="attackRpsGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#F43F5E" stopOpacity={0.6}/>
                    <stop offset="95%" stopColor="#F43F5E" stopOpacity={0.0}/>
                  </linearGradient>
                </defs>
                <XAxis 
                  dataKey="timeLabel" 
                  stroke="#475569" 
                  tick={{ fill: '#94A3B8', fontSize: 10, fontFamily: 'monospace' }} 
                />
                <YAxis 
                  stroke="#475569" 
                  tick={{ fill: '#94A3B8', fontSize: 10, fontFamily: 'monospace' }} 
                />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#0E1422', 
                    borderColor: '#1E2B48', 
                    borderRadius: '8px', 
                    fontFamily: 'monospace',
                    fontSize: '11px',
                    color: '#fff'
                  }} 
                />
                <ReferenceLine 
                  y={stats.thresholds?.rpsThreshold || 500} 
                  stroke="#F59E0B" 
                  strokeDasharray="4 4" 
                  label={{ value: 'THREAT THRESHOLD', fill: '#F59E0B', fontSize: 10, position: 'top', fontFamily: 'monospace' }} 
                />
                <Area 
                  type="monotone" 
                  dataKey="rps" 
                  stroke="#06B6D4" 
                  strokeWidth={2} 
                  fillOpacity={1} 
                  fill="url(#totalRpsGrad)" 
                  name="Total RPS" 
                  isAnimationActive={false}
                />
                <Area 
                  type="monotone" 
                  dataKey="attackRps" 
                  stroke="#F43F5E" 
                  strokeWidth={2} 
                  fillOpacity={1} 
                  fill="url(#attackRpsGrad)" 
                  name="Attack RPS" 
                  isAnimationActive={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Traffic Composition Donut (1 col) */}
        <div className="cyber-panel p-5 rounded-xl border border-slate-800 flex flex-col justify-between">
          <div>
            <h2 className="text-sm font-mono font-bold text-white flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span>CURRENT TRAFFIC COMPOSITION</span>
            </h2>
            <p className="text-xs text-slate-400 font-mono">Live packet distribution breakdown</p>
          </div>

          <div className="h-56 w-full flex items-center justify-center my-2">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#0E1422', 
                    borderColor: '#1E2B48', 
                    borderRadius: '8px', 
                    fontFamily: 'monospace',
                    fontSize: '11px',
                    color: '#fff'
                  }} 
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="space-y-1.5 text-xs font-mono">
            {pieData.map(item => (
              <div key={item.name} className="flex items-center justify-between p-1.5 rounded bg-slate-900/60 border border-slate-800">
                <span className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                  <span className="text-slate-300">{item.name}</span>
                </span>
                <span className="font-bold text-white">{item.value} req/s</span>
              </div>
            ))}
          </div>
        </div>

      </div>

      {/* Controls & Configuration Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Attack Scenario Switcher (1 col) */}
        <div className="cyber-panel p-5 rounded-xl border border-slate-800">
          <h2 className="text-sm font-mono font-bold text-white flex items-center gap-2 mb-1">
            <Flame className="w-4 h-4 text-rose-400" />
            <span>ATTACK SCENARIO SIMULATOR</span>
          </h2>
          <p className="text-xs text-slate-400 font-mono mb-4">Select attack vector to inject safe sample telemetry:</p>

          <div className="space-y-2">
            {[
              { id: 'normal', label: 'Normal Traffic', desc: 'Baseline legitimate web queries (20-60 RPS)', color: 'border-emerald-600/40 hover:bg-emerald-950/30' },
              { id: 'http_flood', label: 'HTTP Flood (L7)', desc: 'Rapid HTTP GET/POST flooding port 80/443', color: 'border-rose-600/40 hover:bg-rose-950/30' },
              { id: 'syn_flood', label: 'SYN Flood (L4)', desc: 'Unacknowledged TCP SYN packets (Half-open)', color: 'border-amber-600/40 hover:bg-amber-950/30' },
              { id: 'udp_flood', label: 'UDP Flood (L4)', desc: 'High-volume datagram bursts on random ports', color: 'border-purple-600/40 hover:bg-purple-950/30' },
              { id: 'icmp_flood', label: 'ICMP Flood (L3)', desc: 'Massive Ping Echo Request bandwidth exhaustion', color: 'border-blue-600/40 hover:bg-blue-950/30' }
            ].map(scn => (
              <button
                key={scn.id}
                onClick={() => setSimulationMode(scn.id)}
                className={`w-full text-left p-2.5 rounded-lg border font-mono transition-all flex items-center justify-between ${scn.color} ${
                  stats.mode === scn.id ? 'bg-slate-800 border-cyan-400 shadow-[0_0_10px_rgba(6,182,212,0.3)]' : 'bg-slate-900/40'
                }`}
              >
                <div>
                  <div className="text-xs font-bold text-white flex items-center gap-1.5">
                    {stats.mode === scn.id && <span className="w-2 h-2 rounded-full bg-cyan-400 pulse-beacon" />}
                    {scn.label}
                  </div>
                  <div className="text-[10px] text-slate-400 mt-0.5">{scn.desc}</div>
                </div>
                <ArrowRight className="w-3.5 h-3.5 text-slate-500" />
              </button>
            ))}
          </div>
        </div>

        {/* Threshold Configuration Station (1 col) */}
        <div className="cyber-panel p-5 rounded-xl border border-slate-800">
          <h2 className="text-sm font-mono font-bold text-white flex items-center gap-2 mb-1">
            <Sliders className="w-4 h-4 text-cyan-400" />
            <span>DETECTION THRESHOLD CONTROLS</span>
          </h2>
          <p className="text-xs text-slate-400 font-mono mb-4">Fine-tune detection sensitivity and limits:</p>

          <form onSubmit={handleSaveThresholds} className="space-y-4 font-mono text-xs">
            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span>RPS Ceiling:</span>
                <span className="font-bold text-cyan-400">{localRpsThreshold} req/s</span>
              </div>
              <input
                type="range"
                min="100"
                max="1200"
                step="50"
                value={localRpsThreshold}
                onChange={(e) => setLocalRpsThreshold(e.target.value)}
                className="w-full accent-cyan-400 bg-slate-800 rounded-lg cursor-pointer"
              />
              <span className="text-[10px] text-slate-500">Triggers DDoS classification when aggregate RPS exceeds this value.</span>
            </div>

            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span>Bandwidth Volume Threshold:</span>
                <span className="font-bold text-cyan-400">{localVolumeThreshold} MB/s</span>
              </div>
              <input
                type="range"
                min="5"
                max="50"
                step="5"
                value={localVolumeThreshold}
                onChange={(e) => setLocalVolumeThreshold(e.target.value)}
                className="w-full accent-cyan-400 bg-slate-800 rounded-lg cursor-pointer"
              />
              <span className="text-[10px] text-slate-500">Flags volumetric bandwidth saturation above this rate.</span>
            </div>

            <div className="pt-2">
              <button
                type="submit"
                className="w-full py-2 px-3 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold tracking-wide shadow-md transition-all flex items-center justify-center gap-2"
              >
                <CheckCircle2 className="w-4 h-4" />
                <span>Apply Detection Thresholds</span>
              </button>
            </div>
          </form>
        </div>

        {/* Active Security Alerts Feed (1 col) */}
        <div className="cyber-panel p-5 rounded-xl border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-sm font-mono font-bold text-white flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-amber-400" />
                <span>LATEST SECURITY ALERTS</span>
              </h2>
              <button
                onClick={() => setActiveTab('alerts')}
                className="text-xs font-mono text-cyan-400 hover:underline flex items-center gap-1"
              >
                View All ({alerts.length})
              </button>
            </div>
            <p className="text-xs text-slate-400 font-mono mb-3">Real-time attack warnings & remediations</p>

            {recentActiveAlerts.length === 0 ? (
              <div className="p-6 text-center rounded-lg bg-slate-900/40 border border-slate-800/80 text-xs font-mono text-slate-400">
                <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-70" />
                <span>No active alerts. System telemetry normal.</span>
              </div>
            ) : (
              <div className="space-y-2.5">
                {recentActiveAlerts.map(alert => (
                  <div 
                    key={alert.id}
                    className="p-3 rounded-lg bg-slate-900/80 border border-amber-500/30 font-mono text-xs space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <span className="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 text-[10px] font-bold">
                        {alert.severity}
                      </span>
                      <span className="text-[10px] text-slate-500">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                    </div>
                    <p className="font-semibold text-slate-200 text-xs leading-tight">{alert.title}</p>
                    <p className="text-[11px] text-slate-400 line-clamp-2">{alert.reason}</p>
                    <div className="pt-1 flex items-center justify-between gap-2">
                      <button
                        onClick={() => {
                          if (alert.offendingIPs?.[0]) {
                            blockIP(alert.offendingIPs[0], `Remediated from alert: ${alert.title}`);
                          }
                          resolveAlert(alert.id);
                        }}
                        className="px-2 py-1 rounded bg-rose-600/80 hover:bg-rose-500 text-white text-[10px] font-bold transition-all"
                      >
                        Block Source & Resolve
                      </button>
                      <button
                        onClick={() => resolveAlert(alert.id)}
                        className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] transition-all"
                      >
                        Dismiss
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="pt-3 border-t border-slate-800/80 text-[11px] font-mono text-slate-500 flex justify-between">
            <span>Detection: Explainable Rules</span>
            <span className="text-cyan-400">SOC Auto-Triage</span>
          </div>
        </div>

      </div>

    </div>
  );
};
