import React from 'react';
import { 
  LayoutDashboard, 
  Activity, 
  AlertTriangle, 
  FileText,
  BarChart3, 
  ShieldCheck, 
  Cpu, 
  GraduationCap, 
  ShieldAlert,
  Server
} from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';

export const Sidebar = ({ activeTab, setActiveTab }) => {
  const { alerts, stats } = useSecurity();
  const activeAlertCount = alerts.filter(a => a.status === 'active').length;

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard, badge: null },
    { id: 'traffic', label: 'Traffic Monitor', icon: Activity, badge: `${stats.currentRps} RPS` },
    { id: 'alerts', label: 'Security Alerts', icon: AlertTriangle, badge: activeAlertCount > 0 ? activeAlertCount : null, alertColor: 'rose' },
    { id: 'incidents', label: 'Incident Forensics', icon: FileText, badge: 'Cases' },
    { id: 'analytics', label: 'Analytics & Trends', icon: BarChart3, badge: null },
    { id: 'mitigation', label: 'Mitigation Rules', icon: ShieldCheck, badge: null },
    { id: 'how-it-works', label: 'How It Works', icon: Cpu, badge: 'Flow' },
    { id: 'about', label: 'Project & Viva Prep', icon: GraduationCap, badge: '10 Q&A' }
  ];

  return (
    <aside className="w-full lg:w-64 bg-[#0A0E1A] border-r border-slate-800/80 flex flex-col justify-between shrink-0">
      
      {/* Brand & SOC Identity */}
      <div>
        <div className="p-5 border-b border-slate-800/70">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 shadow-[0_0_20px_rgba(6,182,212,0.4)]">
              <ShieldAlert className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="font-mono font-extrabold text-sm tracking-wide text-white flex items-center gap-1.5">
                DDOS SHIELD
                <span className="text-[10px] bg-cyan-500/20 text-cyan-400 px-1.5 py-0.2 rounded border border-cyan-500/30">v1.0</span>
              </h1>
              <p className="text-[11px] text-slate-400 font-mono tracking-tight">Detection & Mitigation SOC</p>
            </div>
          </div>
        </div>

        {/* Navigation Items */}
        <nav className="p-3 space-y-1">
          {navItems.map(item => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                id={`nav-${item.id}`}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-xs font-mono transition-all group ${
                  isActive
                    ? 'bg-cyan-950/50 text-cyan-300 border border-cyan-500/40 shadow-[0_0_15px_-3px_rgba(6,182,212,0.25)] font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Icon className={`w-4 h-4 transition-colors ${isActive ? 'text-cyan-400' : 'text-slate-400 group-hover:text-cyan-400'}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge && (
                  <span
                    className={`text-[10px] px-2 py-0.5 rounded-full font-mono border ${
                      item.alertColor === 'rose'
                        ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 animate-pulse'
                        : 'bg-slate-800 text-slate-300 border-slate-700'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Target Asset Telemetry Card */}
      <div className="p-4 border-t border-slate-800/70">
        <div className="cyber-panel p-3 bg-slate-950/60 rounded-lg border border-slate-800 text-xs font-mono">
          <div className="flex items-center gap-2 text-slate-300 font-medium mb-1.5">
            <Server className="w-3.5 h-3.5 text-cyan-400" />
            <span>Target Protected Gateway</span>
          </div>
          <p className="text-[11px] text-slate-400">IP: <span className="text-cyan-300">192.168.1.1</span></p>
          <p className="text-[11px] text-slate-400">Services: <span className="text-slate-300">HTTP/HTTPS/DNS</span></p>
          <div className="mt-2 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] text-slate-500">
            <span>Simulation: In-Memory</span>
            <span className="text-emerald-400">RFC-1918 Safe</span>
          </div>
        </div>
      </div>

    </aside>
  );
};
