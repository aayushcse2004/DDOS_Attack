import React from 'react';
import { Play, Pause, RotateCcw, ShieldAlert, Sparkles, Activity, Wifi, WifiOff } from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';

export const Header = () => {
  const { stats, toggleSimulation, resetSimulation, setSimulationMode, isConnected } = useSecurity();

  const threatColorMap = {
    LOW: {
      badge: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
      dot: 'bg-emerald-400',
      glow: 'shadow-[0_0_12px_rgba(16,185,129,0.4)]'
    },
    MEDIUM: {
      badge: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
      dot: 'bg-yellow-400',
      glow: 'shadow-[0_0_12px_rgba(234,179,8,0.4)]'
    },
    HIGH: {
      badge: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
      dot: 'bg-amber-400',
      glow: 'shadow-[0_0_12px_rgba(245,158,11,0.4)]'
    },
    CRITICAL: {
      badge: 'bg-rose-500/20 text-rose-400 border-rose-500/50 animate-pulse',
      dot: 'bg-rose-500',
      glow: 'shadow-[0_0_20px_rgba(244,63,94,0.6)]'
    }
  };

  const threatStyle = threatColorMap[stats.threatLevel] || threatColorMap.LOW;

  return (
    <header className="sticky top-0 z-40 bg-[#080C14]/90 backdrop-blur-md border-b border-slate-800/80 px-4 lg:px-8 py-3.5">
      <div className="flex flex-wrap items-center justify-between gap-4">
        
        {/* Left: System Status & Telemetry Beacon */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-slate-900/80 border border-slate-700/60 text-xs font-mono">
            {isConnected ? (
              <span className="flex items-center gap-1.5 text-emerald-400">
                <span className="w-2 h-2 rounded-full bg-emerald-400 pulse-beacon" />
                <span>TELEMETRY SYNCED</span>
              </span>
            ) : (
              <span className="flex items-center gap-1.5 text-rose-400">
                <span className="w-2 h-2 rounded-full bg-rose-400" />
                <span>OFFLINE</span>
              </span>
            )}
            <span className="text-slate-600">|</span>
            <span className="text-slate-300">CORE: {stats.isRunning ? 'ACTIVE' : 'PAUSED'}</span>
          </div>

          {/* Active Mode Pill */}
          <div className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-900/80 border border-slate-700/60 text-xs font-mono">
            <span className="text-slate-400">MODE:</span>
            <span className="text-cyan-400 font-semibold uppercase tracking-wider">
              {stats.mode === 'demo' ? `DEMO (PHASE ${stats.demoPhase}/4)` : stats.mode.replace('_', ' ')}
            </span>
          </div>
        </div>

        {/* Center/Right: Threat Level Badge & Controls */}
        <div className="flex items-center flex-wrap gap-3">
          
          {/* Global Threat Level Badge */}
          <div className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg border font-mono text-xs font-bold tracking-wider ${threatStyle.badge} ${threatStyle.glow}`}>
            <span className={`w-2 h-2 rounded-full ${threatStyle.dot}`} />
            <span>THREAT: {stats.threatLevel}</span>
            <span className="text-slate-400 font-normal">({stats.threatScore}/100)</span>
          </div>

          {/* Demo Mode Button */}
          <button
            id="demo-mode-btn"
            onClick={() => setSimulationMode('demo')}
            className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg font-mono text-xs font-semibold tracking-wide transition-all border ${
              stats.mode === 'demo'
                ? 'bg-purple-600 text-white border-purple-400 shadow-[0_0_15px_rgba(139,92,246,0.5)]'
                : 'bg-purple-950/40 text-purple-300 border-purple-700/50 hover:bg-purple-900/60 hover:border-purple-400'
            }`}
            title="Start automated 4-phase demonstration for professors & evaluators"
          >
            <Sparkles className="w-3.5 h-3.5 text-purple-400 animate-spin-slow" />
            <span>DEMO MODE</span>
          </button>

          {/* Play/Pause Simulator */}
          <button
            id="toggle-sim-btn"
            onClick={toggleSimulation}
            className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg font-mono text-xs font-semibold tracking-wide transition-all border ${
              stats.isRunning
                ? 'bg-amber-950/40 text-amber-300 border-amber-700/50 hover:bg-amber-900/50'
                : 'bg-emerald-950/40 text-emerald-300 border-emerald-700/50 hover:bg-emerald-900/50'
            }`}
          >
            {stats.isRunning ? (
              <>
                <Pause className="w-3.5 h-3.5" />
                <span>PAUSE SIM</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" />
                <span>RESUME SIM</span>
              </>
            )}
          </button>

          {/* Reset Simulator */}
          <button
            id="reset-sim-btn"
            onClick={resetSimulation}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900/80 text-slate-300 border border-slate-700 hover:text-white hover:border-cyan-500 font-mono text-xs transition-all"
            title="Reset simulation data to baseline"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span className="hidden md:inline">RESET</span>
          </button>
        </div>

      </div>
    </header>
  );
};
