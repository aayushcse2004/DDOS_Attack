import React from 'react';

export const StatCard = ({ title, value, subtitle, icon: Icon, color = 'cyan', badge, trend }) => {
  const colorMap = {
    cyan: {
      border: 'border-cyan-500/30',
      text: 'text-cyan-400',
      bg: 'bg-cyan-500/10',
      glow: 'shadow-[0_0_15px_-3px_rgba(6,182,212,0.25)]'
    },
    emerald: {
      border: 'border-emerald-500/30',
      text: 'text-emerald-400',
      bg: 'bg-emerald-500/10',
      glow: 'shadow-[0_0_15px_-3px_rgba(16,185,129,0.25)]'
    },
    amber: {
      border: 'border-amber-500/30',
      text: 'text-amber-400',
      bg: 'bg-amber-500/10',
      glow: 'shadow-[0_0_15px_-3px_rgba(245,158,11,0.25)]'
    },
    rose: {
      border: 'border-rose-500/30',
      text: 'text-rose-400',
      bg: 'bg-rose-500/10',
      glow: 'shadow-[0_0_15px_-3px_rgba(244,63,94,0.25)]'
    },
    purple: {
      border: 'border-purple-500/30',
      text: 'text-purple-400',
      bg: 'bg-purple-500/10',
      glow: 'shadow-[0_0_15px_-3px_rgba(139,92,246,0.25)]'
    },
    blue: {
      border: 'border-blue-500/30',
      text: 'text-blue-400',
      bg: 'bg-blue-500/10',
      glow: 'shadow-[0_0_15px_-3px_rgba(59,130,246,0.25)]'
    }
  };

  const scheme = colorMap[color] || colorMap.cyan;

  return (
    <div className={`cyber-panel p-5 relative overflow-hidden transition-all duration-300 hover:scale-[1.01] ${scheme.border} ${scheme.glow}`}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium tracking-wider uppercase text-slate-400 font-mono">{title}</p>
          <div className="mt-2 flex items-baseline gap-2">
            <span className={`text-2xl lg:text-3xl font-bold font-mono tracking-tight text-white`}>
              {typeof value === 'number' ? value.toLocaleString() : value}
            </span>
            {badge && (
              <span className={`text-xs px-2 py-0.5 rounded-full font-mono font-medium ${scheme.bg} ${scheme.text} border ${scheme.border}`}>
                {badge}
              </span>
            )}
          </div>
          {subtitle && (
            <p className="mt-1 text-xs text-slate-400 flex items-center gap-1">
              {trend && <span className={trend > 0 ? 'text-rose-400' : 'text-emerald-400'}>{trend > 0 ? '↑' : '↓'} {Math.abs(trend)}%</span>}
              <span>{subtitle}</span>
            </p>
          )}
        </div>
        {Icon && (
          <div className={`p-3 rounded-lg ${scheme.bg} ${scheme.text} border ${scheme.border}`}>
            <Icon className="w-5 h-5" />
          </div>
        )}
      </div>
      <div className={`absolute bottom-0 left-0 right-0 h-[2px] ${scheme.bg} opacity-50`} />
    </div>
  );
};
