import React from 'react';
import { CheckCircle2, AlertTriangle, AlertOctagon, Info, X } from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';

export const Toast = () => {
  const { toast } = useSecurity();

  if (!toast) return null;

  const typeConfig = {
    success: {
      icon: CheckCircle2,
      border: 'border-emerald-500/50',
      bg: 'bg-emerald-950/90 text-emerald-200',
      iconColor: 'text-emerald-400'
    },
    warning: {
      icon: AlertTriangle,
      border: 'border-amber-500/50',
      bg: 'bg-amber-950/90 text-amber-200',
      iconColor: 'text-amber-400'
    },
    error: {
      icon: AlertOctagon,
      border: 'border-rose-500/50',
      bg: 'bg-rose-950/90 text-rose-200',
      iconColor: 'text-rose-400'
    },
    info: {
      icon: Info,
      border: 'border-cyan-500/50',
      bg: 'bg-slate-900/95 text-cyan-200',
      iconColor: 'text-cyan-400'
    }
  };

  const current = typeConfig[toast.type] || typeConfig.info;
  const Icon = current.icon;

  return (
    <div className="fixed bottom-6 right-6 z-50 animate-bounce-in max-w-md">
      <div className={`cyber-panel flex items-start gap-3 p-4 rounded-lg shadow-2xl border ${current.border} ${current.bg} backdrop-blur-md`}>
        <Icon className={`w-5 h-5 flex-shrink-0 mt-0.5 ${current.iconColor}`} />
        <div className="text-sm font-medium font-mono leading-tight flex-1">
          {toast.message}
        </div>
      </div>
    </div>
  );
};
