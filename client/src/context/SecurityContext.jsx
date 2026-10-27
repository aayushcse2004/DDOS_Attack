import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import { api } from '../services/api';

const SecurityContext = createContext(null);

export const SecurityProvider = ({ children }) => {
  // Telemetry & System state
  const [stats, setStats] = useState({
    isRunning: true,
    mode: 'normal',
    demoPhase: 0,
    totalRequests: 14520,
    currentRps: 42,
    suspiciousRequests: 210,
    blockedRequests: 45,
    currentSuspiciousRps: 0,
    currentBlockedRps: 0,
    threatLevel: 'LOW',
    threatScore: 12,
    threatBadgeColor: 'emerald',
    threatDescription: 'Network operating within nominal parameters.',
    detectionAccuracy: 97.4,
    lastDetection: {
      isPotentialDDoS: false,
      classification: 'Normal',
      severity: 'LOW',
      primaryReason: 'Traffic parameters conform to nominal operating baseline.',
      accuracy: 97.4
    },
    activeAlertsCount: 0,
    thresholds: {
      rpsThreshold: 500,
      volumeThresholdMB: 20,
      singleIpRpsThreshold: 120,
      connectionThreshold: 350
    }
  });

  const [timeSeries, setTimeSeries] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [mitigationRules, setMitigationRules] = useState({
    blockedIPs: [],
    rateLimiting: { enabled: false, threshold: 100 },
    trafficFiltering: { enabled: false },
    synCookie: { enabled: false }
  });

  const [toast, setToast] = useState(null);
  const [isConnected, setIsConnected] = useState(true);
  const pollingRef = useRef(null);

  const showToast = useCallback((message, type = 'info') => {
    setToast({ message, type, id: Date.now() });
    setTimeout(() => {
      setToast(prev => (prev && prev.message === message ? null : prev));
    }, 4000);
  }, []);

  // Fetch telemetry updates
  const fetchTelemetry = useCallback(async () => {
    try {
      const [statsRes, historyRes, alertsRes, rulesRes] = await Promise.allSettled([
        api.getStats(),
        api.getHistory(),
        api.getAlerts('all'),
        api.getMitigationRules()
      ]);

      if (statsRes.status === 'fulfilled' && statsRes.value.success) {
        setStats(statsRes.value.data);
        setIsConnected(true);
      }
      if (historyRes.status === 'fulfilled' && historyRes.value.success) {
        setTimeSeries(historyRes.value.data);
      }
      if (alertsRes.status === 'fulfilled' && alertsRes.value.success) {
        setAlerts(alertsRes.value.data);
      }
      if (rulesRes.status === 'fulfilled' && rulesRes.value.success) {
        setMitigationRules(rulesRes.value.data);
      }
    } catch (err) {
      console.warn('Telemetry sync error:', err);
      setIsConnected(false);
    }
  }, []);

  // Polling loop
  useEffect(() => {
    fetchTelemetry();
    pollingRef.current = setInterval(fetchTelemetry, 1000);
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, [fetchTelemetry]);

  // Simulation Controls
  const toggleSimulation = async () => {
    try {
      if (stats.isRunning) {
        await api.stopSimulation();
        showToast('Traffic simulation halted.', 'warning');
      } else {
        await api.startSimulation();
        showToast('Traffic simulation resumed.', 'success');
      }
      fetchTelemetry();
    } catch (err) {
      showToast('Failed to toggle simulation: ' + err.message, 'error');
    }
  };

  const resetSimulation = async () => {
    try {
      await api.resetSimulation();
      showToast('Simulation state reset to pristine baseline.', 'info');
      fetchTelemetry();
    } catch (err) {
      showToast('Failed to reset simulation: ' + err.message, 'error');
    }
  };

  const setSimulationMode = async (mode) => {
    try {
      await api.setMode(mode);
      if (mode === 'normal') {
        showToast('Mode set to Normal Traffic baseline.', 'success');
      } else if (mode === 'demo') {
        showToast('Demo Mode initialized! Watch the multi-phase cycle.', 'info');
      } else {
        showToast(`Simulated attack launched: ${mode.replace('_', ' ').toUpperCase()}`, 'warning');
      }
      fetchTelemetry();
    } catch (err) {
      showToast('Failed to set mode: ' + err.message, 'error');
    }
  };

  const updateThresholds = async (newThresholds) => {
    try {
      const res = await api.updateThresholds(newThresholds);
      if (res.success) {
        showToast('Detection thresholds updated.', 'success');
        fetchTelemetry();
      }
    } catch (err) {
      showToast('Failed to update thresholds: ' + err.message, 'error');
    }
  };

  // Mitigation Controls
  const blockIP = async (ip, reason) => {
    try {
      const res = await api.blockIP(ip, reason);
      if (res.success) {
        showToast(`Firewall rule applied: Blocked ${ip}`, 'success');
        fetchTelemetry();
      }
    } catch (err) {
      showToast('Failed to block IP: ' + err.message, 'error');
    }
  };

  const unblockIP = async (ip) => {
    try {
      const res = await api.unblockIP(ip);
      if (res.success) {
        showToast(`Firewall rule revoked: Unblocked ${ip}`, 'info');
        fetchTelemetry();
      }
    } catch (err) {
      showToast('Failed to unblock IP: ' + err.message, 'error');
    }
  };

  const toggleRateLimiting = async (enabled, threshold) => {
    try {
      await api.setRateLimiting(enabled, threshold);
      showToast(`Rate limiting ${enabled ? 'ACTIVATED' : 'DEACTIVATED'} (${threshold || stats.thresholds.rpsThreshold} req/s)`, enabled ? 'success' : 'info');
      fetchTelemetry();
    } catch (err) {
      showToast('Failed to update rate limit: ' + err.message, 'error');
    }
  };

  const toggleTrafficFiltering = async (enabled) => {
    try {
      await api.setTrafficFiltering(enabled);
      showToast(`Deep Traffic Filtering ${enabled ? 'ENABLED' : 'DISABLED'}`, enabled ? 'success' : 'info');
      fetchTelemetry();
    } catch (err) {
      showToast('Failed to update traffic filter: ' + err.message, 'error');
    }
  };

  const toggleSynCookie = async (enabled) => {
    try {
      await api.setSynCookie(enabled);
      showToast(`TCP SYN Cookie defense ${enabled ? 'ENABLED' : 'DISABLED'}`, enabled ? 'success' : 'info');
      fetchTelemetry();
    } catch (err) {
      showToast('Failed to update SYN cookie: ' + err.message, 'error');
    }
  };

  const resolveAlert = async (id) => {
    try {
      await api.resolveAlert(id);
      showToast(`Alert ${id} resolved.`, 'success');
      fetchTelemetry();
    } catch (err) {
      showToast('Failed to resolve alert: ' + err.message, 'error');
    }
  };

  const resolveAllAlerts = async () => {
    try {
      await api.resolveAllAlerts();
      showToast('All active alerts marked resolved.', 'success');
      fetchTelemetry();
    } catch (err) {
      showToast('Failed to resolve alerts: ' + err.message, 'error');
    }
  };

  return (
    <SecurityContext.Provider
      value={{
        stats,
        timeSeries,
        alerts,
        mitigationRules,
        toast,
        isConnected,
        toggleSimulation,
        resetSimulation,
        setSimulationMode,
        updateThresholds,
        blockIP,
        unblockIP,
        toggleRateLimiting,
        toggleTrafficFiltering,
        toggleSynCookie,
        resolveAlert,
        resolveAllAlerts,
        showToast,
        refreshTelemetry: fetchTelemetry
      }}
    >
      {children}
    </SecurityContext.Provider>
  );
};

export const useSecurity = () => {
  const context = useContext(SecurityContext);
  if (!context) {
    throw new Error('useSecurity must be used within a SecurityProvider');
  }
  return context;
};
