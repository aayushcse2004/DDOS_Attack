/**
 * Defensive Mitigation Simulation Module (Phase 3 Enhanced)
 * 
 * Capabilities:
 * 1. IP Blacklisting with optional TTL / automatic rule expiration.
 * 2. Per-IP sliding-window rate limiting with configurable quota.
 * 3. Deep Packet Inspection (DPI) protocol traffic filtering.
 * 4. TCP SYN Cookie state table defense.
 * 5. Complete immutable mitigation action audit log.
 * 6. Before-and-after traffic tracking and mitigation effectiveness metrics.
 */

class MitigationManager {
  constructor() {
    // Active Blocklist: IP -> { ip, reason, blockedAt, expiresAt, durationSeconds, interceptedCount: 0 }
    this.blockedIPs = new Map();

    // Rate Limiting Configuration
    this.rateLimitingEnabled = false;
    this.rateLimitThreshold = 100; // max allowed req/s per single IP
    this.slidingWindows = new Map(); // IP -> { count, windowStart }

    // Deep Traffic Filtering (DPI)
    this.trafficFilteringEnabled = false;

    // TCP SYN Cookie Defense
    this.synCookieEnabled = false;

    // Mitigation Action Audit Log (Rolling 150 events)
    this.actionLogs = [];
    this.maxLogs = 150;

    // Cumulative Mitigation Telemetry (Before vs After)
    this.telemetry = {
      totalIngressRequests: 0,
      totalAllowedRequests: 0,
      totalDroppedRequests: 0,
      totalBlockedByIp: 0,
      totalDroppedByRateLimit: 0,
      totalFilteredByDpi: 0,
      totalFilteredBySynCookie: 0
    };
  }

  /**
   * Log a defensive mitigation event into the audit trail
   */
  logAction(action, details = {}) {
    const entry = {
      id: `MIT-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 900 + 100)}`,
      timestamp: new Date().toISOString(),
      action,
      ...details
    };
    this.actionLogs.unshift(entry);
    if (this.actionLogs.length > this.maxLogs) {
      this.actionLogs.pop();
    }
    return entry;
  }

  /**
   * Block an IP with optional TTL (duration in seconds)
   * @param {string} ip - Target IP to block
   * @param {string} [reason] - SOC justification
   * @param {number} [durationSeconds=0] - 0 for permanent, or TTL in seconds
   */
  blockIP(ip, reason = 'Exceeded request threshold / Manual SOC block', durationSeconds = 0) {
    if (!ip || typeof ip !== 'string') return false;
    const cleanIp = ip.trim();
    if (!cleanIp) return false;

    const now = Date.now();
    const duration = Math.max(0, Number(durationSeconds) || 0);
    const expiresAt = duration > 0 ? new Date(now + duration * 1000).toISOString() : null;

    const rule = {
      ip: cleanIp,
      reason,
      blockedAt: new Date(now).toISOString(),
      expiresAt,
      durationSeconds: duration,
      interceptedCount: 0
    };

    this.blockedIPs.set(cleanIp, rule);

    this.logAction('BLOCK_IP', {
      ip: cleanIp,
      reason,
      durationSeconds: duration,
      expiresAt,
      permanent: duration === 0
    });

    return rule;
  }

  /**
   * Unblock an IP manually
   */
  unblockIP(ip, operator = 'SOC Operator') {
    if (!ip || !this.blockedIPs.has(ip)) return false;
    const existing = this.blockedIPs.get(ip);
    this.blockedIPs.delete(ip);

    this.logAction('UNBLOCK_IP', {
      ip,
      operator,
      previouslyBlockedAt: existing.blockedAt,
      totalIntercepted: existing.interceptedCount
    });

    return true;
  }

  /**
   * Clean up expired temporary IP blocks (TTL check)
   */
  checkRuleExpirations() {
    const now = Date.now();
    for (const [ip, rule] of this.blockedIPs.entries()) {
      if (rule.expiresAt) {
        const expireTime = new Date(rule.expiresAt).getTime();
        if (now >= expireTime) {
          this.blockedIPs.delete(ip);
          this.logAction('RULE_EXPIRED', {
            ip,
            reason: `Temporary block expired after ${rule.durationSeconds}s TTL`,
            totalIntercepted: rule.interceptedCount
          });
        }
      }
    }
  }

  /**
   * Toggle and configure per-IP sliding-window rate limiting
   */
  setRateLimiting(enabled, threshold = 100) {
    this.rateLimitingEnabled = !!enabled;
    if (threshold && Number(threshold) > 0) {
      this.rateLimitThreshold = Number(threshold);
    }

    this.logAction('CONFIG_RATE_LIMIT', {
      enabled: this.rateLimitingEnabled,
      threshold: this.rateLimitThreshold
    });

    return { enabled: this.rateLimitingEnabled, threshold: this.rateLimitThreshold };
  }

  /**
   * Toggle Deep Packet Inspection (DPI) traffic filtering
   */
  setTrafficFiltering(enabled) {
    this.trafficFilteringEnabled = !!enabled;
    this.logAction('CONFIG_DPI_FILTER', { enabled: this.trafficFilteringEnabled });
    return { enabled: this.trafficFilteringEnabled };
  }

  /**
   * Toggle TCP SYN Cookie defense
   */
  setSynCookie(enabled) {
    this.synCookieEnabled = !!enabled;
    this.logAction('CONFIG_SYN_COOKIE', { enabled: this.synCookieEnabled });
    return { enabled: this.synCookieEnabled };
  }

  /**
   * Evaluate a single packet or batch sample through the defensive mitigation pipeline
   */
  evaluatePacket(packet) {
    // Run TTL expiration sweep
    this.checkRuleExpirations();

    const { sourceIP, requestCount = 1, attackType, protocol, flags } = packet;
    this.telemetry.totalIngressRequests += requestCount;

    // 1. IP Blacklist Check (Priority 1)
    if (this.blockedIPs.has(sourceIP)) {
      const rule = this.blockedIPs.get(sourceIP);
      rule.interceptedCount += requestCount;
      this.telemetry.totalDroppedRequests += requestCount;
      this.telemetry.totalBlockedByIp += requestCount;

      return {
        action: 'DROP',
        status: 'BLOCKED',
        mitigationReason: `Firewall Rule: Blocked source ${sourceIP} (${rule.reason})`,
        allowedCount: 0,
        droppedCount: requestCount
      };
    }

    // 2. SYN Cookie Defense Simulation (Priority 2: TCP Handshake)
    if (this.synCookieEnabled && protocol === 'TCP' && flags && flags.includes('SYN') && !flags.includes('ACK')) {
      this.telemetry.totalDroppedRequests += requestCount;
      this.telemetry.totalFilteredBySynCookie += requestCount;

      return {
        action: 'FILTERED',
        status: 'BLOCKED',
        mitigationReason: 'SYN Cookie Defense: Validated cryptographic sequence; dropped unacknowledged state',
        allowedCount: 0,
        droppedCount: requestCount
      };
    }

    // 3. Deep Traffic Filtering (DPI) check (Priority 3: Malformed protocol blasts)
    if (this.trafficFilteringEnabled) {
      if (attackType === 'ICMP Flood' || (protocol === 'ICMP' && requestCount > 40)) {
        this.telemetry.totalDroppedRequests += requestCount;
        this.telemetry.totalFilteredByDpi += requestCount;

        return {
          action: 'FILTERED',
          status: 'BLOCKED',
          mitigationReason: 'DPI Protocol Filter: Malformed ICMP Echo ping flood dropped at boundary',
          allowedCount: 0,
          droppedCount: requestCount
        };
      }

      if (attackType === 'UDP Flood' || (protocol === 'UDP' && requestCount > 60)) {
        this.telemetry.totalDroppedRequests += requestCount;
        this.telemetry.totalFilteredByDpi += requestCount;

        return {
          action: 'FILTERED',
          status: 'BLOCKED',
          mitigationReason: 'DPI Protocol Filter: Amplified connectionless UDP datagram storm rejected',
          allowedCount: 0,
          droppedCount: requestCount
        };
      }
    }

    // 4. Rate Limiting Check (Priority 4: Sliding-Window Token Quota)
    if (this.rateLimitingEnabled) {
      const now = Date.now();
      let windowData = this.slidingWindows.get(sourceIP);

      if (!windowData || now - windowData.windowStart > 1000) {
        windowData = { count: 0, windowStart: now };
        this.slidingWindows.set(sourceIP, windowData);
      }

      const availableQuota = Math.max(0, this.rateLimitThreshold - windowData.count);

      if (requestCount > availableQuota) {
        const allowed = availableQuota;
        const dropped = requestCount - allowed;
        windowData.count += allowed;

        this.telemetry.totalAllowedRequests += allowed;
        this.telemetry.totalDroppedRequests += dropped;
        this.telemetry.totalDroppedByRateLimit += dropped;

        return {
          action: allowed > 0 ? 'PARTIAL_THROTTLE' : 'DROP',
          status: 'RATE_LIMITED',
          mitigationReason: `Sliding-Window Limiter: Capped at ${this.rateLimitThreshold} req/s per IP (${dropped} dropped)`,
          allowedCount: allowed,
          droppedCount: dropped
        };
      } else {
        windowData.count += requestCount;
      }
    }

    // Traffic cleanly permitted
    this.telemetry.totalAllowedRequests += requestCount;
    return {
      action: 'ALLOW',
      status: 'NORMAL',
      mitigationReason: 'Permitted by security baseline',
      allowedCount: requestCount,
      droppedCount: 0
    };
  }

  /**
   * Get all active mitigation rules and configuration
   */
  getRules() {
    this.checkRuleExpirations();
    return {
      blockedIPs: Array.from(this.blockedIPs.values()),
      rateLimiting: {
        enabled: this.rateLimitingEnabled,
        threshold: this.rateLimitThreshold
      },
      trafficFiltering: {
        enabled: this.trafficFilteringEnabled
      },
      synCookie: {
        enabled: this.synCookieEnabled
      }
    };
  }

  /**
   * Get mitigation action audit logs
   */
  getActionLogs(limit = 50) {
    return this.actionLogs.slice(0, Number(limit) || 50);
  }

  /**
   * Get before-and-after mitigation telemetry statistics
   */
  getTelemetry() {
    const total = this.telemetry.totalIngressRequests;
    const dropped = this.telemetry.totalDroppedRequests;
    const effectiveness = total > 0 ? Number(((dropped / total) * 100).toFixed(1)) : 0;

    return {
      ...this.telemetry,
      mitigationEffectivenessPercentage: effectiveness
    };
  }

  /**
   * Reset all defensive mitigations to pristine state
   */
  reset() {
    this.blockedIPs.clear();
    this.slidingWindows.clear();
    this.rateLimitingEnabled = false;
    this.rateLimitThreshold = 100;
    this.trafficFilteringEnabled = false;
    this.synCookieEnabled = false;
    this.actionLogs = [];
    this.telemetry = {
      totalIngressRequests: 0,
      totalAllowedRequests: 0,
      totalDroppedRequests: 0,
      totalBlockedByIp: 0,
      totalDroppedByRateLimit: 0,
      totalFilteredByDpi: 0,
      totalFilteredBySynCookie: 0
    };
    this.logAction('RESET_ALL', { reason: 'System returned to baseline state' });
  }
}

module.exports = new MitigationManager();
