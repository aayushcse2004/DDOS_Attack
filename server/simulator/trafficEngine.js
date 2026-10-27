/**
 * In-Memory Traffic Simulation Engine
 * Generates synthetic telemetry for educational DDoS demonstration.
 * Modifies only internal application state. Sends ZERO external network packets.
 */

const { BENIGN_IPS, ATTACK_IPS, TARGET_SERVER, HTTP_PATHS, USER_AGENTS } = require('./sampleData');
const mitigationManager = require('../mitigation/mitigationManager');
const detector = require('../detection/detector');
const { calculateThreatScore } = require('../detection/threatScorer');

class TrafficEngine {
  constructor() {
    this.isRunning = true;
    this.mode = 'normal'; // 'normal' | 'http_flood' | 'syn_flood' | 'udp_flood' | 'icmp_flood' | 'demo'
    this.demoPhase = 0;
    this.demoTimer = 0;
    this.intervalRef = null;

    // Rolling telemetry buffers
    this.recentPackets = [];
    this.maxPackets = 200;
    this.timeSeries = [];
    this.maxTimeSeries = 40;

    // Cumulative stats
    this.totalRequests = 14520;
    this.suspiciousRequests = 210;
    this.blockedRequests = 45;
    this.currentRps = 38;
    this.currentSuspiciousRps = 0;
    this.currentBlockedRps = 0;

    // Detection & Threat output state
    this.currentThreat = {
      score: 12,
      level: 'LOW',
      badgeColor: 'emerald',
      description: 'Network operating within nominal parameters.'
    };
    this.lastDetection = {
      isPotentialDDoS: false,
      classification: 'Normal',
      severity: 'LOW',
      primaryReason: 'Traffic parameters conform to nominal operating baseline.',
      reasons: ['Traffic parameters conform to nominal operating baseline.'],
      multiFactorAnalysis: {
        rps: { value: 38, threshold: 500, breached: false },
        bandwidth: { value: 0.8, threshold: 20, breached: false },
        uniqueIPs: { count: 8, topTalkerIP: '192.168.1.10', topTalkerRequests: 12, concentrationRatio: 0.15 },
        statistical: { baselineEma: 38.0, stdDev: 3.5, zScore: 0.0, growthRatio: 1.0, isAnomaly: false },
        protocol: { synCount: 0, ackCount: 15, synAckRatio: 0, udpCount: 0, icmpCount: 0, httpCount: 38 }
      }
    };

    // Pre-populate historical baseline for charts so user immediately sees smooth graphs
    this.seedHistoricalData();

    // Start simulation loop (1 tick per second)
    this.start();
  }

  seedHistoricalData() {
    const now = Date.now();
    for (let i = 30; i >= 1; i--) {
      const t = new Date(now - i * 1000);
      const timeLabel = t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      const baselineRps = Math.floor(30 + Math.random() * 20);
      this.timeSeries.push({
        timestamp: t.toISOString(),
        timeLabel,
        rps: baselineRps,
        normalRps: baselineRps,
        attackRps: 0,
        blockedRps: 0,
        threatScore: 10,
        threatLevel: 'LOW'
      });
    }
  }

  start() {
    if (this.intervalRef) return;
    this.isRunning = true;
    this.intervalRef = setInterval(() => this.tick(), 1000);
  }

  stop() {
    this.isRunning = false;
    if (this.intervalRef) {
      clearInterval(this.intervalRef);
      this.intervalRef = null;
    }
    this.currentRps = 0;
  }

  reset() {
    this.mode = 'normal';
    this.demoPhase = 0;
    this.demoTimer = 0;
    this.totalRequests = 1000;
    this.suspiciousRequests = 0;
    this.blockedRequests = 0;
    this.recentPackets = [];
    this.timeSeries = [];
    mitigationManager.reset();
    detector.reset();
    this.seedHistoricalData();
    if (!this.isRunning) {
      this.start();
    }
  }

  setMode(newMode) {
    const validModes = ['normal', 'http_flood', 'syn_flood', 'udp_flood', 'icmp_flood', 'demo'];
    if (validModes.includes(newMode)) {
      this.mode = newMode;
      if (newMode === 'demo') {
        this.demoPhase = 1;
        this.demoTimer = 0;
      }
      return true;
    }
    return false;
  }

  tick() {
    if (!this.isRunning) return;

    // Handle Demo Mode state progression
    if (this.mode === 'demo') {
      this.handleDemoProgression();
    }

    // Determine current attack scenario from mode
    let activeAttack = 'None';
    let attackBurstMultiplier = 1;

    if (this.mode === 'http_flood' || (this.mode === 'demo' && this.demoPhase === 2)) {
      activeAttack = 'HTTP Flood';
      attackBurstMultiplier = 16;
    } else if (this.mode === 'syn_flood') {
      activeAttack = 'SYN Flood';
      attackBurstMultiplier = 14;
    } else if (this.mode === 'udp_flood') {
      activeAttack = 'UDP Flood';
      attackBurstMultiplier = 18;
    } else if (this.mode === 'icmp_flood') {
      activeAttack = 'ICMP Flood';
      attackBurstMultiplier = 12;
    }

    // Generate batch of telemetry packet samples for this second
    const newPackets = [];
    let tickTotalRps = 0;
    let tickSuspiciousRps = 0;
    let tickBlockedRps = 0;
    let tickVolumeKB = 0;

    // 1. Generate Normal Benign Traffic
    const benignBatchSize = 4 + Math.floor(Math.random() * 4);
    for (let i = 0; i < benignBatchSize; i++) {
      const sourceIP = BENIGN_IPS[Math.floor(Math.random() * BENIGN_IPS.length)];
      const reqCount = Math.floor(4 + Math.random() * 9);
      const packet = {
        id: `PKT-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        timestamp: new Date().toISOString(),
        sourceIP,
        destIP: TARGET_SERVER.ip,
        port: [80, 443, 8080][Math.floor(Math.random() * 3)],
        protocol: 'HTTP',
        flags: 'PSH-ACK',
        requestCount: reqCount,
        packetVolumeKB: Number((reqCount * (1.2 + Math.random() * 0.8)).toFixed(2)),
        uri: HTTP_PATHS[Math.floor(Math.random() * HTTP_PATHS.length)],
        userAgent: USER_AGENTS[Math.floor(Math.random() * 3)],
        attackType: 'None'
      };

      // Pass through mitigation engine
      const evalResult = mitigationManager.evaluatePacket(packet);
      packet.status = evalResult.status;
      packet.mitigationReason = evalResult.mitigationReason;

      if (evalResult.status === 'BLOCKED') {
        tickBlockedRps += reqCount;
      } else if (evalResult.status === 'RATE_LIMITED') {
        tickBlockedRps += evalResult.droppedCount;
        tickTotalRps += evalResult.allowedCount;
      } else {
        tickTotalRps += reqCount;
      }
      tickVolumeKB += packet.packetVolumeKB;
      newPackets.push(packet);
    }

    // 2. Generate Attack Traffic (if active mode)
    if (activeAttack !== 'None') {
      const attackBatchSize = 8 + Math.floor(Math.random() * 6);
      for (let i = 0; i < attackBatchSize; i++) {
        const sourceIP = ATTACK_IPS[Math.floor(Math.random() * ATTACK_IPS.length)];
        const reqCount = Math.floor((30 + Math.random() * 40) * (attackBurstMultiplier / 3));
        
        let proto = 'HTTP';
        let flags = 'GET';
        let port = 80;
        let uri = '/search?bypass_cache=' + Math.random().toString(36).substring(7);

        if (activeAttack === 'SYN Flood') {
          proto = 'TCP';
          flags = 'SYN';
          port = [80, 443][Math.floor(Math.random() * 2)];
          uri = 'N/A (L4 SYN Handshake)';
        } else if (activeAttack === 'UDP Flood') {
          proto = 'UDP';
          flags = 'DATAGRAM';
          port = Math.floor(1024 + Math.random() * 60000);
          uri = 'N/A (L4 UDP Blast)';
        } else if (activeAttack === 'ICMP Flood') {
          proto = 'ICMP';
          flags = 'ECHO_REQ';
          port = 0;
          uri = 'N/A (L3 Echo Request)';
        }

        const packet = {
          id: `PKT-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
          timestamp: new Date().toISOString(),
          sourceIP,
          destIP: TARGET_SERVER.ip,
          port,
          protocol: proto,
          flags,
          requestCount: reqCount,
          packetVolumeKB: Number((reqCount * (proto === 'UDP' ? 3.5 : 1.8)).toFixed(2)),
          uri,
          userAgent: USER_AGENTS[3] || 'CyberBot/2.4',
          attackType: activeAttack
        };

        // Pass through mitigation engine
        const evalResult = mitigationManager.evaluatePacket(packet);
        packet.status = evalResult.status === 'NORMAL' ? 'SUSPICIOUS' : evalResult.status;
        packet.mitigationReason = evalResult.mitigationReason;

        if (evalResult.status === 'BLOCKED') {
          tickBlockedRps += reqCount;
          tickSuspiciousRps += reqCount;
        } else if (evalResult.status === 'RATE_LIMITED') {
          tickBlockedRps += evalResult.droppedCount;
          tickSuspiciousRps += reqCount;
          tickTotalRps += evalResult.allowedCount;
        } else {
          tickTotalRps += reqCount;
          tickSuspiciousRps += reqCount;
        }
        tickVolumeKB += packet.packetVolumeKB;
        newPackets.push(packet);
      }
    }

    // Update cumulative and instantaneous telemetry
    this.currentRps = tickTotalRps;
    this.currentSuspiciousRps = tickSuspiciousRps;
    this.currentBlockedRps = tickBlockedRps;
    this.totalRequests += (tickTotalRps + tickBlockedRps);
    this.suspiciousRequests += tickSuspiciousRps;
    this.blockedRequests += tickBlockedRps;

    // Prepend new packets to rolling buffer
    this.recentPackets = [...newPackets, ...this.recentPackets].slice(0, this.maxPackets);

    // Run Detection Algorithm
    const volumeMB = tickVolumeKB / 1024;
    this.lastDetection = detector.evaluateTraffic({
      currentRps: this.currentRps,
      volumeMB,
      activePackets: newPackets,
      attackType: activeAttack
    });

    // Calculate Threat Level
    const multiAnalysis = this.lastDetection?.multiFactorAnalysis;
    const blockedRatio = (tickTotalRps + tickBlockedRps) > 0 ? (tickBlockedRps / (tickTotalRps + tickBlockedRps)) : 0;
    this.currentThreat = calculateThreatScore({
      rps: this.currentRps,
      suspiciousRps: this.currentSuspiciousRps,
      rpsThreshold: detector.thresholds.rpsThreshold,
      activeAttackType: activeAttack,
      blockedRatio,
      zScore: multiAnalysis?.statistical?.zScore || 0,
      concentrationRatio: multiAnalysis?.uniqueIPs?.concentrationRatio || 0,
      volumeMB,
      volumeThresholdMB: detector.thresholds.volumeThresholdMB
    });

    // Push into time series for Recharts
    const now = new Date();
    const timeLabel = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    this.timeSeries.push({
      timestamp: now.toISOString(),
      timeLabel,
      rps: this.currentRps,
      normalRps: Math.max(0, this.currentRps - this.currentSuspiciousRps),
      attackRps: this.currentSuspiciousRps,
      blockedRps: this.currentBlockedRps,
      threatScore: this.currentThreat.score,
      threatLevel: this.currentThreat.level
    });

    if (this.timeSeries.length > this.maxTimeSeries) {
      this.timeSeries.shift();
    }
  }

  handleDemoProgression() {
    this.demoTimer += 1;
    // Phase 1: 0 - 8s (Baseline Normal)
    if (this.demoTimer <= 8) {
      this.demoPhase = 1;
    }
    // Phase 2: 9 - 22s (Attack Spike)
    else if (this.demoTimer <= 22) {
      this.demoPhase = 2;
    }
    // Phase 3: 23 - 35s (Auto-Mitigation Activated)
    else if (this.demoTimer <= 35) {
      this.demoPhase = 3;
      // Auto-apply mitigation for demo
      if (!mitigationManager.rateLimitingEnabled) {
        mitigationManager.setRateLimiting(true, 80);
        mitigationManager.blockIP('192.168.1.101', 'Automated Demo Mitigator: High frequency botnet source');
        mitigationManager.blockIP('10.0.4.15', 'Automated Demo Mitigator: SYN flood origin');
      }
    }
    // Phase 4: 36s+ (Complete, loop back to baseline)
    else {
      this.demoTimer = 0;
      this.demoPhase = 1;
      mitigationManager.reset();
    }
  }

  getStats() {
    return {
      isRunning: this.isRunning,
      mode: this.mode,
      demoPhase: this.demoPhase,
      totalRequests: this.totalRequests,
      currentRps: this.currentRps,
      suspiciousRequests: this.suspiciousRequests,
      blockedRequests: this.blockedRequests,
      currentSuspiciousRps: this.currentSuspiciousRps,
      currentBlockedRps: this.currentBlockedRps,
      threatLevel: this.currentThreat.level,
      threatScore: this.currentThreat.score,
      threatBadgeColor: this.currentThreat.badgeColor,
      threatDescription: this.currentThreat.description,
      threatBreakdown: this.currentThreat.breakdown || null,
      detectionAccuracy: this.lastDetection.accuracy,
      multiFactorAnalysis: this.lastDetection.multiFactorAnalysis || null,
      lastDetection: this.lastDetection,
      activeAlertsCount: detector.getAlerts('active').length,
      thresholds: detector.getThresholds()
    };
  }

  getPackets(filter = 'all', search = '', limit = 100) {
    let filtered = this.recentPackets;

    if (filter === 'normal') {
      filtered = filtered.filter(p => p.status === 'NORMAL');
    } else if (filter === 'suspicious') {
      filtered = filtered.filter(p => p.status === 'SUSPICIOUS');
    } else if (filter === 'blocked') {
      filtered = filtered.filter(p => p.status === 'BLOCKED');
    } else if (filter === 'rate_limited') {
      filtered = filtered.filter(p => p.status === 'RATE_LIMITED');
    }

    if (search && search.trim() !== '') {
      const q = search.toLowerCase();
      filtered = filtered.filter(p =>
        p.sourceIP.toLowerCase().includes(q) ||
        p.protocol.toLowerCase().includes(q) ||
        p.attackType.toLowerCase().includes(q) ||
        (p.flags && p.flags.toLowerCase().includes(q)) ||
        (p.uri && p.uri.toLowerCase().includes(q))
      );
    }

    return filtered.slice(0, Number(limit) || 100);
  }

  getTimeSeries() {
    return this.timeSeries;
  }
}

module.exports = new TrafficEngine();
