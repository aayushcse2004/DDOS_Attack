/**
 * Phase 2: Transparent Threat Scoring Engine
 * Computes a bounded 0–100 composite threat score with individual indicator contributions.
 * Handles missing, null, undefined, NaN, and zero values safely.
 */

/**
 * Normalizes input numbers safely to non-negative floats
 */
function safeNum(val, defaultVal = 0) {
  if (val === null || val === undefined) return defaultVal;
  const num = Number(val);
  return (isNaN(num) || !isFinite(num)) ? defaultVal : Math.max(0, num);
}

/**
 * Calculate multi-factor transparent threat score with individual indicator contributions
 * 
 * @param {Object} params
 * @param {number} params.rps - Current aggregate requests per second
 * @param {number} params.suspiciousRps - Suspect request velocity
 * @param {number} params.rpsThreshold - Configured safe capacity ceiling
 * @param {string} params.activeAttackType - Attack signature name
 * @param {number} params.blockedRatio - Proportion of requests currently mitigated [0, 1]
 * @param {number} [params.zScore] - Statistical anomaly standard deviation score
 * @param {number} [params.concentrationRatio] - Share of traffic from single top IP [0, 1]
 * @param {number} [params.volumeMB] - Current aggregate bandwidth in MB/s
 * @param {number} [params.volumeThresholdMB] - Bandwidth threshold in MB/s
 * @returns {Object} Score, level, badgeColor, description, and indicator contributions
 */
function calculateThreatScore(params = {}) {
  // Safe extraction with default fallbacks
  const rps = safeNum(params.rps, 0);
  const suspiciousRps = safeNum(params.suspiciousRps, 0);
  const rpsThreshold = Math.max(1, safeNum(params.rpsThreshold, 500));
  const activeAttackType = typeof params.activeAttackType === 'string' ? params.activeAttackType : 'None';
  const blockedRatio = Math.min(1, Math.max(0, safeNum(params.blockedRatio, 0)));
  const zScore = safeNum(params.zScore, 0);
  const concentrationRatio = Math.min(1, Math.max(0, safeNum(params.concentrationRatio, 0)));
  const volumeMB = safeNum(params.volumeMB, 0);
  const volumeThresholdMB = Math.max(1, safeNum(params.volumeThresholdMB, 20));

  // Baseline healthy network presence (5 base points)
  let baseScore = 5;

  // 1. Volumetric Ingress Contribution (0 to 35 points) - Continuous and smooth
  const rpsRatio = rps / rpsThreshold;
  const volumeRatio = volumeMB / volumeThresholdMB;
  const maxVolumeRatio = Math.max(rpsRatio, volumeRatio);

  let volumetricContribution = 0;
  if (maxVolumeRatio >= 1.5) {
    volumetricContribution = 35;
  } else if (maxVolumeRatio >= 1.0) {
    // 25 to 35 points
    volumetricContribution = Math.round(25 + ((maxVolumeRatio - 1.0) / 0.5) * 10);
  } else if (maxVolumeRatio >= 0.5) {
    // 12 to 24 points
    volumetricContribution = Math.round(12 + ((maxVolumeRatio - 0.5) / 0.5) * 12);
  } else if (maxVolumeRatio >= 0.2) {
    // 4 to 11 points
    volumetricContribution = Math.round(4 + ((maxVolumeRatio - 0.2) / 0.3) * 7);
  } else if (maxVolumeRatio > 0) {
    volumetricContribution = Math.round((maxVolumeRatio / 0.2) * 3);
  }

  // 2. Suspicious Traffic & Velocity Contribution (0 to 25 points)
  let anomalyContribution = 0;
  const suspiciousRatio = rps > 0 ? (suspiciousRps / rps) : 0;
  const suspicionScore = Math.round(suspiciousRatio * 15);
  let zScoreScore = 0;
  if (zScore >= 4.0) zScoreScore = 10;
  else if (zScore >= 2.5) zScoreScore = 7;
  else if (zScore >= 1.5) zScoreScore = 4;
  else if (zScore >= 1.0) zScoreScore = 2;

  anomalyContribution = Math.min(25, suspicionScore + zScoreScore);

  // 3. Attack Signature & Protocol Contribution (0 to 25 points)
  let signatureContribution = 0;
  if (activeAttackType && activeAttackType !== 'None') {
    switch (activeAttackType) {
      case 'SYN Flood':
      case 'HTTP Flood':
        signatureContribution = 25;
        break;
      case 'UDP Flood':
        signatureContribution = 22;
        break;
      case 'ICMP Flood':
        signatureContribution = 18;
        break;
      default:
        signatureContribution = 15;
    }
  }

  // 4. Per-IP Concentration & Low-Entropy Contribution (0 to 15 points)
  let concentrationContribution = 0;
  if (concentrationRatio >= 0.70) {
    concentrationContribution = 15;
  } else if (concentrationRatio >= 0.40) {
    concentrationContribution = 10;
  } else if (concentrationRatio >= 0.25 && rps > 80) {
    concentrationContribution = 5;
  }

  // Subtotal before mitigation suppression
  let rawScore = baseScore + volumetricContribution + anomalyContribution + signatureContribution + concentrationContribution;

  // 5. Mitigation Suppression Discount (Dampens threat score if protective measures are active)
  let mitigationDiscount = 0;
  if (blockedRatio > 0.75 && rawScore > 35) {
    mitigationDiscount = Math.round(rawScore * 0.35); // 35% suppression
  } else if (blockedRatio > 0.40 && rawScore > 30) {
    mitigationDiscount = Math.round(rawScore * 0.20); // 20% suppression
  } else if (blockedRatio > 0.15 && rawScore > 25) {
    mitigationDiscount = Math.round(rawScore * 0.10); // 10% suppression
  }

  // Final Composite Score (Strictly bounded 0 - 100)
  const finalScore = Math.min(100, Math.max(0, Math.round(rawScore - mitigationDiscount)));

  // Threat Level Categorization
  let level = 'LOW';
  let badgeColor = 'emerald';
  let description = 'Network telemetry operating within nominal baseline parameters.';

  if (finalScore >= 76) {
    level = 'CRITICAL';
    badgeColor = 'rose';
    description = 'Severe multi-vector or high-volume DDoS attack actively threatening service availability.';
  } else if (finalScore >= 51) {
    level = 'HIGH';
    badgeColor = 'amber';
    description = 'Substantial traffic anomaly or verified attack signature exceeding safety thresholds.';
  } else if (finalScore >= 26) {
    level = 'MEDIUM';
    badgeColor = 'yellow';
    description = 'Moderate traffic fluctuation or elevated single-source velocity observed.';
  }

  return {
    score: finalScore,
    level,
    badgeColor,
    description,
    breakdown: {
      baseScore,
      volumetricContribution,
      anomalyContribution,
      signatureContribution,
      concentrationContribution,
      mitigationDiscount,
      totalRaw: rawScore,
      netScore: finalScore
    }
  };
}

module.exports = {
  calculateThreatScore,
  safeNum
};
