/**
 * Phase 2 Automated Test Suite: Transparent Threat Scoring Engine
 * Tests 0-100 bounds, safe null/NaN handling, threat level categories, and individual indicator contributions.
 */

const assert = require('assert');
const { calculateThreatScore, safeNum } = require('../detection/threatScorer');

function runTests() {
  console.log('\n======================================================');
  console.log('🧪 RUNNING PHASE 2 THREAT SCORER AUTOMATED TEST SUITE');
  console.log('======================================================\n');

  let passed = 0;
  let total = 0;

  function test(name, fn) {
    total++;
    try {
      fn();
      console.log(`  ✓ [PASS] ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ✗ [FAIL] ${name}`);
      console.error(`    Error: ${err.message}`);
    }
  }

  // TEST 1: Nominal Baseline Traffic results in LOW threat level
  test('1. Nominal baseline traffic yields LOW threat level (<= 25)', () => {
    const res = calculateThreatScore({
      rps: 40,
      suspiciousRps: 0,
      rpsThreshold: 500,
      activeAttackType: 'None',
      blockedRatio: 0
    });

    assert.ok(res.score >= 0 && res.score <= 25, `Expected score <= 25, got ${res.score}`);
    assert.strictEqual(res.level, 'LOW');
    assert.strictEqual(res.badgeColor, 'emerald');
    assert.ok(res.breakdown, 'Breakdown object must exist');
    assert.strictEqual(res.breakdown.signatureContribution, 0);
  });

  // TEST 2: Active Attack with High RPS yields CRITICAL threat level (>= 76)
  test('2. Severe HTTP Flood yields CRITICAL threat level (>= 76)', () => {
    const res = calculateThreatScore({
      rps: 950,
      suspiciousRps: 900,
      rpsThreshold: 500,
      activeAttackType: 'HTTP Flood',
      blockedRatio: 0,
      zScore: 5.2,
      concentrationRatio: 0.8
    });

    assert.ok(res.score >= 76 && res.score <= 100, `Expected score >= 76, got ${res.score}`);
    assert.strictEqual(res.level, 'CRITICAL');
    assert.strictEqual(res.badgeColor, 'rose');
    assert.ok(res.breakdown.volumetricContribution > 0, 'Volumetric contribution should be positive');
    assert.strictEqual(res.breakdown.signatureContribution, 25, 'HTTP flood signature should contribute 25 pts');
  });

  // TEST 3: Mitigation Suppression Dampens Threat Score
  test('3. Defensive mitigation drops threat score proportionally', () => {
    const unmitigated = calculateThreatScore({
      rps: 800,
      suspiciousRps: 750,
      rpsThreshold: 500,
      activeAttackType: 'SYN Flood',
      blockedRatio: 0.0
    });

    const mitigated = calculateThreatScore({
      rps: 800,
      suspiciousRps: 750,
      rpsThreshold: 500,
      activeAttackType: 'SYN Flood',
      blockedRatio: 0.85 // 85% of traffic filtered/blocked
    });

    assert.ok(mitigated.breakdown.mitigationDiscount > 0, 'Mitigation discount must be greater than zero');
    assert.ok(mitigated.score < unmitigated.score, `Mitigated score (${mitigated.score}) must be lower than unmitigated (${unmitigated.score})`);
  });

  // TEST 4: Bounded Calculation: Strict 0 - 100 Clamping
  test('4. Extreme inputs are strictly clamped between 0 and 100', () => {
    const maxExtreme = calculateThreatScore({
      rps: 1000000,
      suspiciousRps: 1000000,
      rpsThreshold: 100,
      activeAttackType: 'HTTP Flood',
      blockedRatio: 0,
      zScore: 99.9,
      concentrationRatio: 1.0,
      volumeMB: 5000
    });

    assert.strictEqual(maxExtreme.score, 100, 'Extreme high must be capped at 100');

    const minExtreme = calculateThreatScore({
      rps: 0,
      suspiciousRps: 0,
      rpsThreshold: 500,
      activeAttackType: 'None',
      blockedRatio: 1.0
    });

    assert.ok(minExtreme.score >= 0 && minExtreme.score <= 15, 'Minimal state must be bounded at or above 0');
  });

  // TEST 5: Robust Handling of Missing, Null, Undefined, and NaN Inputs
  test('5. Safe handling of null, undefined, NaN, and missing parameters', () => {
    const resEmpty = calculateThreatScore({});
    assert.ok(!isNaN(resEmpty.score), 'Empty params must not produce NaN');
    assert.strictEqual(resEmpty.level, 'LOW');

    const resNulls = calculateThreatScore({
      rps: null,
      suspiciousRps: undefined,
      rpsThreshold: NaN,
      activeAttackType: null,
      blockedRatio: 'invalid',
      zScore: null
    });
    assert.ok(!isNaN(resNulls.score), 'Null/NaN params must not produce NaN');
    assert.ok(resNulls.score >= 0 && resNulls.score <= 100);
  });

  // TEST 6: Intermediate Threat Categories: MEDIUM and HIGH
  test('6. Intermediate conditions map cleanly to MEDIUM and HIGH levels', () => {
    const mediumRes = calculateThreatScore({
      rps: 320,
      suspiciousRps: 80,
      rpsThreshold: 500,
      activeAttackType: 'None',
      blockedRatio: 0,
      zScore: 2.2
    });
    assert.ok(mediumRes.score >= 26 && mediumRes.score <= 50, `Expected MEDIUM, got ${mediumRes.score} (${mediumRes.level})`);
    assert.strictEqual(mediumRes.level, 'MEDIUM');

    const highRes = calculateThreatScore({
      rps: 480,
      suspiciousRps: 200,
      rpsThreshold: 500,
      activeAttackType: 'ICMP Flood',
      blockedRatio: 0
    });
    assert.ok(highRes.score >= 51 && highRes.score <= 75, `Expected HIGH, got ${highRes.score} (${highRes.level})`);
    assert.strictEqual(highRes.level, 'HIGH');
  });

  console.log('\n------------------------------------------------------');
  console.log(`Results: ${passed} of ${total} tests passed successfully.`);
  console.log('------------------------------------------------------\n');

  if (passed !== total) {
    process.exit(1);
  }
}

runTests();
