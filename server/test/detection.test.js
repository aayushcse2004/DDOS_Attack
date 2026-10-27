/**
 * Phase 1 Automated Test Suite: DDoS Detection & Multi-Factor Anomaly Engine
 * Tests statistical anomaly detection, multi-factor analysis, explainable reasoning, and alert deduplication.
 */

const assert = require('assert');
const detector = require('../detection/detector');

function runTests() {
  console.log('\n======================================================');
  console.log('🧪 RUNNING PHASE 1 DETECTION ENGINE AUTOMATED TEST SUITE');
  console.log('======================================================\n');

  let passed = 0;
  let total = 0;

  function test(name, fn) {
    total++;
    try {
      detector.reset();
      fn();
      console.log(`  ✓ [PASS] ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ✗ [FAIL] ${name}`);
      console.error(`    Error: ${err.message}`);
    }
  }

  // TEST 1: Baseline Nominal Traffic Evaluation
  test('1. Baseline Nominal Traffic does not trigger false alerts', () => {
    const normalPackets = [
      { sourceIP: '192.168.1.10', requestCount: 8, protocol: 'HTTP', flags: 'PSH-ACK' },
      { sourceIP: '192.168.1.11', requestCount: 6, protocol: 'HTTP', flags: 'PSH-ACK' },
      { sourceIP: '10.0.0.5', requestCount: 9, protocol: 'HTTP', flags: 'PSH-ACK' },
      { sourceIP: '172.16.0.12', requestCount: 7, protocol: 'HTTP', flags: 'PSH-ACK' }
    ];

    const result = detector.evaluateTraffic({
      currentRps: 30,
      volumeMB: 0.5,
      activePackets: normalPackets,
      attackType: 'None'
    });

    assert.strictEqual(result.isPotentialDDoS, false, 'Expected normal traffic to not be DDoS');
    assert.strictEqual(result.classification, 'Normal');
    assert.strictEqual(result.severity, 'LOW');
    assert.strictEqual(detector.getAlerts().length, 0, 'No alert should be created for baseline traffic');
    assert.ok(result.multiFactorAnalysis.statistical.baselineEma > 0, 'Baseline EMA should be computed');
  });

  // TEST 2: Global RPS Threshold Breach
  test('2. Global Volumetric RPS Breach triggers explainable alert', () => {
    const burstPackets = [
      { sourceIP: '192.168.1.101', requestCount: 300, protocol: 'HTTP', flags: 'GET' },
      { sourceIP: '192.168.1.102', requestCount: 250, protocol: 'HTTP', flags: 'GET' }
    ];

    const result = detector.evaluateTraffic({
      currentRps: 550, // Exceeds default 500 threshold
      volumeMB: 5.0,
      activePackets: burstPackets,
      attackType: 'None'
    });

    assert.strictEqual(result.isPotentialDDoS, true, 'RPS > 500 should trigger detection');
    assert.ok(['HIGH', 'CRITICAL'].includes(result.severity), 'Severity should be elevated');
    assert.ok(result.reasons.some(r => r.includes('Volumetric Ingress Breach')), 'Should contain volumetric breach reason');
    assert.strictEqual(detector.getAlerts().length, 1, 'Should generate an alert');
  });

  // TEST 3: Bandwidth Saturation Breach
  test('3. Bandwidth Saturation (MB/s) triggers detection even with moderate RPS', () => {
    const heavyPackets = [
      { sourceIP: '10.0.4.15', requestCount: 80, protocol: 'UDP', flags: 'DATAGRAM' }
    ];

    const result = detector.evaluateTraffic({
      currentRps: 150, // Below 500 RPS threshold
      volumeMB: 26.5,  // Exceeds 20 MB/s threshold
      activePackets: heavyPackets,
      attackType: 'None'
    });

    assert.strictEqual(result.isPotentialDDoS, true, 'Bandwidth > 20 MB/s should trigger detection');
    assert.ok(result.reasons.some(r => r.includes('Bandwidth Saturation')), 'Should explain bandwidth saturation');
  });

  // TEST 4: Single IP Request Rate and Traffic Concentration Anomaly
  test('4. Per-IP Request Concentration detects single high-volume talker', () => {
    const packets = [
      { sourceIP: '192.168.1.101', requestCount: 140, protocol: 'HTTP', flags: 'GET' }, // > 120 threshold
      { sourceIP: '192.168.1.10', requestCount: 10, protocol: 'HTTP', flags: 'GET' },
      { sourceIP: '192.168.1.11', requestCount: 10, protocol: 'HTTP', flags: 'GET' }
    ];

    const result = detector.evaluateTraffic({
      currentRps: 160,
      volumeMB: 1.2,
      activePackets: packets,
      attackType: 'None'
    });

    assert.strictEqual(result.isPotentialDDoS, true);
    assert.ok(result.reasons.some(r => r.includes('High-Rate Single IP') && r.includes('192.168.1.101')), 'Must identify offending IP');
    assert.ok(result.reasons.some(r => r.includes('Traffic Concentration Anomaly')), 'Must flag concentration ratio anomaly');
  });

  // TEST 5: Statistical Anomaly Detection (EMA + Z-Score)
  test('5. Statistical Anomaly flags sudden velocity surge even below hard ceiling', () => {
    // Establish calm baseline of 35-40 req/s over 10 ticks
    for (let i = 0; i < 15; i++) {
      detector.evaluateTraffic({
        currentRps: 36 + (i % 4),
        volumeMB: 0.5,
        activePackets: [{ sourceIP: '192.168.1.10', requestCount: 36, protocol: 'HTTP' }],
        attackType: 'None'
      });
    }

    // Sudden surge to 180 req/s (5x jump, but still below the static 500 ceiling)
    const surgeResult = detector.evaluateTraffic({
      currentRps: 180,
      volumeMB: 1.8,
      activePackets: [
        { sourceIP: '192.168.1.101', requestCount: 90, protocol: 'HTTP' },
        { sourceIP: '192.168.1.102', requestCount: 90, protocol: 'HTTP' }
      ],
      attackType: 'None'
    });

    assert.strictEqual(surgeResult.isPotentialDDoS, true, 'Surge with high Z-score should trigger early anomaly detection');
    assert.ok(surgeResult.reasons.some(r => r.includes('Statistical Anomaly') && r.includes('Z-Score')), 'Should detail Z-Score in forensic reason');
  });

  // TEST 6: Protocol Flag Analysis: TCP SYN Flood
  test('6. TCP SYN Handshake asymmetry triggers state table exhaustion warning', () => {
    const synPackets = [
      { sourceIP: '10.0.4.15', requestCount: 150, protocol: 'TCP', flags: 'SYN' },
      { sourceIP: '192.168.1.10', requestCount: 10, protocol: 'TCP', flags: 'ACK' }
    ];

    const result = detector.evaluateTraffic({
      currentRps: 160,
      volumeMB: 1.0,
      activePackets: synPackets,
      attackType: 'SYN Flood'
    });

    assert.strictEqual(result.isPotentialDDoS, true);
    assert.ok(result.reasons.some(r => r.includes('TCP State Table Exhaustion') && r.includes('SYN-to-ACK ratio')), 'Must report SYN/ACK asymmetry');
  });

  // TEST 7: Alert Deduplication for Ongoing Incidents
  test('7. Alert Deduplication prevents duplicate alerts during ongoing attack', () => {
    const attackPackets = [
      { sourceIP: '192.168.1.101', requestCount: 300, protocol: 'HTTP', flags: 'GET' }
    ];

    // Tick 1 of HTTP Flood
    detector.evaluateTraffic({
      currentRps: 600,
      volumeMB: 8.0,
      activePackets: attackPackets,
      attackType: 'HTTP Flood'
    });

    // Tick 2 of HTTP Flood (1 second later)
    detector.evaluateTraffic({
      currentRps: 650,
      volumeMB: 9.0,
      activePackets: attackPackets,
      attackType: 'HTTP Flood'
    });

    // Tick 3 of HTTP Flood (2 seconds later)
    detector.evaluateTraffic({
      currentRps: 700,
      volumeMB: 10.0,
      activePackets: attackPackets,
      attackType: 'HTTP Flood'
    });

    const activeAlerts = detector.getAlerts('active');
    assert.strictEqual(activeAlerts.length, 1, 'Ongoing attack should result in exactly 1 deduplicated alert record');
    assert.strictEqual(activeAlerts[0].occurrenceCount, 3, 'Alert occurrence count should increment to 3');
    assert.strictEqual(activeAlerts[0].peakRps, 700, 'Alert should track peak RPS across the incident');
  });

  // TEST 8: Dynamic Configurable Thresholds
  test('8. Configurable Thresholds update dynamically and alter evaluation immediately', () => {
    // Set custom strict threshold of 80 req/s
    detector.updateThresholds({ rpsThreshold: 80, singleIpRpsThreshold: 50 });

    const updatedThresholds = detector.getThresholds();
    assert.strictEqual(updatedThresholds.rpsThreshold, 80);
    assert.strictEqual(updatedThresholds.singleIpRpsThreshold, 50);

    // 90 req/s should now trigger detection (whereas under default 500 it would pass)
    const result = detector.evaluateTraffic({
      currentRps: 90,
      volumeMB: 0.8,
      activePackets: [{ sourceIP: '192.168.1.10', requestCount: 45, protocol: 'HTTP' }],
      attackType: 'None'
    });

    assert.strictEqual(result.isPotentialDDoS, true, 'Traffic at 90 req/s should trigger under custom 80 threshold');
  });

  console.log('\n------------------------------------------------------');
  console.log(`Results: ${passed} of ${total} tests passed successfully.`);
  console.log('------------------------------------------------------\n');

  if (passed !== total) {
    process.exit(1);
  }
}

runTests();
