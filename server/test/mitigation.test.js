/**
 * Phase 3 Automated Test Suite: Defensive Mitigation & Access Control
 * Tests IP blocking, TTL auto-expiration, manual unblocking, rate limiting, and action logs.
 */

const assert = require('assert');
const mitigationManager = require('../mitigation/mitigationManager');

function runTests() {
  console.log('\n======================================================');
  console.log('🧪 RUNNING PHASE 3 MITIGATION ENGINE AUTOMATED TEST SUITE');
  console.log('======================================================\n');

  let passed = 0;
  let total = 0;

  function test(name, fn) {
    total++;
    try {
      mitigationManager.reset();
      fn();
      console.log(`  ✓ [PASS] ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ✗ [FAIL] ${name}`);
      console.error(`    Error: ${err.message}`);
    }
  }

  // TEST 1: Manual IP Blocking drops offending traffic completely
  test('1. IP Blacklist drops 100% of packets from blocked IP', () => {
    mitigationManager.blockIP('192.168.1.101', 'High-volume SYN flood origin');
    assert.strictEqual(mitigationManager.getRules().blockedIPs.length, 1);

    const res = mitigationManager.evaluatePacket({
      sourceIP: '192.168.1.101',
      requestCount: 50,
      protocol: 'HTTP',
      flags: 'GET'
    });

    assert.strictEqual(res.action, 'DROP');
    assert.strictEqual(res.status, 'BLOCKED');
    assert.strictEqual(res.allowedCount, 0);
    assert.strictEqual(res.droppedCount, 50);
  });

  // TEST 2: Manual Unblock restores legitimate ingress
  test('2. Manual unblock permits subsequent requests', () => {
    mitigationManager.blockIP('192.168.1.102', 'Suspicious scraper');
    assert.strictEqual(mitigationManager.getRules().blockedIPs.length, 1);

    const unblocked = mitigationManager.unblockIP('192.168.1.102', 'SOC Analyst Manual Unblock');
    assert.strictEqual(unblocked, true);
    assert.strictEqual(mitigationManager.getRules().blockedIPs.length, 0);

    const res = mitigationManager.evaluatePacket({
      sourceIP: '192.168.1.102',
      requestCount: 20,
      protocol: 'HTTP',
      flags: 'GET'
    });

    assert.strictEqual(res.status, 'NORMAL');
    assert.strictEqual(res.allowedCount, 20);
    assert.strictEqual(res.droppedCount, 0);
  });

  // TEST 3: Temporary IP Block with TTL Auto-Expiration
  test('3. Temporary IP Block automatically expires after TTL duration', () => {
    // Block with 1 second TTL
    mitigationManager.blockIP('10.0.4.15', 'Temporary containment', 1);
    assert.strictEqual(mitigationManager.getRules().blockedIPs.length, 1);

    // Immediate check should be BLOCKED
    const immediateRes = mitigationManager.evaluatePacket({
      sourceIP: '10.0.4.15',
      requestCount: 10,
      protocol: 'HTTP'
    });
    assert.strictEqual(immediateRes.status, 'BLOCKED');

    // Simulate clock progression past 1 second
    const rule = mitigationManager.blockedIPs.get('10.0.4.15');
    rule.expiresAt = new Date(Date.now() - 100).toISOString(); // Force expired

    // Next evaluation triggers expiration cleanup
    const afterRes = mitigationManager.evaluatePacket({
      sourceIP: '10.0.4.15',
      requestCount: 10,
      protocol: 'HTTP'
    });

    assert.strictEqual(afterRes.status, 'NORMAL');
    assert.strictEqual(mitigationManager.blockedIPs.has('10.0.4.15'), false, 'Rule should have auto-expired');
    assert.ok(mitigationManager.getActionLogs().some(l => l.action === 'RULE_EXPIRED'));
  });

  // TEST 4: Configurable Sliding-Window Rate Limiting
  test('4. Rate Limiting caps per-IP bursts without blocking nominal traffic', () => {
    mitigationManager.setRateLimiting(true, 50); // 50 req/s threshold

    // Request 1: 30 requests (within quota)
    const res1 = mitigationManager.evaluatePacket({
      sourceIP: '192.168.1.10',
      requestCount: 30,
      protocol: 'HTTP'
    });
    assert.strictEqual(res1.status, 'NORMAL');
    assert.strictEqual(res1.allowedCount, 30);
    assert.strictEqual(res1.droppedCount, 0);

    // Request 2 from same IP: 40 requests (exceeds remaining 20 quota)
    const res2 = mitigationManager.evaluatePacket({
      sourceIP: '192.168.1.10',
      requestCount: 40,
      protocol: 'HTTP'
    });
    assert.strictEqual(res2.status, 'RATE_LIMITED');
    assert.strictEqual(res2.allowedCount, 20, 'Should allow remaining 20');
    assert.strictEqual(res2.droppedCount, 20, 'Should drop excess 20');
  });

  // TEST 5: Protocol Defenses: SYN Cookies & DPI Filtering
  test('5. TCP SYN Cookie and DPI Filtering suppress Layer 4 protocol floods', () => {
    mitigationManager.setSynCookie(true);
    mitigationManager.setTrafficFiltering(true);

    // SYN flood packet
    const synRes = mitigationManager.evaluatePacket({
      sourceIP: '10.0.4.18',
      requestCount: 100,
      protocol: 'TCP',
      flags: 'SYN'
    });
    assert.strictEqual(synRes.status, 'BLOCKED');
    assert.ok(synRes.mitigationReason.includes('SYN Cookie'));

    // ICMP Ping flood packet
    const icmpRes = mitigationManager.evaluatePacket({
      sourceIP: '10.0.4.22',
      requestCount: 80,
      protocol: 'ICMP',
      flags: 'ECHO_REQ'
    });
    assert.strictEqual(icmpRes.status, 'BLOCKED');
    assert.ok(icmpRes.mitigationReason.includes('DPI Protocol Filter'));
  });

  // TEST 6: Mitigation Audit Trail Logging & Telemetry Tracking
  test('6. Complete audit trail records all mitigation actions and computes effectiveness', () => {
    mitigationManager.blockIP('172.16.9.50', 'Test containment');
    mitigationManager.setRateLimiting(true, 100);
    mitigationManager.unblockIP('172.16.9.50');

    const logs = mitigationManager.getActionLogs();
    assert.ok(logs.length >= 3, 'Must record at least 3 audit log events');
    assert.ok(logs.some(l => l.action === 'BLOCK_IP'));
    assert.ok(logs.some(l => l.action === 'UNBLOCK_IP'));
    assert.ok(logs.some(l => l.action === 'CONFIG_RATE_LIMIT'));

    const telemetry = mitigationManager.getTelemetry();
    assert.ok(telemetry.totalIngressRequests >= 0);
    assert.ok(typeof telemetry.mitigationEffectivenessPercentage === 'number');
  });

  console.log('\n------------------------------------------------------');
  console.log(`Results: ${passed} of ${total} tests passed successfully.`);
  console.log('------------------------------------------------------\n');

  if (passed !== total) {
    process.exit(1);
  }
}

runTests();
