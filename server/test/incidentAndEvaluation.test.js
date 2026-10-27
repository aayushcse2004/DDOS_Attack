/**
 * Phase 4, 5 & 6 Automated Test Suite:
 * Incident Management, Ground-Truth Evaluation Benchmark, CSV/HTML Reports, and Error Handling.
 */

const assert = require('assert');
const incidentManager = require('../detection/incidentManager');
const evaluator = require('../evaluation/evaluator');

function runTests() {
  console.log('\n======================================================');
  console.log('🧪 RUNNING INCIDENTS & EVALUATION AUTOMATED TEST SUITE');
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

  // TEST 1: Incident Retrieval & Filtering
  test('1. Incident Manager retrieves and filters incidents by status and severity', () => {
    const all = incidentManager.getIncidents();
    assert.ok(all.length >= 2, 'Should have seeded historical incidents');

    const resolved = incidentManager.getIncidents({ status: 'RESOLVED' });
    assert.ok(resolved.every(i => i.status === 'RESOLVED'), 'Filtered status must strictly match');

    const critical = incidentManager.getIncidents({ severity: 'CRITICAL' });
    assert.ok(critical.every(i => i.severity === 'CRITICAL'), 'Filtered severity must strictly match');
  });

  // TEST 2: Incident Status Updates & Timeline Tracking
  test('2. Updating incident status appends timeline event and note', () => {
    const list = incidentManager.getIncidents();
    const testId = list[0].id;
    const initialTimelineLength = list[0].timeline.length;

    const updated = incidentManager.updateIncidentStatus(testId, 'INVESTIGATING', 'SOC team analyzing pcap trace', 'Senior Analyst');
    assert.strictEqual(updated.status, 'INVESTIGATING');
    assert.strictEqual(updated.timeline.length, initialTimelineLength + 1);
    assert.ok(updated.investigationNotes.some(n => n.note.includes('analyzing pcap trace')));
  });

  // TEST 3: Analyst Note Addition
  test('3. Analysts can append forensic notes with author attribution', () => {
    const list = incidentManager.getIncidents();
    const testId = list[0].id;
    const initialNotesLength = list[0].investigationNotes.length;

    const updated = incidentManager.addNote(testId, 'Firewall ACL drop verified at router interface', 'SecOps Lead');
    assert.strictEqual(updated.investigationNotes.length, initialNotesLength + 1);
    assert.strictEqual(updated.investigationNotes[updated.investigationNotes.length - 1].author, 'SecOps Lead');
  });

  // TEST 4: RFC-4180 Compliant CSV Export
  test('4. Incident CSV Export generates compliant header and forensic rows', () => {
    const list = incidentManager.getIncidents();
    const csv = incidentManager.exportIncidentCSV(list[0].id);
    assert.ok(typeof csv === 'string', 'CSV must be a string');
    assert.ok(csv.includes('INCIDENT_METADATA'), 'Must include metadata section');
    assert.ok(csv.includes(list[0].id), 'Must include incident ID');
    assert.ok(csv.includes('TIMELINE_TIMESTAMP'), 'Must include timeline headers');

    const allCsv = incidentManager.exportAllIncidentsCSV();
    assert.ok(allCsv.includes('"Incident ID"'), 'Must include Incident ID column');
    assert.ok(allCsv.includes('"Attack Type"'), 'Must include Attack Type column');
    assert.ok(allCsv.includes('"Severity"'), 'Must include Severity column');
  });

  // TEST 5: Printable HTML Forensic Report Generation
  test('5. Forensic Report generator outputs complete styled printable HTML', () => {
    const list = incidentManager.getIncidents();
    const html = incidentManager.generateHtmlReport(list[0].id);
    assert.ok(html.includes('CYBERSECURITY INCIDENT INVESTIGATION REPORT'), 'Must contain report title');
    assert.ok(html.includes(list[0].id), 'Must contain target incident ID');
    assert.ok(html.includes('window.print()'), 'Must include print/PDF action');
  });

  // TEST 6: Ground-Truth Benchmark Evaluation
  test('6. Benchmark evaluates TP, TN, FP, FN, precision, recall, F1, and latency', () => {
    const benchmark = evaluator.runBenchmark();
    assert.ok(benchmark.benchmarkId.startsWith('BENCH-'), 'Must generate benchmark ID');

    const cm = benchmark.confusionMatrix;
    assert.ok(cm.truePositives > 0, `Expected TP > 0, got ${cm.truePositives}`);
    assert.ok(cm.trueNegatives > 0, `Expected TN > 0, got ${cm.trueNegatives}`);
    assert.strictEqual(cm.totalSamples, cm.truePositives + cm.trueNegatives + cm.falsePositives + cm.falseNegatives);

    const m = benchmark.metrics;
    assert.ok(m.accuracy >= 80 && m.accuracy <= 100, `Expected accuracy 80-100%, got ${m.accuracy}`);
    assert.ok(m.precision >= 80 && m.precision <= 100, `Expected precision 80-100%, got ${m.precision}`);
    assert.ok(m.recall >= 80 && m.recall <= 100, `Expected recall 80-100%, got ${m.recall}`);
    assert.ok(m.f1Score >= 80 && m.f1Score <= 100, `Expected F1 80-100%, got ${m.f1Score}`);
    assert.ok(m.averageDetectionLatencyMs > 0, 'Latency must be a positive measured number in ms');
    assert.ok(benchmark.scenarios.length >= 4, 'Must evaluate at least 4 distinct scenarios');
  });

  console.log('\n------------------------------------------------------');
  console.log(`Results: ${passed} of ${total} tests passed successfully.`);
  console.log('------------------------------------------------------\n');

  if (passed !== total) {
    process.exit(1);
  }
}

runTests();
