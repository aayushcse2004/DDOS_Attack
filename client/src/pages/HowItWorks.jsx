import React, { useState } from 'react';
import { 
  Cpu, 
  ArrowDown, 
  CheckCircle2, 
  Activity, 
  Sliders, 
  ShieldAlert, 
  ShieldCheck, 
  Terminal, 
  Radio, 
  Code,
  Info
} from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';

export const HowItWorks = () => {
  const { stats } = useSecurity();
  const [selectedStep, setSelectedStep] = useState(0);

  const steps = [
    {
      id: 'step-1',
      title: '1. Client Traffic Ingestion',
      subtitle: 'Packet Arrival at Gateway Border',
      icon: Radio,
      category: 'Network Ingress',
      summary: 'Inbound requests from client IP addresses enter the network boundary destined for services (ports 80, 443, 53).',
      studentExplanation: 
        'Think of this as the front door of a bank. Every visitor (client IP) arrives and asks for service. During normal periods, visitors enter one by one. In a DDoS attack, thousands of fake visitors swarm the door simultaneously to prevent legitimate people from entering.',
      mathOrLogic: 'Ingress Rate: λ(t) = dN(t)/dt (Requests arriving per time differential dt)',
      pseudoCode: `// Telemetry Ingestion
function onPacketArrival(packet) {
  extractMetadata({
    srcIP: packet.sourceIP,
    destPort: packet.port,
    protocol: packet.protocol,
    timestamp: Date.now()
  });
}`
    },
    {
      id: 'step-2',
      title: '2. Real-Time Telemetry & Monitoring',
      subtitle: 'Passive Inspection & Sampling',
      icon: Activity,
      category: 'Telemetry Layer',
      summary: 'The monitoring engine aggregates arriving packets into 1-second rolling time windows without delaying legitimate traffic.',
      studentExplanation: 
        'Instead of looking at each packet in isolation, the monitor acts like a traffic camera counting cars per second and measuring the speed and density of vehicles passing through an intersection.',
      mathOrLogic: 'Rolling Window: W(t) = { packet_i | t - Δt ≤ timestamp_i ≤ t }, where Δt = 1.0 second',
      pseudoCode: `// Aggregation Engine
setInterval(() => {
  const windowTelemetry = buffer.drainLastSecond();
  currentRps = windowTelemetry.length;
  currentVolumeMB = windowTelemetry.totalBytes / 1048576;
}, 1000);`
    },
    {
      id: 'step-3',
      title: '3. Feature Extraction',
      subtitle: 'Extracting Behavioral Signatures',
      icon: Terminal,
      category: 'Feature Engineering',
      summary: 'Extracts statistical dimensions: global RPS, single-IP request frequencies, TCP flag distributions (SYN vs ACK), and protocol ratios.',
      studentExplanation: 
        'The system extracts fingerprints from the traffic. For example, are all the requests coming from the exact same IP? Are they asking for the same web page? Are they sending TCP SYN packets without finishing the handshake?',
      mathOrLogic: 'Source Entropy: H(X) = - ∑ P(x_i) log2 P(x_i) (Low entropy indicates botnet concentration)',
      pseudoCode: `// Feature Matrix
const features = {
  rps: totalRequestsPerSecond,
  synAckRatio: synCount / Math.max(1, ackCount),
  ipConcentration: maxIpCount / totalRequestsPerSecond,
  bandwidthMB: totalPayloadBytes / (1024 * 1024)
};`
    },
    {
      id: 'step-4',
      title: '4. Threshold Analysis',
      subtitle: 'Configurable Baseline Comparison',
      icon: Sliders,
      category: 'Decision Boundaries',
      summary: 'Telemetry features are compared against configurable safety thresholds (e.g. 500 req/s, 20 MB/s, 120 req/s per IP).',
      studentExplanation: 
        'Security engineers set boundaries for what is normal for their website. If an e-commerce server normally handles 50 requests per second, setting a threshold of 500 req/s gives headroom for traffic spikes while quickly flagging an attack.',
      mathOrLogic: 'Anomaly Rule: IF rps(t) > θ_RPS OR volume(t) > θ_VOL OR max_ip(t) > θ_IP → TRIGGER',
      pseudoCode: `// Threshold Evaluator
const isAnomalous = (
  features.rps > thresholds.rpsLimit ||
  features.bandwidthMB > thresholds.volumeLimit ||
  features.maxSingleIpRps > thresholds.singleIpLimit
);`
    },
    {
      id: 'step-5',
      title: '5. DDoS Detection Engine',
      subtitle: 'Explainable Rule & Signature Matching',
      icon: ShieldAlert,
      category: 'Detection Core',
      summary: 'Determines whether the anomaly constitutes a Distributed Denial of Service attack and classifies the vector (HTTP, SYN, UDP, or ICMP Flood).',
      studentExplanation: 
        'Once a threshold is crossed, the detection engine diagnoses the exact attack type and generates human-readable reasoning so the SOC analyst knows exactly why an alarm sounded.',
      mathOrLogic: 'Classification Function: C(features) → { Normal, HTTP_Flood, SYN_Flood, UDP_Flood, ICMP_Flood }',
      pseudoCode: `// Explainable Classification
if (features.rps > thresholds.rpsLimit) {
  if (features.synAckRatio > 0.7) {
    return { type: 'SYN Flood', reason: 'High SYN flag density without ACK' };
  }
  return { type: 'HTTP Flood', reason: 'Volumetric L7 requests exceeded threshold' };
}`
    },
    {
      id: 'step-6',
      title: '6. Dynamic Threat Classification',
      subtitle: 'Multi-Factor Severity Scoring',
      icon: Cpu,
      category: 'Risk Assessment',
      summary: 'Computes a holistic threat score (0-100) and assigns an operational severity level: LOW, MEDIUM, HIGH, or CRITICAL.',
      studentExplanation: 
        'Not all spikes are equally dangerous. A minor 10% burst might only raise the threat to MEDIUM, while a massive 1,000 req/s attack targeting the authentication server triggers a CRITICAL status.',
      mathOrLogic: 'Threat Score: S = 0.45 * (RPS/θ_RPS) + 0.30 * (Anomalous/Total) + 0.25 * AttackWeight',
      pseudoCode: `// Threat Scorer
let score = baseScore + (rpsRatio * 45) + (anomalyRatio * 30);
if (score >= 76) return 'CRITICAL';
if (score >= 51) return 'HIGH';
if (score >= 26) return 'MEDIUM';
return 'LOW';`
    },
    {
      id: 'step-7',
      title: '7. Defensive Mitigation Dispatch',
      subtitle: 'Firewall, Rate Limiting & Traffic Dropping',
      icon: ShieldCheck,
      category: 'Defensive Enforcement',
      summary: 'Executes mitigation countermeasures: dropping packets from blacklisted IPs, throttling bursts with token-bucket rate limiters, and validating TCP handshakes.',
      studentExplanation: 
        'Once the bad actors are identified, the system protects the server by immediately dropping malicious packets at the front door before they can consume CPU or memory.',
      mathOrLogic: 'Token Bucket: B(t) = min(Capacity, B(t-dt) + Rate * dt). If packet > B(t) → DROP/THROTTLE',
      pseudoCode: `// Mitigation Filter
function filterPacket(packet) {
  if (isIpBlocked(packet.sourceIP)) return 'DROP';
  if (rateLimiterExceeded(packet.sourceIP)) return 'THROTTLE';
  return 'ALLOW';
}`
    },
    {
      id: 'step-8',
      title: '8. Continuous Feedback & Validation',
      subtitle: 'Closed-Loop Telemetry Re-evaluation',
      icon: Activity,
      category: 'Feedback Loop',
      summary: 'Monitors the post-mitigation traffic to confirm target server recovery and ensures legitimate users remain unaffected.',
      studentExplanation: 
        'After applying defenses, the system continues checking: Did the server load drop back to normal? Are real users getting through? If the threat clears, rules can be relaxed.',
      mathOrLogic: 'Mitigation Efficacy = (Interception Rate) / (Attack Volume) * 100%',
      pseudoCode: `// Continuous Feedback
const postMitigationRps = totalIngress - droppedIngress;
if (postMitigationRps < thresholds.rpsLimit) {
  threatLevel = 'NORMALIZING';
}`
    }
  ];

  return (
    <div className="space-y-6 font-mono">
      
      {/* Header */}
      <div className="cyber-panel p-5 rounded-xl border border-slate-800">
        <h2 className="text-lg font-bold text-white flex items-center gap-2">
          <Cpu className="w-5 h-5 text-cyan-400" />
          <span>HOW IT WORKS: 8-STAGE DDOS DETECTION & MITIGATION PIPELINE</span>
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Interactive educational breakdown of the defensive cybersecurity workflow. Click any stage to inspect the technical logic, student explanation, and pseudo-code.
        </p>
      </div>

      {/* Interactive Pipeline Steps Overview */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {steps.map((step, idx) => {
          const Icon = step.icon;
          const isSelected = selectedStep === idx;

          return (
            <button
              key={step.id}
              onClick={() => setSelectedStep(idx)}
              className={`p-3.5 rounded-xl border text-left transition-all relative overflow-hidden ${
                isSelected
                  ? 'bg-cyan-950/40 border-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.3)]'
                  : 'bg-slate-900/50 border-slate-800 hover:border-slate-700 hover:bg-slate-900/80'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className={`text-[10px] px-1.5 py-0.5 rounded uppercase font-bold ${
                  isSelected ? 'bg-cyan-500/20 text-cyan-300' : 'bg-slate-800 text-slate-400'
                }`}>
                  {step.category}
                </span>
                <Icon className={`w-4 h-4 ${isSelected ? 'text-cyan-400' : 'text-slate-500'}`} />
              </div>
              <h3 className={`text-xs font-bold ${isSelected ? 'text-white' : 'text-slate-300'}`}>
                {step.title}
              </h3>
              <p className="text-[10px] text-slate-400 mt-1 line-clamp-1">{step.subtitle}</p>
            </button>
          );
        })}
      </div>

      {/* Selected Step Deep Dive Card */}
      {steps[selectedStep] && (
        <div className="cyber-panel p-6 rounded-xl border border-cyan-500/40 bg-[#0E1526] space-y-5">
          
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
            <div>
              <span className="text-xs text-cyan-400 uppercase tracking-wider font-semibold">
                STAGE {selectedStep + 1} OF 8: {steps[selectedStep].category}
              </span>
              <h3 className="text-xl font-bold text-white mt-0.5">
                {steps[selectedStep].title}
              </h3>
              <p className="text-xs text-slate-300 mt-1">{steps[selectedStep].summary}</p>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setSelectedStep(prev => Math.max(0, prev - 1))}
                disabled={selectedStep === 0}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-30 text-xs text-slate-200"
              >
                ← Prev Stage
              </button>
              <button
                onClick={() => setSelectedStep(prev => Math.min(steps.length - 1, prev + 1))}
                disabled={selectedStep === steps.length - 1}
                className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-30 text-xs text-white font-bold"
              >
                Next Stage →
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 text-xs">
            
            {/* Student Explanation & Analogy */}
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="flex items-center gap-2 text-amber-400 font-bold mb-1.5 text-xs">
                  <Info className="w-4 h-4" />
                  <span>STUDENT-FRIENDLY EXPLANATION (FOR PROFESSOR / VIVA)</span>
                </div>
                <p className="text-slate-300 leading-relaxed text-xs">
                  {steps[selectedStep].studentExplanation}
                </p>
              </div>

              <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="flex items-center gap-2 text-cyan-400 font-bold mb-1.5 text-xs">
                  <Sliders className="w-4 h-4" />
                  <span>MATHEMATICAL INTUITION & FORMULA</span>
                </div>
                <p className="p-2.5 rounded bg-black/40 border border-slate-800 text-emerald-400 font-mono text-[11px]">
                  {steps[selectedStep].mathOrLogic}
                </p>
              </div>
            </div>

            {/* Implementation Code Snippet */}
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between">
              <div>
                <div className="flex items-center gap-2 text-purple-400 font-bold mb-2 text-xs">
                  <Code className="w-4 h-4" />
                  <span>SYSTEM IMPLEMENTATION LOGIC</span>
                </div>
                <pre className="p-3.5 rounded-lg bg-black/70 border border-slate-800 text-cyan-300 text-[11px] overflow-x-auto leading-relaxed">
                  {steps[selectedStep].pseudoCode}
                </pre>
              </div>
              <p className="text-[10px] text-slate-500 mt-2">
                Executed in-memory by our Node.js + Express detection core.
              </p>
            </div>

          </div>

        </div>
      )}

      {/* Visual ASCII Flow Chart */}
      <div className="cyber-panel p-5 rounded-xl border border-slate-800">
        <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
          End-to-End Architectural Data Flow
        </h3>
        <pre className="p-4 rounded-lg bg-slate-950/80 border border-slate-800 text-cyan-400 text-[11px] overflow-x-auto leading-relaxed text-center">
{`Client Traffic ──► [Traffic Ingestion] ──► [Feature Extraction (RPS, Flags, Volume)]
                                                        │
Mitigation Dispatch ◄── [Threat Scorer] ◄── [Threshold & Anomaly Detector]
       │
       ▼
[Firewall Drop / Rate Limit] ──► [Post-Mitigation Verification] ──► Protected Core`}
        </pre>
      </div>

    </div>
  );
};
