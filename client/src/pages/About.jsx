import React, { useState } from 'react';
import { 
  GraduationCap, 
  BookOpen, 
  ShieldCheck, 
  Cpu, 
  HelpCircle, 
  ChevronDown, 
  ChevronUp, 
  Code, 
  CheckCircle2,
  FileText
} from 'lucide-react';

export const About = () => {
  const [openFaq, setOpenFaq] = useState(0);

  const vivaQuestions = [
    {
      q: "1. What is the fundamental difference between a DoS and a DDoS attack?",
      a: "A Denial of Service (DoS) attack originates from a single machine or network connection targeting a host, making it straightforward to mitigate by blocking the single offending IP address. In contrast, a Distributed Denial of Service (DDoS) attack harnesses hundreds or thousands of distributed machines (a botnet or compromised IoT devices) across multiple geographic networks to flood the target simultaneously. This distributed nature makes source IP filtering far more complex, as malicious traffic blends with legitimate traffic."
    },
    {
      q: "2. Explain the difference between Layer 4 (Transport) and Layer 7 (Application) DDoS attacks.",
      a: "Layer 4 attacks (such as TCP SYN Floods or UDP Amplification) target network infrastructure, state tables, and bandwidth limits. They exploit protocol handshake mechanics or blast raw packets without establishing complete application sessions. Layer 7 attacks (such as HTTP GET/POST Floods) establish valid TCP handshakes and mimic genuine user behavior, targeting web server resources, database query engines, or backend CPU by requesting computationally intensive endpoints (e.g., search queries, login endpoints)."
    },
    {
      q: "3. How does a TCP SYN Flood exploit the 3-way handshake?",
      a: "Under normal TCP operation, the client sends a SYN packet, the server allocates state in its connection backlog table and replies with SYN-ACK, and the client sends an ACK to complete the handshake. In a SYN Flood, the attacker sends a massive flurry of SYN packets with spoofed source IPs or deliberately ignores the SYN-ACK. The server leaves half-open connections waiting until a timeout expires, exhausting its connection backlog table (TCB table) and dropping connections from legitimate users."
    },
    {
      q: "4. What are SYN Cookies, and how do they defend against SYN Floods without allocating memory?",
      a: "SYN Cookies allow a server to avoid allocating memory for half-open connections. Instead of storing state when a SYN arrives, the server encodes critical connection parameters (source IP, port, server secret, and timestamp) into the 32-bit Initial Sequence Number (ISN) of the SYN-ACK packet. When the client returns the final ACK, the server verifies the sequence number mathematically. Only upon successful verification is memory allocated for the connection, rendering backlog exhaustion attacks ineffective."
    },
    {
      q: "5. How does a detection system distinguish a legitimate Flash Crowd from a DDoS attack?",
      a: "A Flash Crowd (e.g., Black Friday or viral news) consists of real humans browsing pages sequentially, downloading associated CSS/images, generating normal inter-arrival times, and executing JavaScript. A DDoS botnet often exhibits anomalous request rates from fixed subnets, identical User-Agent headers, missing session cookies, low entropy in requested URLs, or rapid repeat queries without downloading assets. Modern detection analyzes request entropy, behavioral navigation sequences, and CAPTCHA/challenge responses."
    },
    {
      q: "6. How does Rate Limiting work, and what is the difference between Token Bucket and Leaky Bucket algorithms?",
      a: "Rate limiting restricts the volume of requests permitted from a source within a given timeframe. In the Token Bucket algorithm, tokens are deposited into a bucket at a constant rate up to a maximum capacity; each incoming request consumes a token. If the bucket is empty, requests are dropped or queued, allowing controlled bursts up to bucket capacity. In the Leaky Bucket algorithm, incoming requests enter a FIFO queue and leak out at a strictly constant rate, smoothing traffic into an uncompromising steady stream."
    },
    {
      q: "7. What are False Positives and False Negatives, and which is generally more dangerous for an e-commerce platform?",
      a: "A False Positive (FP) occurs when legitimate client traffic is incorrectly classified as malicious and blocked. A False Negative (FN) occurs when an actual DDoS attack slips past detection. While FNs can cause service downtime, persistent FPs in e-commerce directly drop paying customers during peak high-revenue sales events (such as Flash Sales). A balanced SOC tuning aims to minimize both, often using graceful degradation (throttling or CAPTCHA challenges) rather than abrupt hard IP drops."
    },
    {
      q: "8. Why is simple IP blocking alone insufficient against modern botnet attacks?",
      a: "First, attackers frequently use IP address spoofing (in UDP/ICMP/DNS reflection attacks) where the source IP in the packet header is forged. Second, botnets such as Mirai recruit tens of thousands of real home routers and IoT devices across global residential ISPs; blocking them one by one leads to table bloat in firewalls and causes collateral damage when legitimate users share dynamic IPs (CGNAT). Modern defenses require multi-layered rate limiting, behavioral challenge-response, and CDN scrubbing."
    },
    {
      q: "9. How does our project's threshold-based detection algorithm ensure explainability for SOC analysts?",
      a: "Unlike black-box machine learning models that output an opaque risk score, our algorithm maps each alert to explicit, observable telemetry metrics: global RPS breach, source IP frequency anomaly, bandwidth saturation in MB/s, or TCP flag imbalance. For each trigger, the engine constructs a human-readable justification string (e.g., 'Source IP 192.168.1.101 emitted 180 req/s exceeding threshold of 120 req/s') enabling analysts to verify and audit automated mitigations in seconds."
    },
    {
      q: "10. What is 'Defense-in-Depth' in the context of DDoS mitigation?",
      a: "Defense-in-Depth is a multi-layered security strategy ensuring that if one defensive tier fails, subsequent layers continue to protect the target. For DDoS, this comprises: 1) Anycast BGP routing and CDN edge scrubbing (absorbing terabits of volumetric traffic), 2) Border router ACLs and upstream ISP blackholing (filtering invalid protocols), 3) Stateful firewall rate-limiting and SYN cookies (protecting L4 state tables), 4) Web Application Firewalls (WAF) inspecting L7 HTTP headers and bot signatures, and 5) Application-level caching and circuit breakers preventing database starvation."
    }
  ];

  return (
    <div className="space-y-6 font-mono text-xs">
      
      {/* Project Overview Header */}
      <div className="cyber-panel p-6 rounded-xl border border-slate-800 bg-gradient-to-r from-slate-900/90 to-slate-950/90">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div>
            <span className="px-2.5 py-0.5 rounded text-[11px] font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 uppercase">
              Academic Cybersecurity Defense Project
            </span>
            <h2 className="text-xl font-bold text-white mt-2">
              DDoS Attack Detection and Mitigation Dashboard
            </h2>
            <p className="text-slate-400 text-xs mt-1 max-w-3xl leading-relaxed">
              An educational defensive platform that models network traffic telemetry, demonstrates explainable threshold-based DDoS detection, and simulates reactive mitigation strategies in an isolated RFC-1918 testbed.
            </p>
          </div>

          <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 shrink-0 text-right">
            <span className="text-[10px] text-slate-500 block">TARGET TESTBED</span>
            <span className="text-sm font-bold text-emerald-400">192.168.1.1 (Safe)</span>
            <span className="text-[10px] text-slate-400 block mt-0.5">In-Memory Telemetry</span>
          </div>
        </div>
      </div>

      {/* 2-Minute Viva Pitch / Elevator Summary */}
      <div className="cyber-panel p-5 rounded-xl border border-amber-500/40 bg-amber-950/10">
        <div className="flex items-center gap-2 text-amber-300 font-bold text-sm mb-2">
          <BookOpen className="w-4 h-4" />
          <span>2-MINUTE VIVA VOCE ELEVATOR EXPLANATION (FOR PROFESSOR)</span>
        </div>
        <div className="p-3.5 rounded-lg bg-black/40 border border-amber-500/20 text-slate-200 text-xs leading-relaxed space-y-2">
          <p>
            <em>"Respected Professor, my project is a <strong>DDoS Attack Detection and Mitigation Dashboard</strong> designed to demonstrate how enterprise Security Operations Centers (SOCs) protect web infrastructure against distributed attacks."</em>
          </p>
          <p>
            <em>"The application features a <strong>safe in-memory traffic generator</strong> that simulates both nominal user traffic and four distinct attack vectors: HTTP Floods, SYN Floods, UDP Floods, and ICMP Floods. As traffic streams into our protected gateway, our <strong>explainable detection engine</strong> extracts key metrics in real time—including Requests Per Second (RPS), bandwidth volume in MB/s, TCP flag distributions, and source frequency entropy."</em>
          </p>
          <p>
            <em>"When traffic exceeds configurable thresholds, the system dynamically calculates a threat score from 0 to 100, assigns a threat level (LOW to CRITICAL), and triggers automated security alerts with clear human-readable forensic reasons. Finally, the defensive mitigation module simulates <strong>IP blacklisting, sliding-window rate limiting, and deep packet filtering</strong>, immediately suppressing the attack and returning the protected server to a healthy operating baseline."</em>
          </p>
        </div>
      </div>

      {/* Technical Specifications Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        
        {/* Core Architecture */}
        <div className="cyber-panel p-5 rounded-xl border border-slate-800 space-y-3">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span>PROJECT METADATA & ARCHITECTURE</span>
          </h3>

          <div className="space-y-2 text-xs">
            <div className="flex justify-between p-2 rounded bg-slate-900/60 border border-slate-800">
              <span className="text-slate-400">Frontend Stack:</span>
              <span className="text-cyan-300 font-bold">React 18, Vite 6, Tailwind CSS, Recharts</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-slate-900/60 border border-slate-800">
              <span className="text-slate-400">Backend Stack:</span>
              <span className="text-cyan-300 font-bold">Node.js, Express, REST APIs (CORS enabled)</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-slate-900/60 border border-slate-800">
              <span className="text-slate-400">Telemetry Sampling:</span>
              <span className="text-white font-bold">1-Second Discrete Rolling Windows</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-slate-900/60 border border-slate-800">
              <span className="text-slate-400">Mitigation Techniques:</span>
              <span className="text-emerald-300 font-bold">IP Blacklisting, Rate Limiter, DPI Filter</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-slate-900/60 border border-slate-800">
              <span className="text-slate-400">Target Environment:</span>
              <span className="text-purple-300 font-bold">Simulated Enterprise Gateway (192.168.1.1)</span>
            </div>
          </div>
        </div>

        {/* Explainable Detection Algorithm Logic */}
        <div className="cyber-panel p-5 rounded-xl border border-slate-800 space-y-3">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Code className="w-4 h-4 text-purple-400" />
            <span>EXPLAINABLE DETECTION ALGORITHM LOGIC</span>
          </h3>

          <div className="p-3.5 rounded-lg bg-black/60 border border-slate-800 text-[11px] text-cyan-300 leading-relaxed font-mono">
{`Algorithm DDoS-Detection(window_telemetry, thresholds):
  1. Calculate aggregate RPS = sum(requests) / window_duration
  2. Compute per-IP request frequencies: F(ip) for all active sources
  3. Calculate network volume V_MB = sum(packet_bytes) / 10^6
  4. IF RPS > thresholds.RPS_LIMIT THEN
       reasons.append("Aggregate traffic rate exceeded ceiling")
       isPotentialDDoS = True
  5. IF max(F(ip)) > thresholds.SINGLE_IP_LIMIT THEN
       reasons.append("Source IP anomaly burst detected")
       flagOffender(ip)
  6. Compute ThreatScore = 0.45*(RPS/RPS_LIMIT) + 0.30*(AnomRatio)
  7. Return { isPotentialDDoS, ThreatLevel, reasons, recommendedMitigation }`}
          </div>
        </div>

      </div>

      {/* 10 Curated Viva Voce Q&A Accordion */}
      <div className="cyber-panel p-6 rounded-xl border border-slate-800 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <GraduationCap className="w-5 h-5 text-cyan-400" />
            <h3 className="text-base font-bold text-white">
              10 ESSENTIAL VIVA VOCE QUESTIONS & MODEL ANSWERS
            </h3>
          </div>
          <span className="text-slate-400 text-xs">Curated for Faculty Evaluation</span>
        </div>

        <div className="space-y-2.5">
          {vivaQuestions.map((item, index) => {
            const isOpen = openFaq === index;
            return (
              <div
                key={index}
                className="rounded-lg border border-slate-800 bg-slate-900/40 overflow-hidden transition-all"
              >
                <button
                  onClick={() => setOpenFaq(isOpen ? -1 : index)}
                  className="w-full p-3.5 text-left flex items-center justify-between gap-3 hover:bg-slate-800/40 transition-colors"
                >
                  <span className="font-bold text-xs text-slate-200">
                    {item.q}
                  </span>
                  {isOpen ? (
                    <ChevronUp className="w-4 h-4 text-cyan-400 shrink-0" />
                  ) : (
                    <ChevronDown className="w-4 h-4 text-slate-500 shrink-0" />
                  )}
                </button>

                {isOpen && (
                  <div className="p-3.5 pt-0 text-slate-300 text-xs leading-relaxed border-t border-slate-800/60 bg-slate-950/40">
                    <p className="mt-2 text-slate-300 pl-3 border-l-2 border-cyan-500/60">
                      {item.a}
                    </p>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

    </div>
  );
};
