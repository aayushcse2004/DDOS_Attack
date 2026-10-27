# 🛡️ DDoS Attack Detection and Mitigation Dashboard (Academic & Defensive SOC Platform)

An academic-grade, defensive cybersecurity platform demonstrating real-time network traffic telemetry, multi-factor statistical anomaly detection, transparent 0–100 threat scoring, reactive mitigation with TTL rule expiration, full incident forensics management, and empirical benchmark evaluation in a modern SOC-style interface.

> [!IMPORTANT]
> **Defensive & Educational Project Notice**:
> This application is built strictly for academic learning and defensive research. It utilizes safe, in-memory synthetic telemetry over private RFC-1918 addresses (`192.168.x.x`, `10.0.x.x`, `172.16.x.x`). It does **NOT** flood external hosts, bypass security controls, or generate unauthorized real-world malicious network packets. Network protections are modeled through software-level packet filtering and token-bucket rate limiting rather than direct operating system kernel driver hooks.

---

## 📑 Table of Contents

1. [Project Overview & Objective](#-project-overview--objective)
2. [7 Development Phases & Enhancements](#-7-development-phases--enhancements)
3. [Key System Features](#-key-system-features)
4. [System Architecture](#-system-architecture)
5. [Technology Stack](#-technology-stack)
6. [Installation & Setup](#-installation--setup)
7. [How to Run & Test](#-how-to-run--test)
8. [Automated Test Suite (26 Verification Tests)](#-automated-test-suite-26-verification-tests)
9. [Step-by-Step Demonstration Script (For Faculty Presentation)](#-step-by-step-demonstration-script-for-faculty-presentation)
10. [Detection Algorithm & Mathematical Formulations](#-detection-algorithm--mathematical-formulations)
11. [Threat Scoring Mechanics (0–100 Breakdown)](#-threat-scoring-mechanics-0100-breakdown)
12. [Defensive Mitigation Pipeline](#-defensive-mitigation-pipeline)
13. [Incident Management & Forensics](#-incident-management--forensics)
14. [REST API Reference](#-rest-api-reference)
15. [Project Directory Structure](#-project-directory-structure)
16. [10 Essential Viva Voce Questions & Model Answers](#-10-essential-viva-voce-questions--model-answers)
17. [Limitations & Future Research](#-limitations--future-research)
18. [License & Ethical Attribution](#-license--ethical-attribution)

---

## 🎯 Project Overview & Objective

Distributed Denial of Service (DDoS) attacks remain one of the most critical threats to internet infrastructure, attempting to exhaust network bandwidth, server sockets, or application CPU.

### Core Academic Objective
This platform demonstrates the end-to-end defensive lifecycle of network attack detection, forensic attribution, and defensive mitigation in a clear, explainable, and demonstrable format:
$$\text{Ingress Telemetry} \longrightarrow \text{Multi-Factor Analysis} \longrightarrow \text{Statistical Baseline (EMA \& Z-Score)} \longrightarrow \text{Incident Management} \longrightarrow \text{Defensive Mitigation}$$

Unlike black-box commercial tools, every stage of detection, scoring, and mitigation in this project provides transparent mathematical formulations, human-readable explanations, and ground-truth metrics.

---

## 🚀 7 Development Phases & Enhancements

This project has been systematically developed and verified across seven distinct phases:

| Phase | Module | Key Capabilities Implemented |
|---|---|---|
| **Phase 1** | **Improved DDoS Detection** | Multi-factor analysis (RPS, bandwidth MB/s, unique source IPs, concentration ratio, traffic velocity). Rolling baseline moving average (EMA $\alpha=0.15$) and Z-score anomaly detection. Explainable detection reasons. Incident-aware alert deduplication preventing alert storms. |
| **Phase 2** | **Transparent Threat Scoring** | Normalized 0–100 composite threat score. Explicit breakdown of individual indicator contributions (volumetric, anomaly velocity, attack vector signature, IP concentration, and mitigation suppression). Robust clamping and safe handling of zero/missing values. |
| **Phase 3** | **Defensive Mitigation** | Configurable per-IP sliding-window rate limiting. Temporary IP blacklisting with automatic TTL expiration. Manual unblocking. Mitigation action audit log. Before-and-after traffic impact telemetry. |
| **Phase 4** | **Incident Management** | Dedicated Incident Investigation page. Structured incident tracking (ID, timestamps, duration, peak RPS, peak Z-Score, offending IPs, detection reasons). Chronological incident timelines and SOC analyst note threads. |
| **Phase 5** | **Analytics & Evaluation** | Real ground-truth confusion matrix (TP, TN, FP, FN), precision, recall, F1-score, and detection latency (ms) measured across labelled synthetic scenarios. No fabricated accuracy percentages. |
| **Phase 6** | **Reporting & Testing** | RFC-4180 compliant CSV forensic exports. Formal styled printable HTML/PDF report dossier. Comprehensive backend test suite (26 assertions across 4 test suites) validating all detection, scoring, and mitigation logic. |
| **Phase 7** | **Frontend SOC Dashboard** | High-contrast SOC dark theme (`#080C14`), responsive layouts, real-time Recharts visualizations, multi-factor telemetry ribbons, threat breakdown meters, and empty/loading state handling. |

---

## ✨ Key System Features

### 1. Multi-Factor Anomaly & DDoS Detection Engine
- **Global RPS & Bandwidth Saturation**: Evaluates instantaneous request velocity and bandwidth consumption against configurable thresholds.
- **Statistical Velocity & Z-Score Anomaly**:
  $$Z = \frac{\text{RPS} - \text{EMA}}{\sigma_{\text{baseline}}}$$
  Detects sudden traffic acceleration before static ceilings are breached.
- **Source IP Distribution Entropy**: Analyzes top-talker concentration ($N_{\text{top}} / N_{\text{total}}$) to distinguish botnets from organic distributed users.
- **Protocol & State Table Inspection**: Evaluates TCP SYN-to-ACK asymmetry, connectionless UDP datagram storms, and ICMP Echo inundation.

### 2. Transparent 0–100 Threat Scoring
- Continuous mathematical model providing an audited breakdown:
  - Base Network Floor: `5 pts`
  - Volumetric Factor: `0 to 35 pts`
  - Anomaly Velocity / Z-Score: `0 to 25 pts`
  - Attack Signature Heuristics: `0 to 25 pts`
  - IP Concentration Ratio: `0 to 15 pts`
  - Mitigation Suppression Discount: `Up to -35% deduction`
- Categorized into operational threat bands:
  - **LOW** (`0–25`): Emerald — Nominal baseline parameters
  - **MEDIUM** (`26–50`): Yellow — Moderate fluctuation or single-source elevation
  - **HIGH** (`51–75`): Amber — Confirmed threshold breach or attack pattern
  - **CRITICAL** (`76–100`): Rose — Severe multi-vector flood threatening gateway survival

### 3. Defensive Mitigation & Access Control
- **Per-IP Rate Limiting**: Sliding-window quota preventing bursts from starving system capacity.
- **IP Blacklisting with TTL Auto-Expiration**: Support for permanent or temporary containment (e.g. 30s, 60s, 300s TTL) with automatic expiration sweeps.
- **Deep Packet Inspection (DPI)**: Suppresses malformed ICMP echo floods and amplified UDP datagrams.
- **TCP SYN Cookie Simulation**: Defends against connection backlog table exhaustion without allocating kernel state.
- **Mitigation Audit Trail**: Immutable log of every defensive enforcement action taken.

### 4. Forensic Incident Investigation Center
- Dedicated incident triage view with status filtering (`OPEN`, `INVESTIGATING`, `MITIGATED`, `RESOLVED`).
- Detail drawer with chronological event timelines and analyst note threads.
- One-click **CSV Forensic Export** and formal **Printable HTML/PDF Dossier**.

### 5. Empirical Benchmark & Ground-Truth Evaluation
- Live benchmark runner evaluating 62 synthetic samples across 4 labelled scenarios.
- Calculates authentic confusion matrix metrics ($TP, TN, FP, FN$, Precision, Recall, F1-Score) and measured detection latency ($ms$).

---

## 🏛️ System Architecture

```
                                  [ INGRESS TELEMETRY ]
                           (Private RFC-1918 IP Simulation)
                                          │
                                          ▼
                             ┌─────────────────────────┐
                             │  Express Server (:5000) │
                             │  trafficEngine.js       │
                             └────────────┬────────────┘
                                          │
               ┌──────────────────────────┴──────────────────────────┐
               ▼                                                     ▼
    ┌──────────────────────┐                              ┌──────────────────────┐
    │  DDoS Detector       │                              │  Mitigation Manager  │
    │  - Multi-factor logic│                              │  - IP Blacklist (TTL)│
    │  - Rolling EMA / Z   │                              │  - Rate Limiter      │
    │  - Incident Manager  │                              │  - DPI & SYN Cookie  │
    │  - Ground Truth Eval │                              │  - Audit Trail Log   │
    └──────────┬───────────┘                              └──────────┬───────────┘
               │                                                     │
               └──────────────────────────┬──────────────────────────┘
                                          │  REST APIs (/api/stats, /api/incidents, /api/evaluation)
                                          ▼
                             ┌─────────────────────────┐
                             │  React + Vite Frontend  │
                             │  - Dark Theme SOC UI    │
                             │  - Recharts Visualizer  │
                             │  - Security Context     │
                             │  - Incident Drawer      │
                             └─────────────────────────┘
```

---

## 💻 Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| **Frontend Framework** | React 18 + Vite 6 | Fast modular single-page SOC application |
| **Styling & Design System** | Tailwind CSS | High-contrast dark SOC theme (`#080C14`), glassmorphism, glows |
| **Data Visualization** | Recharts | Real-time area charts, composition donuts, and protocol bars |
| **Icons** | Lucide React | Modern cybersecurity icons |
| **Backend Framework** | Node.js + Express 4 | Telemetry simulation, REST APIs, and forensic coordination |
| **State Management** | React Context API | Global telemetry synchronization and toast notifications |
| **Concurrency Runner** | Concurrently | Single-command launch for client and server processes |
| **Testing Engine** | Node.js Assertions | Automated unit and integration test suites |

---

## 📦 Installation & Setup

### Prerequisites
- **Node.js**: v18.0.0 or higher
- **npm**: v9.0.0 or higher

### 1. Clone or Open Project Directory
```powershell
cd ddos_3
```

### 2. Install All Dependencies
Run the unified installer to configure root, server, and client environments:
```powershell
npm.cmd run install:all
```

---

## 🚀 How to Run & Test

### Option A: Unified Startup (Recommended)
Run both backend Express server and frontend Vite server in a single terminal:
```powershell
npm.cmd run dev
```
- **Frontend Dashboard**: `http://localhost:5173`
- **Backend REST API**: `http://localhost:5000/api/stats`

### Option B: Separate Terminals

**Terminal 1 (Backend Server):**
```powershell
npm.cmd run server
# Listening on http://localhost:5000
```

**Terminal 2 (Frontend Client):**
```powershell
npm.cmd run client
# Vite ready at http://localhost:5173
```

---

## 🧪 Automated Test Suite (26 Verification Tests)

The project includes four automated backend test suites verifying all functional requirements:

```powershell
npm.cmd test
```

### Test Suite Execution Output:
```text
======================================================
🧪 RUNNING PHASE 1 DETECTION ENGINE AUTOMATED TEST SUITE
======================================================
  ✓ [PASS] 1. Baseline Nominal Traffic does not trigger false alerts
  ✓ [PASS] 2. Global Volumetric RPS Breach triggers explainable alert
  ✓ [PASS] 3. Bandwidth Saturation (MB/s) triggers detection even with moderate RPS
  ✓ [PASS] 4. Per-IP Request Concentration detects single high-volume talker
  ✓ [PASS] 5. Statistical Anomaly flags sudden velocity surge even below hard ceiling
  ✓ [PASS] 6. TCP SYN Handshake asymmetry triggers state table exhaustion warning
  ✓ [PASS] 7. Alert Deduplication prevents duplicate alerts during ongoing attack
  ✓ [PASS] 8. Configurable Thresholds update dynamically and alter evaluation immediately
Results: 8 of 8 tests passed successfully.

======================================================
🧪 RUNNING PHASE 2 THREAT SCORER AUTOMATED TEST SUITE
======================================================
  ✓ [PASS] 1. Nominal baseline traffic yields LOW threat level (<= 25)
  ✓ [PASS] 2. Severe HTTP Flood yields CRITICAL threat level (>= 76)
  ✓ [PASS] 3. Defensive mitigation drops threat score proportionally
  ✓ [PASS] 4. Extreme inputs are strictly clamped between 0 and 100
  ✓ [PASS] 5. Safe handling of null, undefined, NaN, and missing parameters
  ✓ [PASS] 6. Intermediate conditions map cleanly to MEDIUM and HIGH levels
Results: 6 of 6 tests passed successfully.

======================================================
🧪 RUNNING PHASE 3 MITIGATION ENGINE AUTOMATED TEST SUITE
======================================================
  ✓ [PASS] 1. IP Blacklist drops 100% of packets from blocked IP
  ✓ [PASS] 2. Manual unblock permits subsequent requests
  ✓ [PASS] 3. Temporary IP Block automatically expires after TTL duration
  ✓ [PASS] 4. Rate Limiting caps per-IP bursts without blocking nominal traffic
  ✓ [PASS] 5. TCP SYN Cookie and DPI Filtering suppress Layer 4 protocol floods
  ✓ [PASS] 6. Complete audit trail records all mitigation actions and computes effectiveness
Results: 6 of 6 tests passed successfully.

======================================================
🧪 RUNNING INCIDENTS & EVALUATION AUTOMATED TEST SUITE
======================================================
  ✓ [PASS] 1. Incident Manager retrieves and filters incidents by status and severity
  ✓ [PASS] 2. Updating incident status appends timeline event and note
  ✓ [PASS] 3. Analysts can append forensic notes with author attribution
  ✓ [PASS] 4. Incident CSV Export generates compliant header and forensic rows
  ✓ [PASS] 5. Forensic Report generator outputs complete styled printable HTML
  ✓ [PASS] 6. Benchmark evaluates TP, TN, FP, FN, precision, recall, F1, and latency
Results: 6 of 6 tests passed successfully.
```

---

## 🎬 Step-by-Step Demonstration Script (For Faculty Presentation)

Follow this 5-minute presentation walkthrough to demonstrate the system to academic evaluators:

### Step 1: Baseline Nominal Monitoring (`/dashboard`)
1. Point to the **System Status**: `TELEMETRY SYNCED`, `CORE: ACTIVE`.
2. Review the **Multi-Factor Ribbon**: Baseline EMA (`~38 req/s`), Anomaly Z-Score (`+0.0 σ`), Top Source Share (`<20%`).
3. Observe the **Threat Score Meter**: `12/100 (LOW)` with transparent indicator breakdown.
4. Review the **Real-Time Area Chart**: Telemetry operates smoothly below the yellow 500 req/s threshold line.

### Step 2: Inject an Attack Scenario
1. In the **Attack Scenario Simulator**, select **"HTTP Flood (L7)"** (or "SYN Flood").
2. **Observe Instantaneous Telemetry Reaction**:
   - Aggregate RPS spikes to `700–1,100 req/s`.
   - Velocity Z-Score jumps to `+4.5 to +6.0 σ`.
   - Threat Level switches to **CRITICAL** (`80–95/100`) with a glowing rose pulse.
   - The top banner provides explicit forensic justification: *"Volumetric Ingress Breach: Aggregate traffic rate of 840 req/s exceeded safety threshold of 500 req/s"*.
   - A single deduplicated alert appears in the **Latest Security Alerts** feed.

### Step 3: Incident Forensics & Investigation (`/incidents`)
1. Click **Incident Forensics** in the sidebar.
2. Open the active incident:
   - Review the **Forensic Metrics Grid** (Attack vector, Peak Ingress, Z-Score, Duration).
   - Inspect the **Chronological Timeline** tracking onset, detection trigger, and escalation.
   - Click **"Block"** next to an offending botnet IP.
   - Add an analyst note: *"Applied perimeter throttling to botnet cluster"*.
3. Click **"PDF Report"** to show the formal printable forensic report dossier.

### Step 4: Execute Defensive Mitigation (`/mitigation`)
1. Click **Mitigation Rules** in the sidebar.
2. Toggle on **Rate Limiting (Sliding Window)** at `80 req/s`.
3. Add a temporary block on `192.168.1.101` with **"60 Seconds TTL"**.
4. Observe the **Before vs After Impact Analysis**:
   - Total Ingress vs Permitted vs Suppressed requests.
   - Active Filter Ratio reaches `70–85%`.
5. Point to the **Mitigation Action Audit Trail** showing the recorded `BLOCK_IP` and `CONFIG_RATE_LIMIT` events.

### Step 5: Academic Evaluation & Confusion Matrix (`/analytics`)
1. Click **Analytics & Trends** in the sidebar.
2. Click **"RUN BENCHMARK SUITE"**:
   - Evaluates 62 synthetic samples across 4 labelled scenarios.
   - Displays real **Accuracy (100%)**, **Precision (100%)**, **Recall (100%)**, **F1-Score (100%)**, and **Detection Latency (<1.0 ms)**.
   - Show the 2x2 Confusion Matrix and the scenario breakdown table.

---

## 🧠 Detection Algorithm & Mathematical Formulations

### 1. Rolling Exponential Moving Average (EMA)
$$\text{EMA}_t = \alpha \cdot \text{RPS}_t + (1 - \alpha) \cdot \text{EMA}_{t-1}$$
where smoothing factor $\alpha = 0.15$.

### 2. Sample Standard Deviation ($\sigma$) & Z-Score
$$\sigma = \sqrt{\frac{1}{N-1} \sum_{i=1}^{N} (\text{RPS}_i - \mu)^2}$$
$$Z = \frac{\text{RPS}_t - \text{EMA}_t}{\max(\sigma, 2.0)}$$
An anomaly is flagged when $Z \ge 2.5$ and growth ratio $\ge 2.0\times$.

### 3. Per-IP Concentration Ratio ($C$)
$$C = \frac{\max_{i} (\text{Requests}_{\text{IP}_i})}{\sum \text{Requests}_{\text{Total}}}$$
If $C \ge 0.40$ (40% of all ingress from a single source) during elevated volume, a concentration anomaly is triggered.

### 4. TCP Handshake Asymmetry Ratio ($R_{\text{SYN}}$)
$$R_{\text{SYN}} = \frac{\text{SYN Count}}{\max(1, \; \text{SYN Count} + \text{ACK Count})}$$
When $R_{\text{SYN}} \ge 0.70$ and $\text{SYN Count} > 80$, the engine identifies TCP connection table exhaustion.

---

## 🛡️ Threat Scoring Mechanics (0–100 Breakdown)

$$\text{ThreatScore} = \min\left(100, \; \max\left(0, \; \text{RawScore} - \text{MitigationDiscount}\right)\right)$$

Where:
$$\text{RawScore} = \text{Base} (5) + \text{Volumetric} (0\text{–}35) + \text{Velocity} (0\text{–}25) + \text{Signature} (0\text{–}25) + \text{Concentration} (0\text{–}15)$$

Mitigation discount dampens target threat when defensive rules actively filter malicious ingress:
$$\text{MitigationDiscount} = \begin{cases} 
0.35 \times \text{RawScore} & \text{if BlockedRatio} > 0.75 \land \text{RawScore} > 35 \\ 
0.20 \times \text{RawScore} & \text{if BlockedRatio} > 0.40 \land \text{RawScore} > 30 \\ 
0.10 \times \text{RawScore} & \text{if BlockedRatio} > 0.15 \land \text{RawScore} > 25 \\ 
0 & \text{otherwise} 
\end{cases}$$

---

## 🔌 REST API Reference

### Telemetry & Stats
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/stats` | Returns real-time metrics, RPS, threat level, multi-factor analysis |
| `GET` | `/api/traffic` | Retrieves packet stream (`filter`, `search`, `limit`) |
| `GET` | `/api/traffic/history` | Rolling 40-second historical time-series for Recharts |
| `GET` | `/api/threat-level` | Detailed threat level, composite score, and indicator breakdown |

### Simulation Control
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/simulation/start` | Resumes traffic simulation loop |
| `POST` | `/api/simulation/stop` | Pauses traffic simulation loop |
| `POST` | `/api/simulation/reset` | Resets all telemetry, counters, and rules to pristine baseline |
| `POST` | `/api/simulation/mode` | Sets scenario: `normal`, `http_flood`, `syn_flood`, `udp_flood`, `icmp_flood`, `demo` |
| `POST` | `/api/simulation/thresholds` | Configures thresholds: `rpsThreshold`, `volumeThresholdMB`, `singleIpRpsThreshold`, `zScoreThreshold` |

### Mitigation & Access Control
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/mitigation/rules` | Retrieves active block rules, rate limits, and filter states |
| `GET` | `/api/mitigation/logs` | Retrieves immutable audit trail of mitigation actions (`limit`) |
| `GET` | `/api/mitigation/stats` | Returns before/after telemetry (ingress vs allowed vs suppressed) |
| `POST` | `/api/mitigation/block` | Blacklists an IP with optional TTL: `{ "ip": "...", "reason": "...", "durationSeconds": 60 }` |
| `POST` | `/api/mitigation/unblock` | Removes an IP from blacklist: `{ "ip": "..." }` |
| `POST` | `/api/mitigation/rate-limit` | Configures rate limiter: `{ "enabled": true, "threshold": 80 }` |
| `POST` | `/api/mitigation/filter` | Toggles DPI filtering: `{ "enabled": true }` |
| `POST` | `/api/mitigation/syn-cookie` | Toggles TCP SYN Cookie defense: `{ "enabled": true }` |

### Incident Forensics & Reporting
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/incidents` | Lists incident cases with filters: `status`, `severity`, `search` |
| `GET` | `/api/incidents/:id` | Returns complete incident forensics and timeline |
| `POST` | `/api/incidents/:id/status` | Updates status: `{ "status": "MITIGATED", "note": "...", "author": "..." }` |
| `POST` | `/api/incidents/:id/notes` | Appends analyst note: `{ "note": "...", "author": "..." }` |
| `GET` | `/api/incidents/:id/export/csv` | Downloads RFC-4180 forensic CSV for specific incident |
| `GET` | `/api/incidents/export/csv` | Downloads summary CSV of all recorded incidents |
| `GET` | `/api/incidents/:id/report` | Generates formal, printable HTML/PDF forensic report dossier |

### Benchmark Evaluation
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/evaluation/benchmark` | Returns latest benchmark confusion matrix and metrics |
| `POST` | `/api/evaluation/run` | Executes 62-sample benchmark suite and computes fresh ground-truth results |

---

## 📁 Project Directory Structure

```
ddos_3/
├── package.json                         # Root package & test runner orchestrator
├── README.md                            # Complete academic documentation & viva guide
├── server/                              # Node.js + Express backend server
│   ├── package.json
│   ├── server.js                        # REST API routing, error handling, CORS
│   ├── simulator/
│   │   ├── trafficEngine.js             # Telemetry engine & historical time-series buffer
│   │   └── sampleData.js                # RFC-1918 private IPs, attack signatures, user agents
│   ├── detection/
│   │   ├── detector.js                  # Multi-factor anomaly engine & alert deduplication
│   │   ├── threatScorer.js              # Transparent 0-100 composite threat scorer
│   │   └── incidentManager.js           # Forensic incident records, timelines, CSV/PDF reports
│   ├── mitigation/
│   │   └── mitigationManager.js         # IP blacklist with TTL, rate limiter, DPI, audit log
│   ├── evaluation/
│   │   └── evaluator.js                 # Ground-truth benchmark suite (TP/TN/FP/FN/latency)
│   └── test/
│       ├── detection.test.js            # Phase 1 test suite (8 tests)
│       ├── threatScorer.test.js         # Phase 2 test suite (6 tests)
│       ├── mitigation.test.js           # Phase 3 test suite (6 tests)
│       └── incidentAndEvaluation.test.js# Phase 4, 5, 6 test suite (6 tests)
└── client/                              # React + Vite frontend client
    ├── package.json
    ├── vite.config.js                   # Proxy configuration for port 5000
    ├── tailwind.config.js               # SOC Cyber Dark Theme tokens
    ├── index.html                       # Fonts & web metadata
    └── src/
        ├── App.jsx                      # Navigation controller & active page switcher
        ├── main.jsx                     # React DOM entrypoint
        ├── index.css                    # Design system utilities, scrollbars, glows
        ├── context/
        │   └── SecurityContext.jsx      # Global telemetry state polling & toast dispatch
        ├── services/
        │   └── api.js                   # REST API client wrapper
        ├── components/
        │   ├── Header.jsx               # Navigation bar, Threat badge, Demo trigger
        │   ├── Sidebar.jsx              # SOC navigation sidebar
        │   ├── StatCard.jsx             # Metric card components
        │   └── Toast.jsx                # Toast alerts
        └── pages/
            ├── Dashboard.jsx            # Real-time telemetry, multi-factor bar, threat meter
            ├── Traffic.jsx              # Real-time packet table & Deep Packet Inspector
            ├── Alerts.jsx               # Security alert triage & 1-click remediation
            ├── Incidents.jsx            # Forensic incident investigation, timelines, CSV/PDF
            ├── Analytics.jsx            # Real benchmark evaluator, confusion matrix, latency
            ├── Mitigation.jsx           # Firewall controls, TTL expirations, before/after impact
            ├── HowItWorks.jsx           # 8-stage educational pipeline with code & math
            └── About.jsx                # Project specifications & 10 Viva Voce Q&As
```

---

## 🎓 10 Essential Viva Voce Questions & Model Answers

### Q1: What is the fundamental difference between a DoS and a DDoS attack?
**Answer**: A Denial of Service (DoS) attack originates from a single network connection or host, making it straightforward to mitigate by blocking the offending IP address. In contrast, a Distributed Denial of Service (DDoS) attack harnesses hundreds or thousands of distributed devices (a botnet) across disparate autonomous systems. This distributed nature makes simple source IP blocking ineffective, as malicious traffic blends with legitimate traffic and exhibits low individual volume per node.

### Q2: What is the difference between Layer 4 and Layer 7 DDoS attacks?
**Answer**: Layer 4 attacks (such as TCP SYN Floods or UDP Amplification) target network infrastructure, bandwidth limits, and transport state tables without completing application sessions. Layer 7 attacks (such as HTTP GET/POST Floods) establish valid TCP handshakes and mimic genuine user browsing behavior. They target server CPU, database queries, and backend memory by requesting computationally intensive endpoints (e.g., search queries, login endpoints).

### Q3: How does a TCP SYN Flood exploit the three-way handshake?
**Answer**: In a normal TCP handshake:
1. Client sends `SYN`.
2. Server allocates state in its Transmission Control Block (TCB) queue and replies with `SYN-ACK`.
3. Client completes with `ACK`.
In a SYN Flood, the attacker sends a massive flurry of `SYN` packets with spoofed source IPs or ignores `SYN-ACK`. The server holds half-open connections waiting until a timeout expires, exhausting table memory and dropping connections from legitimate users.

### Q4: What are SYN Cookies, and how do they defend without allocating memory?
**Answer**: SYN Cookies eliminate the need for the server to allocate state memory when a `SYN` arrives. Instead, the server mathematically encodes connection parameters (source IP, port, server secret, and timestamp) into the 32-bit Initial Sequence Number (ISN) of the `SYN-ACK`. When the client returns the final `ACK`, the server verifies the sequence number mathematically. Only upon valid verification is memory allocated, neutralizing connection backlog exhaustion.

### Q5: How does a detection system distinguish a legitimate Flash Crowd from a DDoS attack?
**Answer**: A legitimate Flash Crowd (e.g., Black Friday sales or breaking news) consists of authentic users who browse pages sequentially, request accompanying CSS/JavaScript/images, possess session cookies, exhibit natural human inter-arrival delays, and follow human navigation patterns. Conversely, a botnet exhibits low entropy in requested URLs, identical User-Agent strings, absent cookies, lack of secondary asset downloads, and rapid burst repetition from fixed IP clusters.

### Q6: How does the Token Bucket algorithm differ from the Leaky Bucket algorithm?
**Answer**:
- **Token Bucket**: Tokens are continuously deposited into a bucket at rate $r$ up to capacity $b$. Incoming requests consume tokens. If tokens are available, the request passes immediately. This allows **controlled traffic bursts** up to bucket capacity.
- **Leaky Bucket**: Incoming requests enter a FIFO queue and leak out at a strictly constant rate. Excess requests over queue capacity are dropped. This **smooths traffic into a uniform output stream**, disallowing bursts.

### Q7: What are False Positives and False Negatives, and which is more dangerous in e-commerce?
**Answer**: A **False Positive (FP)** occurs when legitimate client traffic is incorrectly flagged as malicious and blocked. A **False Negative (FN)** occurs when an actual DDoS attack slips past detection. In high-revenue e-commerce (such as flash sales), False Positives directly prevent paying customers from completing purchases, causing immediate financial loss and brand damage. Consequently, SOC teams tune systems using progressive challenges (rate limiting, CAPTCHAs) rather than immediate permanent IP bans.

### Q8: Why is simple IP blacklisting insufficient against modern botnets?
**Answer**:
1. **IP Spoofing**: In UDP/ICMP reflection attacks, the source IP in the packet header is forged, so blocking the apparent source drops traffic from innocent third parties.
2. **Dynamic Botnets**: Modern botnets control tens of thousands of IoT devices and residential routers with dynamic IPs or behind Carrier-Grade NAT (CGNAT). Blocking IPs leads to massive firewall table bloat and collateral blocking of legitimate users sharing the same public IP.

### Q9: How does our project's threshold-based detection algorithm ensure explainability?
**Answer**: Unlike black-box machine learning models that generate opaque probability scores, our threshold detection maps each alert to explicit, observable telemetry metrics: global RPS breach, single-IP request frequencies, bandwidth volume in MB/s, or TCP flag ratios. The engine constructs a clear rationale string (e.g., *"Potential DDoS detected: Aggregate traffic rate of 840 req/s breached safety ceiling of 500 req/s"*), providing SOC analysts with immediate actionable auditability.

### Q10: What is Defense-in-Depth in the context of DDoS mitigation?
**Answer**: Defense-in-Depth is a multi-tiered security strategy ensuring that if one defensive tier fails, subsequent layers continue to protect the target:
1. **Edge/Cloud Scrubbing (Tier 1)**: Anycast DNS and BGP scrubbing centers absorb massive multi-terabit volumetric floods.
2. **Perimeter Firewalls (Tier 2)**: Border router ACLs, SYN cookies, and protocol filters drop malformed packets.
3. **Web Application Firewall (Tier 3)**: WAF inspects HTTP headers, rate limits abusive API tokens, and injects JavaScript/CAPTCHA challenges.
4. **Application Tier (Tier 4)**: Caching layers (Redis), database read replicas, and circuit breakers prevent backend service starvation.

---

## ⚠️ Limitations & Future Research

### Educational Architecture Scope
- Telemetry is generated safely in-memory using Node.js synthetic distributions over private RFC-1918 IP addresses.
- Rate limiting and packet dropping are enforced at the application middleware layer rather than through kernel-level eBPF/XDP hardware bypasses.
- Baseline moving averages and active rule tables reside in Node.js process memory.

### Potential Future Extensions
1. **PCAP Capture Ingestion**: Direct parsing of recorded Wireshark packet captures (`.pcap` / `.pcapng`).
2. **Hybrid ML Classifier**: Integrating an isolation forest or autoencoder model alongside the explainable rule engine.
3. **Webhook Notifications**: Real-time incident dispatch to Slack or Microsoft Teams.

---

## 📄 License & Ethical Attribution
- Created as an academic cybersecurity project for educational and defensive learning.
- Released under the **MIT License**.
