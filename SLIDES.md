# 🖥️ NetGuard Presentation Deck (Markdown Edition)
### SEE Hackathon अभिनव (Abhinava) 2026 — Topic 7: Network Traffic Analyzer

---

## Slide 1: Problem Statement & Team Overview
- **Title:** NetGuard: Network Traffic Analyzer & Intrusion Detection System
- **Context:** REVA University SEE Hackathon Abhinava (B25CS0311 Studio Course)
- **Problem:** Modern enterprise and university networks lack transparent visibility into raw packet streams, making manual detection of stealth scans and DoS floods impossible.
- **Team NetGuard (Section J):**
  - **Abhishek Maurya** (`R25EJ004`) — Team Lead & Packet Engine Architect
  - **Arun H Kalamuddi** (`R25EJ013`) — Anomaly & Threat Detection
  - **Rakesh N** (`R25EJ042`) — Web Dashboard & Visual Analytics
  - **Sneha R** (`R25EJ058`) — Testing, Test PCAP Generator & Slides

---

## Slide 2: End-to-End System Architecture
- **Layer 1: Binary PCAP Ingestion**
  - Decodes libpcap standard format (Global 24-byte header + Packet 16-byte headers).
- **Layer 2: Protocol Demultiplexing**
  - Extracts Ethernet frames (MAC addressing).
  - Unpacks IPv4 header (TTL, Identification, Source & Destination IPs).
  - Evaluates Layer 4 control structures (TCP flags: SYN, ACK, FIN, RST; UDP ports; ICMP echo types).
- **Layer 3: Analytics & Anomaly State Machine**
  - Aggregates throughput (pps, kbps), top talkers, and protocol distributions.
  - Heuristic detection of port scans and buffer-exhausting SYN floods.
- **Layer 4: Dual Presentation Layer**
  - Rich CLI formatted tables + Browser-based Chart.js dashboard.

---

## Slide 3: Technology Stack & Technical Innovations
- **Core Engine:** Python 3.x Standard Library (`struct`, `socket`, `http.server`).
- **Zero Third-Party Dependency Requirement:**
  - No Wireshark GUI needed.
  - No WinPcap / Npcap kernel driver installations or permissions required.
  - Runs portably on any standard Python installation.
- **Frontend & Visualization:** HTML5, CSS3 Glassmorphism, Chart.js 4.4.
- **Testing & Verification:** Python `unittest` framework with 100% test pass rate.

---

## Slide 4: Security Detections in Live Evaluations
- **Reconnaissance Port Scans:**
  - Detects attacker `10.0.0.99` scanning 15+ target ports.
  - Raises `HIGH` severity alert with destination target telemetry.
- **Denial-of-Service (TCP SYN Flood):**
  - Flags attacker `172.16.4.88` emitting 40+ unacknowledged SYN packets.
  - Raises `CRITICAL` severity alert for connection state starvation.
- **Suspicious Backdoors & Malware Ports:**
  - Flags connections to port 23 (Telnet), 4444 (Metasploit), and 31337 (Back Orifice).
- **False-Positive Mitigation:**
  - Server return traffic with ephemeral destination ports is filtered to prevent false alerts.

---

## Slide 5: Challenges Overcome & Future Roadmap
- **Challenges Solved in 12-Hour Sprint:**
  - Byte-level endianness handling (big-endian vs little-endian PCAP magic).
  - Cross-platform Windows console character encoding (CP1252 compatibility).
- **Future Enhancements (Beyond 12 Hours):**
  - Supervised ML classification using Random Forest on NSL-KDD dataset features.
  - Promiscuous mode raw socket sniffing on Linux with automated `iptables` drop rules.
  - Exporting forensic incident reports to PDF format.
