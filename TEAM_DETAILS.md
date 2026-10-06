# REVA University — School of Computer Science & Engineering
## Semester End Examination (SEE) Hackathon — अभिनव (Abhinava)
### Team Details Sheet & Individual Contribution Log (Annexure B)

**Date of Hackathon:** 07/10/2026 (9:00 AM – 9:00 PM)  
**Course Code & Title:** `B25CS0311` — Portfolio Building Studio (Credits: 0-0-2)  
**Program & Semester:** 3rd Semester B.Tech — Computer Science and Information Technology (CSIT), Section J  
**Venue:** SVB and SMVB Block, REVA University, Bengaluru  
**Team Name:** **NetGuard**  
**Selected Problem Statement:** **Topic 7: Network Traffic Analyzer & Intrusion Detection System**

---

### 1. Mandatory 4-Member Team Roster & Role Allocation

| Member Designation | Student Name | University SRN | Section | Primary Hackathon Role |
| :--- | :--- | :--- | :--- | :--- |
| **Member A** (Team Lead) | **Abhishek Maurya** | `R25EJ004` | CSIT - J | Core Logic & Packet Decoding Engine Architect |
| **Member B** | **Arun H Kalamuddi** | `R25EJ013` | CSIT - J | Supporting Logic & Anomaly/Attack Detector |
| **Member C** | **Rakesh N** | `R25EJ042` | CSIT - J | Interface, Visualization & Web Dashboard Engineer |
| **Member D** | **Sneha R** | `R25EJ058` | CSIT - J | Documentation, Test PCAP Generation & Presentation Lead |

---

### 2. Specific Individual Contributions (Hour 0 – Hour 12)

- **Abhishek Maurya (`R25EJ004`) — Member A (Core Logic / Backend):**
  - Engineered the pure-Python zero-dependency binary Libpcap packet parser (`packet_parser.py`) utilizing `struct` and `socket` to decode Ethernet frames, IPv4 headers, and L4 TCP/UDP/ICMP control headers without third-party C driver dependencies.
  - Architected the statistical aggregator (`traffic_analyzer.py`) computing throughput, packet frequencies, protocol distribution, and top talker matrices.

- **Arun H Kalamuddi (`R25EJ013`) — Member B (Supporting Logic / Integration):**
  - Designed the intrusion and anomaly state machine (`anomaly_detector.py`) detecting horizontal/vertical port reconnaissance (Nmap-style scans), DoS SYN floods, and unauthorized malware port access (Metasploit, Telnet).
  - Integrated the bidirectional protocol filters to eliminate false-positive port scan alerts on server return traffic.

- **Rakesh N (`R25EJ042`) — Member C (Interface / Output / Testing):**
  - Built the modern glassmorphism web dashboard (`web/index.html`, `styles.css`, `app.js`) with responsive Chart.js visual analytics and instant packet filtering.
  - Implemented the native multithreaded REST API server (`web_server.py`) with scenario selection support.

- **Sneha R (`R25EJ058`) — Member D (Documentation / Presentation / Research):**
  - Synthesized standard binary test PCAP captures (`generate_pcaps.py`) for clean traffic, port scan attack, and DoS floods to guarantee 100% reliable live demonstrations for judges.
  - Authored the 5-slide interactive presentation deck (`slides/index.html`, `SLIDES.md`), comprehensive project README, and automated unit test suite (`tests/test_analyzer.py`).

---

### 3. Student Signature Declaration
We hereby declare that this project was designed, developed, and verified collaboratively within the 12-hour SEE Hackathon window on 07/10/2026 according to REVA University examination guidelines.

- *Abhishek Maurya (R25EJ004)*: ______________________
- *Arun H Kalamuddi (R25EJ013)*: ______________________
- *Rakesh N (R25EJ042)*: ______________________
- *Sneha R (R25EJ058)*: ______________________
