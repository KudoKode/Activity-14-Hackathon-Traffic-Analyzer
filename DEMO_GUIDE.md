# 🎙️ 3-Minute Live Demo & Oral Presentation Script
### REVA University SEE Hackathon अभिनव (Abhinava) — Team NetGuard (Topic 7)

This script is structured for the **mandatory 3–5 minute live presentation and walkthrough** in front of the examiners at SVB/SMVB Block.

---

### Phase 1: Problem Context & Architecture (0:00 – 0:50)
**Speaker: Abhishek Maurya (Team Lead — `R25EJ004`)**

> "Good morning / afternoon respected examiners. Our team is **NetGuard**, representing 3rd Semester B.Tech CSIT, Section J. Our allotted problem statement is **Topic 7: Network Traffic Analyzer with Packet Sniffing & Intrusion Detection**."
>
> "In campus and enterprise networks, raw traffic data is often opaque. Security analysts cannot manually parse millions of packets to find malicious activity. To solve this, we engineered **NetGuard**, a zero-dependency, pure-Python network traffic engine."
>
> "Unlike typical projects that rely on heavy external drivers like Npcap or Scapy that often fail on client machines, NetGuard implements a native binary Libpcap parser from scratch. It directly decodes raw bytes into Ethernet frames, IPv4 headers, and Layer 4 TCP, UDP, and ICMP control flags."
>
> *(Abhishek runs: `python main.py` in the terminal)*
>
> "As you can see on the screen, our engine parses 210 packets in under 0.1 seconds, delivering a complete protocol distribution, top talkers matrix, and real-time throughput calculations."

---

### Phase 2: Anomaly Detection Engine (0:50 – 1:40)
**Speaker: Arun H Kalamuddi (`R25EJ013`)**

> "Thank you Abhishek. I developed the heuristic anomaly detection engine in `anomaly_detector.py`."
>
> "Our engine actively tracks stateful connection metrics to detect two of the most critical network attacks:"
> 1. "**Port Scanning Reconnaissance:** When attacker IP `10.0.0.99` probes more than 15 distinct destination ports, our state machine immediately raises a `HIGH` severity alert for network reconnaissance."
> 2. "**TCP SYN Flood (Denial of Service):** When attacker `172.16.4.88` floods the server with 40+ unacknowledged SYN packets without completing the 3-way handshake, our system detects buffer exhaustion and fires a `CRITICAL` DoS alert."
>
> "Crucially, we eliminated false positives: when legitimate servers like Google DNS or web servers reply to random client ports, our system recognizes them as server response flows and avoids false alarms."

---

### Phase 3: Live Visual Web Dashboard Walkthrough (1:40 – 2:30)
**Speaker: Rakesh N (`R25EJ042`)**

> "Now let us show you our live visual dashboard."
>
> *(Rakesh runs `python main.py --web` or points to the browser at `http://localhost:5000`)*
>
> "To give network operators clear visibility, we built this responsive glassmorphism web dashboard. It is powered by a native multithreaded Python HTTP server and Chart.js."
>
> "At a glance, examiners can observe:
> - Real-time metrics: Packet count, bandwidth, and anomaly counts.
> - A dynamic Doughnut chart displaying protocol distribution (HTTP, DNS, ICMP, TCP).
> - Top Talkers bar charts profiling highest volume IP addresses.
> - An interactive Security Alert table highlighting attack signatures with timestamps.
> - An instant-search packet inspector where we can filter frames live by typing an IP or port."
>
> "We also built scenario switching: if we select 'Reconnaissance Port Scan' from the dropdown, the dashboard instantly refreshes to isolate the Nmap scan traffic."

---

### Phase 4: Testing, Verification & Conclusion (2:30 – 3:00)
**Speaker: Sneha R (`R25EJ058`)**

> "To ensure 100% reliability, I created the synthetic PCAP generator (`generate_pcaps.py`) and our automated test suite."
>
> *(Sneha runs `python -m unittest tests/test_analyzer.py`)*
>
> "Our test suite runs 4 automated unit tests verifying header decoding, port scan thresholds, DoS detection, and protocol percentages. All tests pass in 0.12 seconds."
>
> "For future scope beyond this 12-hour build, we plan to train a Random Forest classifier on flow features (NSL-KDD dataset) to classify zero-day anomalies, and connect live Linux raw sockets with automatic `iptables` drop rules."
>
> "Thank you, and we welcome your questions!"

---

### 💡 Expected Viva / Examiner Questions & Model Answers

**Q1: Why did you not use Wireshark or Scapy?**
> **A:** Wireshark is a GUI tool, and Scapy requires WinPcap/Npcap kernel drivers which require admin privileges and third-party installations. Building our binary parser using Python's native `struct` module proves our fundamental understanding of network packet formats and enables NetGuard to run portably on any standard Python environment without external dependencies.

**Q2: How does your SYN Flood detection work?**
> **A:** During a standard TCP 3-way handshake, a SYN is followed by a SYN-ACK and an ACK. In a SYN flood attack, the attacker sends SYN packets continuously with spoofed or inactive IPs without sending the final ACK. Our detector tracks the counter of `SYN=1, ACK=0` packets per source IP; if it exceeds our threshold (40 packets), we flag a potential DoS attack.

**Q3: How do you prevent a server response from looking like a port scan?**
> **A:** When a web or DNS server responds to clients, the destination port is the client's ephemeral port (e.g., 52341, 52342), which changes for every request. If we only counted distinct destination ports, servers would look like port scanners. We inspect the source port: if the source port is a well-known service port (< 1024 such as 80, 443, 53), we recognize it as a legitimate server response flow.
