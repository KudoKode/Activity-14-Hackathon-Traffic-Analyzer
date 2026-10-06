"""
Anomaly and Attack Traffic Detector Module
Author: Arun H Kalamuddi (R25EJ013) & Abhishek Maurya (R25EJ004), Team NetGuard
Detects Port Scans, DoS/SYN Floods, Abnormal Request Rates, and Malicious Traffic
"""

from collections import defaultdict
from typing import List, Dict, Any
from .packet_parser import Packet

class SecurityAlert:
    def __init__(self, alert_type: str, severity: str, src_ip: str, description: str, timestamp: float, metadata: Dict[str, Any] = None):
        self.alert_type = alert_type
        self.severity = severity  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
        self.src_ip = src_ip
        self.description = description
        self.timestamp = timestamp
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.alert_type,
            "severity": self.severity,
            "src_ip": self.src_ip,
            "description": self.description,
            "timestamp": round(self.timestamp, 4),
            "metadata": self.metadata
        }

class AnomalyDetector:
    def __init__(self, port_scan_threshold: int = 15, syn_flood_threshold: int = 40):
        self.port_scan_threshold = port_scan_threshold
        self.syn_flood_threshold = syn_flood_threshold
        
        # State trackers
        self.ip_dst_ports = defaultdict(set)       # src_ip -> set of dst_ports
        self.ip_syn_count = defaultdict(int)       # src_ip -> count of SYN packets
        self.ip_packet_count = defaultdict(int)    # src_ip -> total packets
        self.ip_dst_hosts = defaultdict(set)       # src_ip -> set of dst_ips
        
        self.alerts: List[SecurityAlert] = []
        self._alerted_scanners = set()
        self._alerted_flood = set()

    def process_packet(self, packet: Packet):
        if not packet.ip_src:
            return
            
        src = packet.ip_src
        dst = packet.ip_dst
        self.ip_packet_count[src] += 1
        
        # Ignore legitimate server responses where server is source port (e.g. 53, 80, 443)
        # Servers return traffic to ephemeral ports of clients; that is not an outbound port scan
        is_server_reply = packet.src_port and packet.src_port in (80, 443, 53, 21, 22, 25, 110, 143)

        if packet.dst_port and not is_server_reply:
            self.ip_dst_ports[src].add(packet.dst_port)
            self.ip_dst_hosts[src].add(dst)
            
            # 1. Port Scan Detection (Horizontal or Vertical Scan)
            ports_contacted = len(self.ip_dst_ports[src])
            if ports_contacted >= self.port_scan_threshold and src not in self._alerted_scanners:
                self._alerted_scanners.add(src)
                self.alerts.append(SecurityAlert(
                    alert_type="PORT_SCAN",
                    severity="HIGH",
                    src_ip=src,
                    description=f"Host {src} probed {ports_contacted} distinct destination ports (Threshold: {self.port_scan_threshold}). Suspicious reconnaissance detected.",
                    timestamp=packet.timestamp,
                    metadata={"unique_ports_scanned": ports_contacted, "target_ip": dst}
                ))

            # 2. Suspicious Backdoor / Malware Ports
            KNOWN_MALICIOUS_PORTS = {
                4444: "Metasploit Default Listener",
                31337: "Back Orifice Trojan",
                1337: "Elite Backdoor / Hacktool",
                6667: "IRC Botnet C2 Channel",
                23: "Telnet Brute Force"
            }
            if packet.dst_port in KNOWN_MALICIOUS_PORTS:
                self.alerts.append(SecurityAlert(
                    alert_type="SUSPICIOUS_PORT_ACCESS",
                    severity="MEDIUM",
                    src_ip=src,
                    description=f"Traffic from {src} directed to high-risk port {packet.dst_port} ({KNOWN_MALICIOUS_PORTS[packet.dst_port]}).",
                    timestamp=packet.timestamp,
                    metadata={"dst_port": packet.dst_port, "target_ip": dst}
                ))

        # 3. TCP SYN Flood (DoS Attack Detection)
        if packet.protocol_name in ("TCP", "HTTP", "HTTPS") and packet.tcp_flags.get("SYN") and not packet.tcp_flags.get("ACK"):
            self.ip_syn_count[src] += 1
            if self.ip_syn_count[src] >= self.syn_flood_threshold and src not in self._alerted_flood:
                self._alerted_flood.add(src)
                self.alerts.append(SecurityAlert(
                    alert_type="SYN_FLOOD_DOS",
                    severity="CRITICAL",
                    src_ip=src,
                    description=f"Host {src} generated {self.ip_syn_count[src]} unacknowledged SYN packets. Potential Denial-of-Service (DoS) in progress.",
                    timestamp=packet.timestamp,
                    metadata={"syn_count": self.ip_syn_count[src]}
                ))

        # 4. ICMP Flood Detection
        if packet.protocol_name == "ICMP" and packet.icmp_type == 8: # Echo Request
            if self.ip_packet_count[src] > 50 and (self.ip_packet_count[src] % 50 == 0):
                self.alerts.append(SecurityAlert(
                    alert_type="ICMP_FLOOD",
                    severity="HIGH",
                    src_ip=src,
                    description=f"High rate of ICMP Echo Requests from {src} ({self.ip_packet_count[src]} packets).",
                    timestamp=packet.timestamp,
                    metadata={"icmp_packets": self.ip_packet_count[src]}
                ))

    def get_summary(self) -> Dict[str, Any]:
        return {
            "total_alerts": len(self.alerts),
            "alerts": [a.to_dict() for a in self.alerts],
            "scanners_detected": list(self._alerted_scanners),
            "dos_sources": list(self._alerted_flood),
        }
