"""
Traffic Analyzer Core Engine
Author: Abhishek Maurya (R25EJ004), Team NetGuard
REVA University SEE Hackathon - Abhinava (B25CS0311)
"""

import time
from collections import Counter, defaultdict
from typing import Dict, Any, List, Optional
from .packet_parser import PcapReader, Packet
from .anomaly_detector import AnomalyDetector

class TrafficAnalyzer:
    def __init__(self, port_scan_threshold: int = 15, syn_flood_threshold: int = 40):
        self.anomaly_detector = AnomalyDetector(port_scan_threshold, syn_flood_threshold)
        
        self.total_packets = 0
        self.total_bytes = 0
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        
        self.protocol_counts = Counter()
        self.protocol_bytes = Counter()
        
        self.src_ip_counts = Counter()
        self.src_ip_bytes = Counter()
        
        self.dst_ip_counts = Counter()
        self.dst_ip_bytes = Counter()
        
        self.dst_port_counts = Counter()
        self.conversations = Counter()  # (src_ip, dst_ip) -> count
        
        self.packet_size_buckets = {
            "< 64 B": 0,
            "64 - 512 B": 0,
            "513 - 1024 B": 0,
            "> 1024 B": 0
        }
        
        self.recent_packets: List[Dict[str, Any]] = []

    def process_packet(self, packet: Packet):
        self.total_packets += 1
        self.total_bytes += packet.orig_len
        
        if self.start_time is None or packet.timestamp < self.start_time:
            self.start_time = packet.timestamp
        if self.end_time is None or packet.timestamp > self.end_time:
            self.end_time = packet.timestamp

        # Protocol statistics
        proto = packet.protocol_name
        self.protocol_counts[proto] += 1
        self.protocol_bytes[proto] += packet.orig_len

        # IP Top Talkers
        if packet.ip_src:
            self.src_ip_counts[packet.ip_src] += 1
            self.src_ip_bytes[packet.ip_src] += packet.orig_len
        if packet.ip_dst:
            self.dst_ip_counts[packet.ip_dst] += 1
            self.dst_ip_bytes[packet.ip_dst] += packet.orig_len
            
        if packet.ip_src and packet.ip_dst:
            self.conversations[f"{packet.ip_src} -> {packet.ip_dst}"] += 1

        # Ports
        if packet.dst_port:
            self.dst_port_counts[packet.dst_port] += 1

        # Packet sizes
        if packet.orig_len < 64:
            self.packet_size_buckets["< 64 B"] += 1
        elif packet.orig_len <= 512:
            self.packet_size_buckets["64 - 512 B"] += 1
        elif packet.orig_len <= 1024:
            self.packet_size_buckets["513 - 1024 B"] += 1
        else:
            self.packet_size_buckets["> 1024 B"] += 1

        # Anomaly Detection Hook
        self.anomaly_detector.process_packet(packet)

        # Retain recent packets for live inspection
        if len(self.recent_packets) < 100:
            self.recent_packets.append(packet.to_dict())

    def analyze_pcap(self, pcap_path: str) -> Dict[str, Any]:
        with PcapReader(pcap_path) as reader:
            for packet in reader.packets():
                self.process_packet(packet)
        return self.get_report()

    def get_report(self) -> Dict[str, Any]:
        duration = max(0.001, (self.end_time or 0) - (self.start_time or 0)) if self.start_time and self.end_time else 0.0
        pps = round(self.total_packets / duration, 2) if duration > 0 else 0
        kbps = round((self.total_bytes * 8) / (duration * 1000), 2) if duration > 0 else 0

        # Protocol Distribution %
        proto_dist = []
        for proto, count in self.protocol_counts.most_common():
            pct = round((count / max(1, self.total_packets)) * 100, 2)
            b_count = self.protocol_bytes[proto]
            proto_dist.append({
                "protocol": proto,
                "packet_count": count,
                "percentage": pct,
                "bytes": b_count
            })

        # Top 5 Source IPs
        top_src = [
            {"ip": ip, "packets": count, "bytes": self.src_ip_bytes[ip]}
            for ip, count in self.src_ip_counts.most_common(5)
        ]

        # Top 5 Destination IPs
        top_dst = [
            {"ip": ip, "packets": count, "bytes": self.dst_ip_bytes[ip]}
            for ip, count in self.dst_ip_counts.most_common(5)
        ]

        # Top 5 Conversations
        top_conv = [
            {"flow": flow, "count": count}
            for flow, count in self.conversations.most_common(5)
        ]

        # Top Ports
        top_ports = [
            {"port": port, "count": count}
            for port, count in self.dst_port_counts.most_common(5)
        ]

        anomaly_summary = self.anomaly_detector.get_summary()

        return {
            "summary": {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "duration_seconds": round(duration, 3),
                "packets_per_second": pps,
                "throughput_kbps": kbps,
            },
            "protocol_distribution": proto_dist,
            "top_source_ips": top_src,
            "top_destination_ips": top_dst,
            "top_conversations": top_conv,
            "top_ports": top_ports,
            "packet_size_buckets": self.packet_size_buckets,
            "security_alerts": anomaly_summary["alerts"],
            "total_alerts": anomaly_summary["total_alerts"],
            "recent_packets": self.recent_packets[-30:] # Last 30 packets for sample view
        }

    def print_cli_summary(self):
        report = self.get_report()
        s = report["summary"]
        print("=" * 68)
        print("   [*] REVA UNIVERSITY - NETWORK TRAFFIC ANALYZER REPORT")
        print("   SEE Hackathon Abhinava | Team NetGuard (Topic 7)")
        print("=" * 68)
        print(f"Total Packets Captured: {s['total_packets']:,}")
        print(f"Total Traffic Volume:   {s['total_bytes']:,} Bytes ({s['total_bytes']/1024:.2f} KB)")
        print(f"Capture Duration:       {s['duration_seconds']}s")
        print(f"Packet Rate:            {s['packets_per_second']} pkts/sec")
        print(f"Throughput:             {s['throughput_kbps']} Kbps")
        print("-" * 68)
        
        print("\n[+] PROTOCOL BREAKDOWN:")
        print(f"{'Protocol':<12} | {'Packets':<10} | {'Bytes':<12} | {'Share (%)':<10}")
        print("-" * 52)
        for p in report["protocol_distribution"]:
            print(f"{p['protocol']:<12} | {p['packet_count']:<10} | {p['bytes']:<12} | {p['percentage']:<10.1f}%")
            
        print("\n[+] TOP TALKERS (Source IPs):")
        print(f"{'Source IP':<20} | {'Packets':<10} | {'Volume (Bytes)':<15}")
        print("-" * 52)
        for src in report["top_source_ips"]:
            print(f"{src['ip']:<20} | {src['packets']:<10} | {src['bytes']:<15}")

        print("\n[!] SECURITY & ANOMALY ALERTS:")
        alerts = report["security_alerts"]
        if not alerts:
            print("  [OK] No malicious anomalies or port scans detected.")
        else:
            for i, a in enumerate(alerts, 1):
                print(f"  [{i}] [{a['severity']}] {a['type']} from {a['src_ip']}")
                print(f"      -> {a['description']}")
        print("=" * 68)
