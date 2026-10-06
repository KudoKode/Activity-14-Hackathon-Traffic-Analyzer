"""
Synthetic PCAP Generator for Testing & Judges Demonstration
Author: Sneha R (R25EJ058) & Abhishek Maurya (R25EJ004), Team NetGuard
Generates valid libpcap binary files without needing root privileges or Wireshark.
"""

import os
import struct
import socket
import random
import time

def create_pcap_file(filepath: str, packets_data: list):
    """Writes a standard libpcap file (Ethernet DLT=1)."""
    with open(filepath, "wb") as f:
        # PCAP Global Header (24 bytes)
        # magic(4B), ver_maj(2B), ver_min(2B), tz(4B), sig(4B), snaplen(4B), network(4B)
        magic = 0xa1b2c3d4 # big-endian magic or 0xd4c3b2a1 for little-endian
        # We use little-endian standard
        f.write(struct.pack("<IHHiIII", 0xd4c3b2a1, 2, 4, 0, 0, 65535, 1))
        
        for ts, raw_pkt in packets_data:
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)
            pkt_len = len(raw_pkt)
            # Packet header (16 bytes): ts_sec, ts_usec, incl_len, orig_len
            f.write(struct.pack("<IIII", ts_sec, ts_usec, pkt_len, pkt_len))
            f.write(raw_pkt)

def make_ethernet(src_mac="00:11:22:33:44:55", dst_mac="aa:bb:cc:dd:ee:ff", eth_type=0x0800):
    src_b = bytes.fromhex(src_mac.replace(":", ""))
    dst_b = bytes.fromhex(dst_mac.replace(":", ""))
    return struct.pack("!6s6sH", dst_b, src_b, eth_type)

def make_ipv4(src_ip, dst_ip, proto, payload, ttl=64):
    v_ihl = (4 << 4) | 5 # Version 4, IHL 5 (20 bytes)
    tos = 0
    total_len = 20 + len(payload)
    ident = random.randint(1000, 65000)
    flags_fo = 2 << 13 # Don't fragment
    s_ip = socket.inet_aton(src_ip)
    d_ip = socket.inet_aton(dst_ip)
    
    # Checksum 0 initially
    hdr_no_cs = struct.pack("!BBHHHBBH4s4s", v_ihl, tos, total_len, ident, flags_fo, ttl, proto, 0, s_ip, d_ip)
    # Simple internet checksum
    cs = calculate_checksum(hdr_no_cs)
    hdr = struct.pack("!BBHHHBBH4s4s", v_ihl, tos, total_len, ident, flags_fo, ttl, proto, cs, s_ip, d_ip)
    return hdr + payload

def make_tcp(src_port, dst_port, seq, ack, flags_dict, payload=b""):
    offset_res = (5 << 4) # 5 words = 20 bytes
    flags = 0
    if flags_dict.get("FIN"): flags |= 0x01
    if flags_dict.get("SYN"): flags |= 0x02
    if flags_dict.get("RST"): flags |= 0x04
    if flags_dict.get("PSH"): flags |= 0x08
    if flags_dict.get("ACK"): flags |= 0x10
    if flags_dict.get("URG"): flags |= 0x20
    
    win = 64240
    urg = 0
    hdr = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, offset_res, flags, win, 0, urg)
    return hdr + payload

def make_udp(src_port, dst_port, payload=b""):
    length = 8 + len(payload)
    return struct.pack("!HHHH", src_port, dst_port, length, 0) + payload

def make_icmp_echo(seq, req=True):
    itype = 8 if req else 0
    icode = 0
    payload = b"REVA_HACKATHON_ABHINAVA_PING_DATA"
    return struct.pack("!BBHHH", itype, icode, 0, 1337, seq) + payload

def calculate_checksum(data):
    if len(data) % 2 != 0:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff

def generate_all():
    base_dir = os.path.join(os.path.dirname(__file__), "data")
    os.makedirs(base_dir, exist_ok=True)
    t0 = 1728270000.0 # Fixed baseline timestamp
    
    # 1. NORMAL CAMPUS TRAFFIC PCAP
    print("[*] Generating normal_traffic.pcap...")
    normal_pkts = []
    t = t0
    # Simulate DNS requests & replies
    for i in range(15):
        t += 0.05
        # DNS query
        dns_query = make_udp(random.randint(40000, 60000), 53, b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01")
        ip = make_ipv4("192.168.1.105", "8.8.8.8", 17, dns_query)
        eth = make_ethernet()
        normal_pkts.append((t, eth + ip))
        
        # DNS reply
        t += 0.02
        dns_reply = make_udp(53, random.randint(40000, 60000), b"\x01\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x8e\xfa\xbe\x2e")
        ip2 = make_ipv4("8.8.8.8", "192.168.1.105", 17, dns_reply)
        normal_pkts.append((t, eth + ip2))

    # Simulate HTTP Web Traffic
    for i in range(25):
        t += 0.03
        sp = random.randint(35000, 55000)
        # TCP SYN
        tcp = make_tcp(sp, 80, 1000 + i, 0, {"SYN": True})
        normal_pkts.append((t, make_ethernet() + make_ipv4("192.168.1.120", "93.184.216.34", 6, tcp)))
        # TCP SYN-ACK
        t += 0.01
        tcp_sa = make_tcp(80, sp, 5000 + i, 1001 + i, {"SYN": True, "ACK": True})
        normal_pkts.append((t, make_ethernet() + make_ipv4("93.184.216.34", "192.168.1.120", 6, tcp_sa)))
        # HTTP GET
        t += 0.01
        http_data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        tcp_req = make_tcp(sp, 80, 1001 + i, 5001 + i, {"ACK": True, "PSH": True}, http_data)
        normal_pkts.append((t, make_ethernet() + make_ipv4("192.168.1.120", "93.184.216.34", 6, tcp_req)))

    # Simulate ICMP Pings
    for i in range(10):
        t += 0.1
        icmp_req = make_icmp_echo(i, req=True)
        normal_pkts.append((t, make_ethernet() + make_ipv4("192.168.1.15", "192.168.1.1", 1, icmp_req)))
        t += 0.01
        icmp_rep = make_icmp_echo(i, req=False)
        normal_pkts.append((t, make_ethernet() + make_ipv4("192.168.1.1", "192.168.1.15", 1, icmp_rep)))

    create_pcap_file(os.path.join(base_dir, "sample_normal.pcap"), normal_pkts)

    # 2. PORT SCAN ATTACK PCAP
    print("[*] Generating sample_port_scan.pcap...")
    scan_pkts = list(normal_pkts[:20]) # Include some background traffic
    scanner_ip = "10.0.0.99"
    target_ip = "192.168.1.50"
    ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 4444, 5432, 8080, 8443, 31337]
    for port in ports_to_scan:
        t += 0.005
        # Reconnaissance SYN scan
        tcp_scan = make_tcp(random.randint(50000, 60000), port, random.randint(10000, 99999), 0, {"SYN": True})
        scan_pkts.append((t, make_ethernet() + make_ipv4(scanner_ip, target_ip, 6, tcp_scan)))
    create_pcap_file(os.path.join(base_dir, "sample_port_scan.pcap"), scan_pkts)

    # 3. SYN FLOOD DoS ATTACK PCAP
    print("[*] Generating sample_syn_flood.pcap...")
    flood_pkts = list(normal_pkts[:15])
    attacker_ip = "172.16.4.88"
    victim_ip = "192.168.1.200"
    for i in range(65):
        t += 0.001
        tcp_flood = make_tcp(random.randint(1024, 65535), 80, random.randint(100000, 999999), 0, {"SYN": True})
        flood_pkts.append((t, make_ethernet() + make_ipv4(attacker_ip, victim_ip, 6, tcp_flood)))
    create_pcap_file(os.path.join(base_dir, "sample_syn_flood.pcap"), flood_pkts)

    # 4. MIXED ENTERPRISE COMBINED PCAP
    print("[*] Generating mixed_campus_traffic.pcap...")
    mixed = normal_pkts + scan_pkts[20:] + flood_pkts[15:]
    mixed.sort(key=lambda x: x[0])
    create_pcap_file(os.path.join(base_dir, "mixed_campus_traffic.pcap"), mixed)

    print(f"[+] All PCAP captures generated successfully in: {base_dir}")

if __name__ == "__main__":
    generate_all()
