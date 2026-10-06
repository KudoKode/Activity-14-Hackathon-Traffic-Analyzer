"""
Packet Parser Module - Binary Libpcap & Layer 2-4 Protocol Decoder
Author: Abhishek Maurya (R25EJ004), Team NetGuard
Part of REVA University SEE Hackathon - Abhinava (B25CS0311)
"""

import struct
import socket
from typing import BinaryIO, Dict, Generator, Any, Optional

PCAP_GLOBAL_HEADER_MAGIC_LE = 0xd4c3b2a1
PCAP_GLOBAL_HEADER_MAGIC_BE = 0xa1b2c3d4

class Packet:
    def __init__(self, timestamp: float, orig_len: int, raw_data: bytes):
        self.timestamp = timestamp
        self.orig_len = orig_len
        self.raw_data = raw_data
        
        # Parsed attributes
        self.eth_src: Optional[str] = None
        self.eth_dst: Optional[str] = None
        self.eth_type: Optional[int] = None
        
        self.ip_src: Optional[str] = None
        self.ip_dst: Optional[str] = None
        self.ip_proto: Optional[int] = None
        self.ip_ttl: Optional[int] = None
        
        self.protocol_name: str = "OTHER"
        self.src_port: Optional[int] = None
        self.dst_port: Optional[int] = None
        self.tcp_flags: Dict[str, bool] = {}
        self.icmp_type: Optional[int] = None
        self.icmp_code: Optional[int] = None
        self.payload_len: int = 0
        
        self._decode()

    def _decode(self):
        # Decode Ethernet (14 bytes)
        if len(self.raw_data) < 14:
            return
        
        eth_hdr = self.raw_data[:14]
        dst_mac, src_mac, eth_type = struct.unpack("!6s6sH", eth_hdr)
        self.eth_src = ":".join(f"{b:02x}" for b in src_mac)
        self.eth_dst = ":".join(f"{b:02x}" for b in dst_mac)
        self.eth_type = eth_type
        
        offset = 14
        
        # IPv4
        if eth_type == 0x0800:
            if len(self.raw_data) < offset + 20:
                return
            ip_hdr = self.raw_data[offset:offset+20]
            v_ihl, tos, total_len, ident, flags_fo, ttl, proto, checksum, s_ip, d_ip = struct.unpack("!BBHHHBBH4s4s", ip_hdr)
            
            ihl = (v_ihl & 0x0F) * 4
            self.ip_src = socket.inet_ntoa(s_ip)
            self.ip_dst = socket.inet_ntoa(d_ip)
            self.ip_proto = proto
            self.ip_ttl = ttl
            
            ip_offset = offset + ihl
            
            if proto == 6:  # TCP
                self.protocol_name = "TCP"
                if len(self.raw_data) >= ip_offset + 20:
                    tcp_hdr = self.raw_data[ip_offset:ip_offset+20]
                    sp, dp, seq, ack, offset_res, flags, win, cs, urg = struct.unpack("!HHIIBBHHH", tcp_hdr)
                    self.src_port = sp
                    self.dst_port = dp
                    self.tcp_flags = {
                        "FIN": bool(flags & 0x01),
                        "SYN": bool(flags & 0x02),
                        "RST": bool(flags & 0x04),
                        "PSH": bool(flags & 0x08),
                        "ACK": bool(flags & 0x10),
                        "URG": bool(flags & 0x20),
                    }
                    tcp_header_len = ((offset_res >> 4) & 0x0F) * 4
                    self.payload_len = max(0, len(self.raw_data) - (ip_offset + tcp_header_len))
                    
                    # Detect application layer hints
                    if self.src_port == 80 or self.dst_port == 80:
                        self.protocol_name = "HTTP"
                    elif self.src_port == 443 or self.dst_port == 443:
                        self.protocol_name = "HTTPS"
                        
            elif proto == 17:  # UDP
                self.protocol_name = "UDP"
                if len(self.raw_data) >= ip_offset + 8:
                    sp, dp, ulen, cs = struct.unpack("!HHHH", self.raw_data[ip_offset:ip_offset+8])
                    self.src_port = sp
                    self.dst_port = dp
                    self.payload_len = max(0, ulen - 8)
                    if self.src_port == 53 or self.dst_port == 53:
                        self.protocol_name = "DNS"
                    elif self.src_port in (67, 68) or self.dst_port in (67, 68):
                        self.protocol_name = "DHCP"
                        
            elif proto == 1:  # ICMP
                self.protocol_name = "ICMP"
                if len(self.raw_data) >= ip_offset + 8:
                    itype, icode, cs = struct.unpack("!BBH", self.raw_data[ip_offset:ip_offset+4])
                    self.icmp_type = itype
                    self.icmp_code = icode
                    self.payload_len = max(0, len(self.raw_data) - (ip_offset + 8))
            else:
                self.protocol_name = f"IP-Proto-{proto}"
                
        elif eth_type == 0x0806:  # ARP
            self.protocol_name = "ARP"
        elif eth_type == 0x86DD:  # IPv6
            self.protocol_name = "IPv6"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": round(self.timestamp, 4),
            "orig_len": self.orig_len,
            "eth_src": self.eth_src,
            "eth_dst": self.eth_dst,
            "ip_src": self.ip_src,
            "ip_dst": self.ip_dst,
            "protocol": self.protocol_name,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "tcp_flags": [k for k, v in self.tcp_flags.items() if v],
            "payload_len": self.payload_len,
        }

class PcapReader:
    """Reads standard libpcap binary files without third-party dependencies."""
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.file: Optional[BinaryIO] = None
        self.endianness = "<"  # Default little endian

    def __enter__(self):
        self.file = open(self.filepath, "rb")
        self._read_global_header()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.file:
            self.file.close()

    def _read_global_header(self):
        ghdr = self.file.read(24)
        if len(ghdr) < 24:
            raise ValueError(f"Invalid PCAP file: header too short ({len(ghdr)} bytes)")
        
        magic = struct.unpack("<I", ghdr[:4])[0]
        if magic == PCAP_GLOBAL_HEADER_MAGIC_LE:
            self.endianness = "<"
        elif magic == PCAP_GLOBAL_HEADER_MAGIC_BE:
            self.endianness = ">"
        else:
            # Check big-endian unpack
            magic_be = struct.unpack(">I", ghdr[:4])[0]
            if magic_be == PCAP_GLOBAL_HEADER_MAGIC_BE:
                self.endianness = ">"
            elif magic_be == PCAP_GLOBAL_HEADER_MAGIC_LE:
                self.endianness = "<"
            else:
                raise ValueError(f"Unsupported PCAP magic number: 0x{magic:08x}")

    def packets(self) -> Generator[Packet, None, None]:
        while True:
            phdr = self.file.read(16)
            if len(phdr) < 16:
                break
            
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{self.endianness}IIII", phdr)
            raw_pkt = self.file.read(incl_len)
            if len(raw_pkt) < incl_len:
                break
                
            timestamp = ts_sec + (ts_usec / 1_000_000.0)
            yield Packet(timestamp, orig_len, raw_pkt)
