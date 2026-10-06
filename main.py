"""
NetGuard: Network Traffic Analyzer & Intrusion Detection System
Main Entry Point
REVA University SEE Hackathon - Abhinava (B25CS0311 Topic 7)
"""

import sys
import os
import argparse
import webbrowser
from src.traffic_analyzer import TrafficAnalyzer
from src.web_server import run_server
from generate_pcaps import generate_all

def main():
    parser = argparse.ArgumentParser(
        description="NetGuard: Network Traffic Analyzer & Intrusion Detection (REVA SEE Hackathon 2026)"
    )
    parser.add_argument("--web", "-w", action="store_true", help="Launch interactive Web Dashboard")
    parser.add_argument("--port", "-p", type=int, default=5000, help="Web server port (default: 5000)")
    parser.add_argument("--file", "-f", type=str, default="data/mixed_campus_traffic.pcap", help="PCAP capture file to analyze")
    parser.add_argument("--gen", "-g", action="store_true", help="Regenerate all synthetic sample PCAP captures")
    parser.add_argument("--slides", "-s", action="store_true", help="Open Hackathon 5-Slide Presentation in browser")
    
    args = parser.parse_args()

    # If --gen requested
    if args.gen:
        generate_all()
        return

    # If --slides requested
    if args.slides:
        slides_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "slides", "index.html"))
        print(f"[*] Opening Hackathon Presentation Slides: {slides_path}")
        webbrowser.open(f"file:///{slides_path.replace(os.sep, '/')}")
        return

    # If --web requested
    if args.web:
        # Check if sample pcaps exist; if not, generate them
        if not os.path.exists(os.path.join(os.path.dirname(__file__), "data", "mixed_campus_traffic.pcap")):
            print("[*] Generating baseline sample PCAP files first...")
            generate_all()
            
        print(f"[*] Launching NetGuard Web Dashboard on http://localhost:{args.port}...")
        webbrowser.open(f"http://localhost:{args.port}")
        run_server(args.port)
        return

    # Default: CLI mode
    pcap_target = args.file
    if not os.path.isabs(pcap_target):
        pcap_target = os.path.join(os.path.dirname(__file__), pcap_target)

    if not os.path.exists(pcap_target):
        print(f"[!] File not found: {pcap_target}")
        print("[*] Generating sample PCAPs now...")
        generate_all()
        pcap_target = os.path.join(os.path.dirname(__file__), "data", "mixed_campus_traffic.pcap")

    print(f"[*] Analyzing capture file: {pcap_target} ...\n")
    analyzer = TrafficAnalyzer()
    analyzer.analyze_pcap(pcap_target)
    analyzer.print_cli_summary()
    print("\n[TIP] Run 'python main.py --web' to explore the live visual web dashboard!")
    print("[TIP] Run 'python main.py --slides' to launch the 5-slide hackathon presentation deck!\n")

if __name__ == "__main__":
    main()
