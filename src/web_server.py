"""
Lightweight Web Server & REST API for Live Dashboard
Author: Rakesh N (R25EJ042) & Abhishek Maurya (R25EJ004), Team NetGuard
Uses standard library http.server (Zero external dependencies required).
"""

import os
import json
import urllib.parse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from .traffic_analyzer import TrafficAnalyzer

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_DIR = os.path.join(PROJECT_ROOT, "web")
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

class DashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/api/files":
            self._handle_get_files()
        elif path == "/api/analyze":
            filename = query.get("file", ["mixed_campus_traffic.pcap"])[0]
            self._handle_analyze(filename)
        elif path == "/" or not os.path.exists(os.path.join(WEB_DIR, path.lstrip("/"))):
            # Serve index.html
            self.path = "/index.html"
            return super().do_GET()
        else:
            return super().do_GET()

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _handle_get_files(self):
        pcaps = [f for f in os.listdir(DATA_DIR) if f.endswith(".pcap")]
        self._send_json({"files": pcaps})

    def _handle_analyze(self, filename: str):
        # Prevent directory traversal
        safe_name = os.path.basename(filename)
        pcap_path = os.path.join(DATA_DIR, safe_name)
        if not os.path.exists(pcap_path):
            self._send_json({"error": f"File '{safe_name}' not found"}, status=404)
            return

        analyzer = TrafficAnalyzer()
        report = analyzer.analyze_pcap(pcap_path)
        report["active_file"] = safe_name
        self._send_json(report)

def run_server(port=5000):
    server = ThreadingHTTPServer(("127.0.0.1", port), DashboardHandler)
    print("=" * 65)
    print(f"[*] NetGuard Web Dashboard live at: http://localhost:{port}")
    print("    Press Ctrl+C to stop the server.")
    print("=" * 65)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server.")
        server.server_close()

if __name__ == "__main__":
    run_server()
