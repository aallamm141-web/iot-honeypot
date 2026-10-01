#!/usr/bin/env python3
"""Simple proxy server for SOC Dashboard — bypasses CORS/Mixed Content

SECURITY: Binds to localhost only by default. This proxy injects Elasticsearch
credentials into every forwarded request, so exposing it on 0.0.0.0 would let
anyone who can reach the port query Elasticsearch without authentication.
To reach the dashboard from another machine, use an SSH tunnel:
    ssh -L 8080:localhost:8080 <user>@<honeypot-ip>
"""
import os
import sys
import http.server
import urllib.request
import ssl
import base64
import logging
from dotenv import load_dotenv

load_dotenv()

# ==============================================================================
# CONFIG
# ==============================================================================

PROJECT_ROOT = os.getenv("PROJECT_ROOT")

ES_URL  = os.getenv("ELASTIC_HOST", "https://localhost:9200")
ES_USER = os.getenv("ELASTIC_USER", "elastic")
ES_PASS = os.getenv("ELASTIC_PASSWORD")

missing = []
if not PROJECT_ROOT: missing.append("PROJECT_ROOT")
if not ES_PASS: missing.append("ELASTIC_PASSWORD")
if missing:
    print(f"[FATAL ERROR] Missing required environment variables: {', '.join(missing)}", file=sys.stderr)
    print("[FATAL ERROR] Ensure your .env file is populated correctly.", file=sys.stderr)
    sys.exit(1)

AUTH = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()

PORT     = int(os.getenv("SOC_PROXY_PORT", 8080))
BIND     = os.getenv("SOC_PROXY_BIND", "127.0.0.1")
WEB_DIR  = PROJECT_ROOT
LOG_FILE = os.path.join(PROJECT_ROOT, "logs_and_reports/soc_proxy.log")

# Restrict CORS to the proxy's own origin instead of allowing any site
ALLOWED_ORIGIN = os.getenv("SOC_PROXY_ORIGIN", f"http://{BIND}:{PORT}")

# Disable SSL verification for local self-signed certs
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

os.makedirs(os.path.dirname(os.path.abspath(LOG_FILE)), exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=WEB_DIR, **kw)

    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def do_GET(self):
        if self.path == "/api/health":
            self.proxy_get("/_cluster/health")
        else:
            super().do_GET()

    def do_POST(self):
        if self.path.startswith("/api/"):
            es_path = self.path[4:]
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
            self.proxy_post(es_path, body)
        else:
            self.send_json_error(404, "Endpoint not found")

    def proxy_get(self, path):
        req = urllib.request.Request(ES_URL + path, headers={"Authorization": "Basic " + AUTH})
        self._execute_request(req)

    def proxy_post(self, path, body):
        req = urllib.request.Request(
            ES_URL + path,
            data=body,
            headers={"Authorization": "Basic " + AUTH, "Content-Type": "application/json"}
        )
        self._execute_request(req)

    def _execute_request(self, req):
        try:
            with urllib.request.urlopen(req, context=ctx) as r:
                data = r.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(data)
        except urllib.error.HTTPError as e:
            # Pass along Elasticsearch HTTP error codes and body back to the frontend dashboard
            error_data = e.read()
            self.send_response(e.code)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(error_data)
        except Exception as e:
            logging.error(f"Proxy request failed: {e}")
            self.send_json_error(500, "Internal proxy error")

    def send_json_error(self, status, message):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps({"error": message}).encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def log_message(self, fmt, *args):
        pass

if __name__ == "__main__":
    print(f"[*] SOC Dashboard: http://{BIND}:{PORT}/soc_dashboard.html")
    if BIND == "0.0.0.0":
        print("[!] WARNING: Proxy is bound to 0.0.0.0 — Elasticsearch is reachable")
        print("[!]          by anyone who can reach this port, with no authentication.")
    http.server.HTTPServer((BIND, PORT), Handler).serve_forever()
