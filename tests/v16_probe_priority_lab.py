#!/usr/bin/env python3
"""Regression for scheme fallback, multi-port probing, and body-bound APIs beyond top80."""

import json, socket, subprocess, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "pipeline" / "deep_scanner.py"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def first_free_port(candidates):
    for port in candidates:
        s = socket.socket()
        try:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
        finally:
            s.close()
    return free_port()


class ReusableServer(ThreadingHTTPServer):
    allow_reuse_address = True

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}"


class DefaultHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        data = b"<html>default landing</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class AppHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def send_json(self, obj, status=200):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_text(self, text, content_type="text/html"):
        data = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def read_json(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        try:
            return json.loads(raw.decode() or "{}")
        except Exception:
            return {}

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            return self.send_text('<script src="/app.js"></script>')
        if parsed.path == "/app.js":
            noise = "\n".join(f'fetch("/api/noise/{i}");' for i in range(120))
            js = noise + '\nservice.post("/api/zzzz/body-only/search", {deptId: deptId, pageNum: 1, pageSize: 10});'
            return self.send_text(js, "application/javascript")
        if parsed.path == "/api/server/system/configInfo":
            return self.send_json({"code": 0, "data": {"system": "real-app", "phone": "13800001234"}})
        return self.send_json({"code": 404}, status=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        data = self.read_json()
        if parsed.path == "/api/zzzz/body-only/search" and data.get("deptId") and data.get("pageNum"):
            return self.send_json({"code": 0, "data": [{"userId": 1, "phone": "13800009999"}]})
        return self.send_json({"code": 404}, status=404)


def start(port, handler):
    server = ReusableServer(("127.0.0.1", port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def flatten(report):
    return [fi for host in report.get("findings", []) for fi in host.get("findings", [])]


def run_scan(targets):
    with tempfile.TemporaryDirectory() as tmp:
        target_file = Path(tmp) / "targets.json"
        outdir = Path(tmp) / "out"
        target_file.write_text(json.dumps(targets), encoding="utf-8")
        proc = subprocess.run(
            [
                sys.executable,
                str(SCANNER),
                "--input",
                str(target_file),
                "--outdir",
                str(outdir),
                "--workers",
                "8",
                "--timeout",
                "3",
                "--no-proxy",
                "--full-bypass",
                "--file-max-probes",
                "4",
                "--param-max-probes",
                "8",
            ],
            text=True,
            capture_output=True,
            timeout=120,
        )
        if proc.returncode != 0:
            print(proc.stdout)
            print(proc.stderr)
            raise SystemExit(proc.returncode)
        return json.loads((outdir / "report.json").read_text(encoding="utf-8"))


def main():
    port_8443 = first_free_port([8443])
    check_https_like_fallback = port_8443 == 8443
    default_port = first_free_port([8001, 8080, 8088])
    app_port = first_free_port([8089, 10000, 10080])
    if app_port == default_port:
        app_port = first_free_port([10000, 10080, 8088])
    servers = [
        start(port_8443, AppHandler),
        start(default_port, DefaultHandler),
        start(app_port, AppHandler),
    ]
    try:
        report = run_scan([
            {"url": f"127.0.0.1:{port_8443}", "title": "http-on-https-port", "score": 100},
            {"url": "127.0.0.1", "title": "multi-port", "score": 100},
        ])
        findings = flatten(report)
        urls = [fi.get("url", "") for fi in findings]
        if check_https_like_fallback:
            assert any(u.startswith(f"http://127.0.0.1:{port_8443}/") for u in urls), "HTTP fallback on HTTPS-like port failed"
        assert any(f"http://127.0.0.1:{app_port}/api/server/system/configInfo" in u for u in urls), "multi-port probing missed app port"
        assert any(urlparse(u).path == "/api/zzzz/body-only/search" for u in urls), "body-bound API beyond top80 missed"
        print("PROBE PRIORITY LAB PASS")
        print(f"vulnerable={report.get('vulnerable')} findings={len(findings)}")
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
