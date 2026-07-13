#!/usr/bin/env python3
"""Regression: 0 means unlimited for param/body probe caps."""

import json
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "pipeline" / "deep_scanner.py"


class LabServer(ThreadingHTTPServer):
    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}"


class Handler(BaseHTTPRequestHandler):
    query_hits = []
    body_hits = []

    def log_message(self, fmt, *args):
        return

    def send_body(self, body, content_type="text/html", status=200):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/":
            return self.send_body(
                '<script src="/app.js"></script>'
                '<form><input name="alpha"><input name="beta"><input name="gamma"><input name="delta"></form>'
            )
        if self.path == "/app.js":
            return self.send_body(
                'axios.get("/api/query/list", {params: {alpha: 1, beta: 2, gamma: 3, delta: 4, epsilon: 5}});\n'
                'axios.post("/api/body/save", {alpha: 1, beta: 2, gamma: 3, delta: 4, epsilon: 5});\n',
                "application/javascript",
            )
        if self.path.startswith("/api/query/list"):
            Handler.query_hits.append(self.path)
            return self.send_body(json.dumps({"code": 200, "result": []}), "application/json")
        return self.send_body("not found", "text/plain", 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length).decode(errors="ignore")
        if self.path.startswith("/api/body/save"):
            Handler.body_hits.append(body)
            return self.send_body(json.dumps({"code": 200, "result": []}), "application/json")
        return self.send_body("not found", "text/plain", 404)


def run_scan(server_url, *, param_max_probes, allow_active_post=True):
    Handler.query_hits = []
    Handler.body_hits = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        target_file = tmp / "targets.json"
        outdir = tmp / "out"
        target_file.write_text(json.dumps([{"url": server_url, "title": "zero-unlimited-lab", "score": 100}]), encoding="utf-8")
        cmd = [
            sys.executable,
            str(SCANNER),
            "--input",
            str(target_file),
            "--outdir",
            str(outdir),
            "--workers",
            "4",
            "--timeout",
            "3",
            "--phase3a-timeout",
            "40",
            "--phase3b-layer-timeout",
            "40",
            "--no-proxy",
            "--full-bypass",
            "--param-probe-mode",
            "broad",
            "--phase3a-param-rescue",
            "--phase3a-param-rescue-max-apis",
            "0",
            "--phase3a-body-max-apis",
            "0",
            "--param-max-probes",
            str(param_max_probes),
        ]
        if allow_active_post:
            cmd.append("--allow-active-post")
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=120)
        if proc.returncode != 0:
            print(proc.stdout)
            print(proc.stderr)
            raise SystemExit(proc.returncode)
    return list(Handler.query_hits), list(Handler.body_hits)


def main():
    server = LabServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        _blocked_query_hits, blocked_body_hits = run_scan(server.url, param_max_probes=2, allow_active_post=False)
        assert blocked_body_hits == [], blocked_body_hits

        limited_query_hits, limited_body_hits = run_scan(server.url, param_max_probes=2)
        unlimited_query_hits, unlimited_body_hits = run_scan(server.url, param_max_probes=0)

        assert len(limited_query_hits) >= 1, limited_query_hits
        assert len(limited_body_hits) >= 1, limited_body_hits
        assert len(unlimited_query_hits) > len(limited_query_hits), (limited_query_hits, unlimited_query_hits)
        assert len(unlimited_body_hits) > len(limited_body_hits), (limited_body_hits, unlimited_body_hits)
        print("PARAM ZERO UNLIMITED LAB PASS")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
