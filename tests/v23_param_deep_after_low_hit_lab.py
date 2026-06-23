#!/usr/bin/env python3
"""Regression: a low-value baseline hit must not block parameterized deep probing."""

import json
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "pipeline" / "deep_scanner.py"


class LabServer(ThreadingHTTPServer):
    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def send_body(self, body, content_type="text/html", status=200):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, obj, status=200):
        self.send_body(json.dumps(obj), "application/json", status)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            return self.send_body('<script src="/app.js"></script>')
        if parsed.path == "/app.js":
            return self.send_body(
                'axios.get("/api/user/detail", {params: {userId: id, pageNum: 1, pageSize: 10}});',
                "application/javascript",
            )
        if parsed.path == "/api/user/detail":
            qs = parse_qs(parsed.query)
            if qs.get("userId"):
                return self.send_json({
                    "code": 0,
                    "data": [{"userId": 1, "phone": "13800000000", "address": "Nanjing"}],
                })
            return self.send_json({"code": 0, "data": {"version": "1.0", "service": "user-detail"}})
        return self.send_json({"code": 404}, status=404)

    def do_POST(self):
        return self.do_GET()


def flatten(report):
    return [fi for host in report.get("findings", []) for fi in host.get("findings", [])]


def main():
    server = LabServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target_file = tmp / "targets.json"
            outdir = tmp / "out"
            target_file.write_text(json.dumps([{"url": server.url, "title": "param-deep-after-low-hit", "score": 100}]), encoding="utf-8")
            cmd = [
                sys.executable,
                str(SCANNER),
                "--input",
                str(target_file),
                "--outdir",
                str(outdir),
                "--workers",
                "6",
                "--timeout",
                "3",
                "--no-proxy",
                "--full-bypass",
                "--param-max-probes",
                "8",
                "--phase3b-layer-timeout",
                "60",
            ]
            proc = subprocess.run(cmd, text=True, capture_output=True, timeout=120)
            if proc.returncode != 0:
                print(proc.stdout)
                print(proc.stderr)
                raise SystemExit(proc.returncode)

            report = json.loads((outdir / "report.json").read_text(encoding="utf-8"))
            user_findings = [
                fi for fi in flatten(report)
                if urlparse(fi.get("url", "")).path == "/api/user/detail"
            ]
            assert user_findings, "expected /api/user/detail finding"
            best = max(user_findings, key=lambda fi: len(fi.get("data_keys") or []))
            keys = set(best.get("data_keys", []))
            assert {"userId", "phone", "address"}.issubset(keys), user_findings
            assert any("userId=" in u for fi in user_findings for u in fi.get("sample_urls", [])), user_findings
            print("PARAM DEEP AFTER LOW HIT LAB PASS")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
