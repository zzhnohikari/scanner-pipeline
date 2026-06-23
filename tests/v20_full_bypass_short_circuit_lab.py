#!/usr/bin/env python3
"""Regression for FULL bypass short-circuit vs all-variant evidence collection."""

import json
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


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
            return self.send_body('fetch("/api/user/list");', "application/javascript")
        if parsed.path == "/api/user/list":
            return self.send_json({"code": 0, "data": [{"userId": 1, "phone": "13800000000"}]})
        return self.send_json({"code": 404}, status=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/user/list":
            return self.send_json({"code": 0, "data": [{"userId": 2, "phone": "13800000001"}]})
        return self.send_json({"code": 404}, status=404)


def flatten(report):
    return [fi for host in report.get("findings", []) for fi in host.get("findings", [])]


def run_scan(server_url, collect_all=False, full_bypass=True):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        target_file = tmp / "targets.json"
        outdir = tmp / "out"
        target_file.write_text(json.dumps([{"url": server_url, "title": "full-bypass-short-circuit", "score": 100}]), encoding="utf-8")
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
            "--phase3b-layer-timeout",
            "60",
            "--param-max-probes",
            "4",
        ]
        if full_bypass:
            cmd.append("--full-bypass")
        if collect_all:
            cmd.append("--collect-all-variants")
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=120)
        if proc.returncode != 0:
            print(proc.stdout)
            print(proc.stderr)
            raise SystemExit(proc.returncode)
        report = json.loads((outdir / "report.json").read_text(encoding="utf-8"))
        return flatten(report)


def main():
    server = LabServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        short_findings = run_scan(server.url, collect_all=False)
        short_user = [fi for fi in short_findings if urlparse(fi.get("url", "")).path == "/api/user/list"]
        assert short_user, "FULL bypass should still find the vulnerable API"
        short_variants = short_user[0].get("variant_count", 1)
        assert short_variants <= 2, f"FULL bypass should short-circuit by default, got {short_variants}"

        full_findings = run_scan(server.url, collect_all=True, full_bypass=False)
        full_user = [fi for fi in full_findings if urlparse(fi.get("url", "")).path == "/api/user/list"]
        assert full_user, "collect-all run should still find the vulnerable API"
        full_variants = full_user[0].get("variant_count", 1)
        assert full_variants > short_variants, f"collect-all should preserve more variants: {short_variants} -> {full_variants}"
        print("FULL BYPASS SHORT CIRCUIT LAB PASS")
        print(f"short_variants={short_variants} collect_all_variants={full_variants}")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
