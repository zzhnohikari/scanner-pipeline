#!/usr/bin/env python3
"""Regression check for gzip-compressed HTTP bodies across scanner phases."""

import gzip
import importlib.util
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "pipeline" / "deep_scanner.py"


def load_scanner():
    old_argv = sys.argv[:]
    sys.argv = [str(SCANNER), "--no-proxy"]
    try:
        spec = importlib.util.spec_from_file_location("deep_scanner_gzip_test", SCANNER)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        sys.argv = old_argv


class LabServer(ThreadingHTTPServer):
    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def send_gzip(self, body, content_type, status=200, extra_headers=None):
        raw = body if isinstance(body, bytes) else body.encode()
        packed = gzip.compress(raw)
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(packed)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(packed)

    def do_GET(self):
        if self.path.startswith("/api/gzip-json"):
            return self.send_gzip(
                json.dumps({"code": 0, "data": [{"userId": 1, "phone": "13800001234"}]}),
                "application/json",
            )
        if self.path.startswith("/api/gzip-file"):
            return self.send_gzip(
                b"%PDF-1.7\n" + (b"A" * 4096),
                "application/pdf",
                extra_headers={"Content-Disposition": 'attachment; filename="report.pdf"'},
            )
        self.send_response(404)
        self.end_headers()


def main():
    scanner = load_scanner()
    js = b'axios.get("/goods/itemNew"); fetch("/user/querycustomer"); const api="/upload/uploadSign";'
    packed = gzip.compress(js)
    text = scanner.decode_http_body(packed, {"Content-Encoding": "gzip", "Content-Type": "application/javascript"})
    apis = set(scanner.extract_apis(text))
    assert "/goods/itemNew" in apis, apis
    assert "/user/querycustomer" in apis, apis
    assert "/upload/uploadSign" in apis, apis

    server = LabServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        json_findings = scanner.test_api(
            server.url,
            "/api/gzip-json",
            [("GET_no_auth", "GET", "", None, {})],
            short_circuit=True,
        )
        assert json_findings, "gzip JSON API response should be detected"
        assert json_findings[0].get("data_count") == 1, json_findings

        file_findings = scanner.test_api(
            server.url,
            "/api/gzip-file",
            [("GET_no_auth", "GET", "", None, {})],
            short_circuit=True,
        )
        assert file_findings, "gzip file API response should be detected"
        assert file_findings[0].get("file_magic") == "PDF", file_findings
    finally:
        server.shutdown()
        server.server_close()

    print("GZIP HTTP DECODE PASS")


if __name__ == "__main__":
    main()
