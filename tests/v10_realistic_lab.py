#!/usr/bin/env python3
"""
Realistic local regression lab for deep_scanner v10.

It starts several in-process HTTP targets and runs the scanner against them.
The scenarios intentionally model competition surfaces:
- SPA deployed under a URL prefix with baseURL in bundled JS.
- File download endpoint discovered from JS params/seeds, not hardcoded baseline.
- API-only Swagger/OpenAPI target with data-bearing endpoints.
- Noise target to ensure /api/profile is not misclassified as a file endpoint.
"""

import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "deep_scanner.py"
if not SCANNER.exists():
    SCANNER = ROOT / "scripts" / "pipeline" / "deep_scanner.py"


class LabServer(ThreadingHTTPServer):
    def __init__(self, handler_cls):
        super().__init__(("127.0.0.1", 0), handler_cls)
        self.hits = []

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}"


class BaseLabHandler(BaseHTTPRequestHandler):
    server_version = "LabHTTP/1.0"

    def log_message(self, fmt, *args):
        return

    def record(self):
        self.server.hits.append((self.command, self.path))

    def send_bytes(self, status, body, content_type="text/plain", extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, obj, status=200):
        self.send_bytes(status, json.dumps(obj).encode(), "application/json")

    def not_found(self):
        self.send_bytes(404, b"not found")

    def do_POST(self):
        self.do_GET()


class PrefixSpaHandler(BaseLabHandler):
    def do_GET(self):
        self.record()
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)

        if parsed.path == "/tenant/":
            body = b"""<!doctype html>
<html><head><title>prefix-spa</title></head>
<body><script src="/tenant/assets/app.8f3a1.js"></script></body></html>"""
            return self.send_bytes(200, body, "text/html")

        if parsed.path == "/tenant/assets/app.8f3a1.js":
            body = b"""
window.__ENV__ = {"VUE_APP_BASE_API": "/tenant/prod-api"};
const assetCode = "demo-report-2026.pdf";
axios.get("/prod-api/profile");
axios.get("/prod-api/login/verifyCode");
axios.get("/prod-api/download/webplugin.exe");
axios.get("/prod-api/fileCenter/download?assetCode=demo-report-2026.pdf");
axios.get("/prod-api/user/list?pageNum=1&pageSize=10");
"""
            return self.send_bytes(200, body, "application/javascript")

        if parsed.path == "/tenant/prod-api/login/verifyCode":
            body = b"\x89PNG\r\n\x1a\n" + (b"0" * 256)
            return self.send_bytes(200, body, "image/png")

        if parsed.path == "/tenant/prod-api/download/webplugin.exe":
            body = b"MZ" + (b"0" * 2048)
            return self.send_bytes(
                200,
                body,
                "application/x-msdownload",
                {"Content-Disposition": 'attachment; filename="webplugin.exe"'},
            )

        if parsed.path == "/tenant/prod-api/fileCenter/download":
            if qs.get("assetCode") == ["demo-report-2026.pdf"]:
                body = b"%PDF-1.4\n" + (b"0" * 512)
                return self.send_bytes(
                    200,
                    body,
                    "application/pdf",
                    {"Content-Disposition": 'attachment; filename="demo-report-2026.pdf"'},
                )
            return self.not_found()

        if parsed.path == "/tenant/prod-api/profile":
            return self.send_json({"code": 200, "data": {"nickname": "operator", "role": "viewer"}})

        if parsed.path == "/tenant/prod-api/user/list":
            return self.send_json(
                {
                    "code": 200,
                    "data": [
                        {"userId": 1, "phone": "13800000000", "email": "u1@example.local"},
                        {"userId": 2, "phone": "13900000000", "email": "u2@example.local"},
                    ],
                }
            )

        return self.not_found()


class SwaggerApiOnlyHandler(BaseLabHandler):
    def do_GET(self):
        self.record()
        parsed = urlparse(self.path)

        if parsed.path == "/":
            return self.send_bytes(200, b"{}", "application/json")

        if parsed.path == "/v3/api-docs":
            return self.send_json(
                {
                    "openapi": "3.0.0",
                    "servers": [{"url": "/api"}],
                    "paths": {
                        "/camera/list": {"get": {"summary": "camera list"}},
                        "/system/config": {"get": {"summary": "system config"}},
                    },
                }
            )

        if parsed.path == "/api/camera/list":
            return self.send_json(
                {
                    "code": 0,
                    "data": [
                        {"cameraId": "cam-1", "streamUrl": "rtsp://10.0.0.8/live/1"},
                        {"cameraId": "cam-2", "streamUrl": "rtsp://10.0.0.9/live/2"},
                    ],
                }
            )

        if parsed.path == "/api/system/config":
            return self.send_json({"code": 0, "data": {"version": "1.0.0", "auth": "none"}})

        return self.not_found()


class NoiseProfileHandler(BaseLabHandler):
    def do_GET(self):
        self.record()
        parsed = urlparse(self.path)

        if parsed.path == "/":
            body = b"""<html><head><title>noise-profile</title></head>
<body><script src="/js/app.js"></script></body></html>"""
            return self.send_bytes(200, body, "text/html")

        if parsed.path == "/js/app.js":
            body = b"""
window.publicPath = "/static/";
fetch("/api/profile");
fetch("/api/overview");
"""
            return self.send_bytes(200, body, "application/javascript")

        if parsed.path == "/api/profile":
            return self.send_json({"code": 200, "data": {"profileName": "normal user profile"}})

        if parsed.path == "/api/overview":
            return self.send_json({"code": 200, "data": {"status": "ok"}})

        if parsed.path in ("/api/common/download", "/api/file/download"):
            return self.send_json({"code": 500, "msg": "file baseline should be disabled"}, status=500)

        return self.not_found()


def start_server(handler_cls):
    server = LabServer(handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def flatten_findings(report):
    return [fi for host in report.get("findings", []) for fi in host.get("findings", [])]


def main():
    servers = [start_server(PrefixSpaHandler), start_server(SwaggerApiOnlyHandler), start_server(NoiseProfileHandler)]
    try:
        targets = [
            {"url": servers[0].url + "/tenant/", "title": "prefix", "score": 100},
            {"url": servers[1].url, "title": "swagger", "score": 100},
            {"url": servers[2].url, "title": "noise", "score": 10},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            target_file = Path(tmp) / "targets.json"
            outdir = Path(tmp) / "out"
            target_file.write_text(json.dumps(targets), encoding="utf-8")

            cmd = [
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
                "--file-max-probes",
                "4",
                "--param-max-probes",
                "12",
            ]
            proc = subprocess.run(cmd, text=True, capture_output=True, timeout=120)
            print(proc.stdout)
            if proc.returncode != 0:
                print(proc.stderr)
                raise SystemExit(proc.returncode)

            report = json.loads((outdir / "report.json").read_text(encoding="utf-8"))
            findings = flatten_findings(report)
            file_leaks = [fi for fi in findings if fi.get("file_leak")]

            assert any(
                "/tenant/prod-api/fileCenter/download?assetCode=demo-report-2026.pdf" in fi.get("url", "")
                for fi in file_leaks
            ), "JS-derived prefixed file download was not detected"
            assert any(
                "camera" in " ".join(fi.get("data_keys", [])).lower() or "stream" in " ".join(fi.get("data_keys", [])).lower()
                for fi in findings
            ), "Swagger-derived camera API data was not detected"
            assert not any("/api/profile" in fi.get("url", "") and fi.get("file_leak") for fi in findings), (
                "/api/profile was misclassified as a file leak"
            )
            assert not any("verifyCode" in fi.get("url", "") and fi.get("file_leak") for fi in findings), (
                "captcha image was misclassified as a file leak"
            )
            public_downloads = [fi for fi in file_leaks if fi.get("public_download_intel")]
            assert any("webplugin.exe" in fi.get("url", "") for fi in public_downloads), (
                "public download was not classified as public_download_intel"
            )
            assert sum(1 for fi in public_downloads if "webplugin.exe" in fi.get("url", "")) == 1, (
                "public download entity was not deduplicated"
            )
            assert report.get("stats", {}).get("unique_data_endpoints", 0) > 0, "report stats missing unique data endpoints"

            all_hits = [path for server in servers for _, path in server.hits]
            assert not any(path.startswith("/api/common/download") for path in all_hits), (
                "hardcoded file baseline was requested even though --enable-file-baseline was not set"
            )

            print("LAB PASS")
            print(f"targets={report.get('targets')} live={report.get('live')} vulnerable={report.get('vulnerable')}")
            print(f"findings={len(findings)} file_leaks={len(file_leaks)}")
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
