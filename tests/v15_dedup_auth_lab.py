#!/usr/bin/env python3
"""Dedup/auth-filter lab for full-bypass report noise."""

import json, subprocess, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "deep_scanner.py"
if not SCANNER.exists():
    SCANNER = ROOT / "scripts" / "pipeline" / "deep_scanner.py"


class LabServer(ThreadingHTTPServer):
    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}"


class Handler(BaseHTTPRequestHandler):
    server_version = "DedupLab/1.0"

    def log_message(self, fmt, *args):
        return

    def send_body(self, status, body, content_type="text/plain"):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, obj, status=200):
        self.send_body(status, json.dumps(obj, ensure_ascii=False), "application/json")

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            return self.send_body(200, '<script src="/app.js"></script>', "text/html")
        if parsed.path == "/app.js":
            js = '''
            fetch("/api/user/list?page=1&size=10");
            fetch("/api/auth/expired");
            fetch("/api/auth/permission");
            fetch("/api/auth/data-error");
            '''
            return self.send_body(200, js, "application/javascript")
        if parsed.path == "/api/user/list":
            return self.send_json({"code": 0, "data": [{"userId": 1, "phone": "13800001234"}]})
        if parsed.path == "/api/auth/expired":
            return self.send_json({"code": 0, "msg": "登录已过期，请重新登录", "data": {"error": "无权限访问"}})
        if parsed.path == "/api/auth/permission":
            return self.send_json({"message": "Access Denied", "data": {"phone": "13800000000"}})
        if parsed.path == "/api/auth/data-error":
            return self.send_json({"msg": "success", "data": {"error": "无权限访问", "phone": "13800000001"}})
        return self.send_json({"code": 404}, status=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/user/list":
            return self.send_json({"code": 0, "data": [{"userId": 1, "phone": "13800001234"}]})
        if parsed.path == "/api/auth/expired":
            return self.send_json({"code": 0, "msg": "无权限访问", "data": {"error": "permission denied"}})
        if parsed.path == "/api/auth/permission":
            return self.send_json({"message": "Access Denied", "data": {"phone": "13800000000"}})
        if parsed.path == "/api/auth/data-error":
            return self.send_json({"msg": "success", "data": {"error": "无权限访问", "phone": "13800000001"}})
        return self.send_json({"code": 404}, status=404)


def flatten(report):
    return [fi for host in report.get("findings", []) for fi in host.get("findings", [])]


def main():
    server = LabServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            target_file = Path(tmp) / "targets.json"
            outdir = Path(tmp) / "out"
            target_file.write_text(json.dumps([{"url": server.url, "title": "dedup-auth-lab", "score": 100}]), encoding="utf-8")
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
            report = json.loads((outdir / "report.json").read_text(encoding="utf-8"))
            findings = flatten(report)
            user_findings = [fi for fi in findings if urlparse(fi.get("url", "")).path == "/api/user/list"]
            auth_findings = [fi for fi in findings if urlparse(fi.get("url", "")).path == "/api/auth/expired"]
            permission_findings = [fi for fi in findings if urlparse(fi.get("url", "")).path in ("/api/auth/permission", "/api/auth/data-error")]
            assert len(user_findings) == 1, f"user/list should aggregate to 1 finding, got {len(user_findings)}"
            assert user_findings[0].get("variant_count", 0) > len(user_findings[0].get("sample_urls", [])), "variant_count should not be capped by sample_urls"
            assert len(user_findings[0].get("tests", [])) >= 2, "aggregated finding should preserve bypass tests"
            assert not auth_findings, "auth failure response should not be reported"
            assert not permission_findings, "nested/case-insensitive auth failure response should not be reported"
            assert report["stats"].get("merged_variants", 0) > 0, "merged variant stat missing"
            print("DEDUP AUTH LAB PASS")
            print(f"targets={report.get('targets')} live={report.get('live')} vulnerable={report.get('vulnerable')} findings={len(findings)} merged={report['stats'].get('merged_variants')}")
            for fi in findings[:8]:
                print(f"  variants={fi.get('variant_count')} tests={','.join(fi.get('tests', [])[:4])} {fi.get('url','')[:100]}")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
