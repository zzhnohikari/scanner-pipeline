#!/usr/bin/env python3
"""Edge cases for candidate gating, nested JSON bodies, short HTML, and response shapes."""

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
    server_version = "EdgeLab/1.0"

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

    def read_json(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        try:
            return json.loads(raw.decode() or "{}")
        except Exception:
            return {}

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            return self.send_body(200, '<script src="/app.js"></script>', "text/html")
        if parsed.path == "/app.js":
            js = '''
            service.post("/api/body-only/search", {deptId: deptId, pageNum: 1, pageSize: 10});
            service.post("/api/nested/user/search", {filter:{deptId: deptId, status: 1}, pageable:{pageNum: 1, pageSize: 10}});
            service.post("/api/result/records", {deptId: deptId, pageNum: 1});
            service.post("/api/top/rows", {deptId: deptId, pageNum: 1});
            '''
            return self.send_body(200, js, "application/javascript")
        return self.send_json({"code": 404, "msg": "not found"}, status=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        data = self.read_json()
        if parsed.path == "/api/body-only/search":
            if data.get("deptId") and data.get("pageNum"):
                return self.send_json({"code": 0, "data": [{"userId": 1, "phone": "13800007777"}]})
            return self.send_json({"code": 400, "msg": "flat json body required"})
        if parsed.path == "/api/nested/user/search":
            if data.get("filter", {}).get("deptId") and data.get("pageable", {}).get("pageNum"):
                return self.send_json({"code": 0, "data": [{"userId": 2, "phone": "13800008888", "deptId": data["filter"]["deptId"]}]})
            return self.send_json({"code": 400, "msg": "nested json body required"})
        if parsed.path == "/api/result/records":
            if data.get("deptId"):
                return self.send_json({"success": True, "result": {"records": [{"phone": "13800009999", "idCard": "320100199901011111"}], "total": 1}})
            return self.send_json({"success": False})
        if parsed.path == "/api/top/rows":
            if data.get("deptId"):
                return self.send_json({"code": 0, "rows": [{"phone": "13800001111", "address": "Nanjing"}], "total": 1})
            return self.send_json({"code": 400})
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
            target_file.write_text(json.dumps([{"url": server.url, "title": "edge-lab", "score": 100}]), encoding="utf-8")
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
                    "10",
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
            paths = {urlparse(fi.get("url", "")).path for fi in findings}
            keys_by_path = {urlparse(fi.get("url", "")).path: set(fi.get("data_keys", [])) for fi in findings}
            assert report.get("vulnerable") == 1, "pure body-only target did not become candidate"
            assert "/api/body-only/search" in paths, "body-only flat POST endpoint missing"
            assert "/api/nested/user/search" in paths, "nested JSON endpoint missing"
            assert "/api/result/records" in paths, "result.records response missing"
            assert "/api/top/rows" in paths, "top-level rows response missing"
            assert "idCard" in keys_by_path.get("/api/result/records", set()), "result.records data keys not extracted"
            assert "address" in keys_by_path.get("/api/top/rows", set()), "rows data keys not extracted"
            print("EDGE LAB PASS")
            print(f"targets={report.get('targets')} live={report.get('live')} vulnerable={report.get('vulnerable')} findings={len(findings)}")
            for fi in findings[:10]:
                print(f"  {fi.get('test')} {fi.get('method')} {fi.get('url','')[:100]}")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
