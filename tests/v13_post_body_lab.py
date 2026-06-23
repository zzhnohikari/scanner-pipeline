#!/usr/bin/env python3
"""POST-body lab: bound params must be sent as JSON/form bodies, not only query."""

import json, subprocess, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "pipeline" / "deep_scanner.py"


class LabServer(ThreadingHTTPServer):
    def __init__(self, handler):
        super().__init__(("127.0.0.1", 0), handler)
        self.hits = []

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}"


class Handler(BaseHTTPRequestHandler):
    server_version = "BodyLab/1.0"

    def log_message(self, fmt, *args):
        return

    def send_body(self, status, body, content_type="text/plain", headers=None):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
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

    def read_form(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        return {k: v[0] for k, v in parse_qs(raw.decode()).items()}

    def do_GET(self):
        parsed = urlparse(self.path)
        q = parse_qs(parsed.query)
        self.server.hits.append((self.command, self.path, ""))
        if parsed.path == "/":
            return self.send_body(200, '<html><script src="/static/app.bundle.js"></script></html>', "text/html")
        if parsed.path == "/static/app.bundle.js":
            js = '''
            const request = axios.create({baseURL:"/prod-api"});
            axios.get("/api/bootstrap/status");
            axios.get("/api/bootstrap/users");
            request.post("/body/user/search", {deptId: deptId, pageNum: page.pageNum || 1, pageSize: 10, keyword: kw});
            fetch("/prod-api/body/report/export", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({reportId:reportId, format:"xlsx", includePhone:true})});
            fetch("/prod-api/form/audit/search", {method:"POST", body:qs.stringify({operatorId:operatorId, page:1, size:20, actionType:type})});
            $.post("/prod-api/form/doc/preview", {docId: docId, fileType:"pdf", watermark: false}, function(r){});
            const fd = new FormData(); fd.append("attachId", attachId); fd.append("fileType", "pdf"); axios.post("/prod-api/form/attach/download", fd);
            '''
            return self.send_body(200, js, "application/javascript")
        if parsed.path == "/api/bootstrap/status":
            return self.send_json({"code": 0, "data": {"module": "bootstrap", "status": "open"}})
        if parsed.path == "/api/bootstrap/users":
            return self.send_json({"code": 0, "data": [{"userId": 1, "phone": "13800006666", "deptId": 1}]})
        if parsed.path in (
            "/prod-api/body/user/search",
            "/prod-api/body/report/export",
            "/prod-api/form/audit/search",
            "/prod-api/form/doc/preview",
            "/prod-api/form/attach/download",
        ):
            if q:
                return self.send_json({"code": 400, "msg": "query rejected; body required"})
            return self.send_json({"code": 405, "msg": "POST required"}, status=405)
        return self.send_body(404, "not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        self.server.hits.append((self.command, self.path, self.headers.get("Content-Type", "")))
        content_type = self.headers.get("Content-Type", "")
        if parsed.path == "/prod-api/body/user/search":
            data = self.read_json()
            if data.get("deptId") and data.get("pageNum"):
                return self.send_json({"code": 0, "data": [{"userId": 1, "realName": "BodyUser", "phone": "13800005555", "deptId": data.get("deptId")}]})
            return self.send_json({"code": 400, "msg": "json body params required"})
        if parsed.path == "/prod-api/body/report/export":
            data = self.read_json()
            if data.get("reportId") and data.get("format"):
                return self.send_json({"code": 0, "data": {"reportId": data.get("reportId"), "downloadUrl": "http://10.0.0.8/files/report.xlsx", "secretToken": "body-report-token"}})
            return self.send_json({"code": 400, "msg": "json export params required"})
        if parsed.path == "/prod-api/form/audit/search":
            data = self.read_form() if "x-www-form-urlencoded" in content_type else {}
            if data.get("operatorId") and data.get("page"):
                return self.send_json({"code": 0, "data": [{"operatorId": 1, "actionType": "login", "ip": "192.168.10.5"}]})
            return self.send_json({"code": 400, "msg": "form audit params required"})
        if parsed.path == "/prod-api/form/doc/preview":
            data = self.read_form() if "x-www-form-urlencoded" in content_type else {}
            if data.get("docId") and data.get("fileType"):
                return self.send_json({"code": 0, "data": {"docId": data.get("docId"), "fileType": data.get("fileType"), "previewUrl": "/internal/doc/1.pdf"}})
            return self.send_json({"code": 400, "msg": "form doc params required"})
        if parsed.path == "/prod-api/form/attach/download":
            data = self.read_form() if "x-www-form-urlencoded" in content_type else {}
            if data.get("attachId") and data.get("fileType"):
                return self.send_json({"code": 0, "data": {"attachId": data.get("attachId"), "filePath": "/mnt/private/contract.pdf"}})
            return self.send_json({"code": 400, "msg": "form attach params required"})
        return self.send_body(404, "not found")


def flatten(report):
    return [fi for host in report.get("findings", []) for fi in host.get("findings", [])]


def main():
    server = LabServer(Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            target_file = Path(tmp) / "targets.json"
            outdir = Path(tmp) / "out"
            target_file.write_text(json.dumps([{"url": server.url, "title": "post-body-lab", "score": 100}]), encoding="utf-8")
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
            by_path_method = {(urlparse(fi.get("url", "")).path, fi.get("method"), fi.get("test")) for fi in findings}
            assert ("/prod-api/body/user/search", "POST", "POST_JSON_no_auth") in by_path_method, "JSON user body endpoint missing"
            assert ("/prod-api/body/report/export", "POST", "POST_JSON_no_auth") in by_path_method, "JSON export body endpoint missing"
            assert ("/prod-api/form/audit/search", "POST", "POST_FORM_no_auth") in by_path_method, "form audit endpoint missing"
            assert ("/prod-api/form/doc/preview", "POST", "POST_FORM_no_auth") in by_path_method, "jQuery form doc endpoint missing"
            assert ("/prod-api/form/attach/download", "POST", "POST_FORM_no_auth") in by_path_method, "FormData-style form endpoint missing"
            assert not any("query rejected" in fi.get("raw", "") for fi in findings), "query-only rejection was reported as finding"
            assert not any("attachId=deptId" in fi.get("url", "") for fi in findings), "JS variable name leaked into seed values"
            assert not any("attachId=page.pageNum" in fi.get("url", "") for fi in findings), "JS member expression leaked into seed values"
            print("BODY LAB PASS")
            print(f"targets={report.get('targets')} live={report.get('live')} vulnerable={report.get('vulnerable')} findings={len(findings)}")
            for fi in findings[:10]:
                print(f"  {fi.get('test')} {fi.get('method')} {fi.get('url','')[:100]}")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
