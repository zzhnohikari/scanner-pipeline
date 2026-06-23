#!/usr/bin/env python3
"""Additional request-style lab for URL-param binding in modern/legacy frontends."""

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


class BaseHandler(BaseHTTPRequestHandler):
    server_version = "LabHTTP/1.0"

    def log_message(self, fmt, *args):
        return

    def record(self):
        self.server.hits.append((self.command, self.path))

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

    def not_found(self):
        self.send_body(404, "not found")

    def do_POST(self):
        self.do_GET()


class ObjectStyleHandler(BaseHandler):
    def do_GET(self):
        self.record()
        parsed = urlparse(self.path)
        q = parse_qs(parsed.query)
        if parsed.path == "/":
            return self.send_body(200, '<html><script src="/assets/app.js"></script></html>', "text/html")
        if parsed.path == "/assets/app.js":
            js = '''
            axios.get("/api/member/basic");
            axios({url:"/api/order/page", method:"post", data:{pageNo:p.pageNo||1, pageSize:20, customerId:p.customerId, orderStatus:p.orderStatus}});
            request("/api/member/detail", {params:{memberId:id, includeAccount:true}});
            uni.request({url:"/api/mobile/patient/list", method:"POST", data:{hospitalId:hospitalId, keyword:kw, pageNum:1, pageSize:10}});
            wx.request({url:"/api/mobile/health/detail", data:{personId:pid, archiveNo:no}});
            const fd = new FormData(); fd.append("docId", docId); fd.append("fileType", "pdf"); axios.post("/api/doc/download", fd);
            '''
            return self.send_body(200, js, "application/javascript")
        if parsed.path == "/api/member/basic":
            return self.send_json({"code": 0, "data": {"module": "member", "status": "open"}})
        if parsed.path == "/api/order/page":
            if q.get("pageNo") and q.get("pageSize"):
                return self.send_json({"code": 0, "data": {"records": [{"orderId": 1, "customerId": 7, "phone": "13800001111"}], "total": 1}})
            return self.send_json({"code": 400, "msg": "pagination required"})
        if parsed.path == "/api/member/detail":
            if q.get("memberId"):
                return self.send_json({"code": 0, "data": {"memberId": 1, "name": "MemberA", "idCard": "320102199301011111", "phone": "13800002222"}})
            return self.send_json({"code": 400})
        if parsed.path == "/api/mobile/patient/list":
            if q.get("hospitalId") and q.get("pageNum"):
                return self.send_json({"code": 0, "data": [{"patientId": 1, "name": "PatientA", "phone": "13800003333"}]})
            return self.send_json({"code": 400})
        if parsed.path == "/api/mobile/health/detail":
            if q.get("personId"):
                return self.send_json({"code": 0, "data": {"personId": 1, "archiveNo": "A001", "address": "Nanjing"}})
            return self.send_json({"code": 400})
        if parsed.path == "/api/doc/download":
            if q.get("docId"):
                return self.send_body(200, b"%PDF-1.4\n" + b"0" * 2048, "application/pdf", {"Content-Disposition": 'attachment; filename="doc.pdf"'})
            return self.send_json({"code": 400})
        return self.not_found()


class QsAndAngularHandler(BaseHandler):
    def do_GET(self):
        self.record()
        parsed = urlparse(self.path)
        q = parse_qs(parsed.query)
        if parsed.path == "/":
            return self.send_body(200, '<html><script src="/main.bundle.js"></script></html>', "text/html")
        if parsed.path == "/main.bundle.js":
            js = '''
            fetch("/api/ng/user/basic");
            fetch("/api/report/export", {method:"POST", body:qs.stringify({reportId:reportId, format:"xlsx", startDate:"2026-01-01", endDate:"2026-06-01"})});
            fetch("/api/audit/search?"+new URLSearchParams({operatorId:opId, actionType:type, page:1, size:20}));
            this.http.post("/api/ng/user/search", {deptId:this.deptId, roleCode:this.roleCode, pageNum:1, pageSize:10}).subscribe();
            this.http.get("/api/ng/device/detail", {params:{deviceId:this.deviceId, channelId:this.channelId}}).subscribe();
            $.getJSON("/api/jquery/config/detail", {configId:cid, tenantId:tid}, function(r){});
            '''
            return self.send_body(200, js, "application/javascript")
        if parsed.path == "/api/ng/user/basic":
            return self.send_json({"code": 0, "data": {"module": "ng", "status": "open"}})
        if parsed.path == "/api/report/export":
            if q.get("reportId"):
                return self.send_body(200, b"PK\x03\x04" + b"0" * 2048, "application/zip", {"Content-Disposition": 'attachment; filename="report.xlsx"'})
            return self.send_json({"code": 400})
        if parsed.path == "/api/audit/search":
            if q.get("operatorId") and q.get("page"):
                return self.send_json({"code": 0, "data": [{"operatorId": 1, "actionType": "login", "ip": "10.0.0.5"}]})
            return self.send_json({"code": 400})
        if parsed.path == "/api/ng/user/search":
            if q.get("deptId") and q.get("pageNum"):
                return self.send_json({"code": 0, "data": [{"userId": 1, "realName": "NgUser", "phone": "13800004444"}]})
            return self.send_json({"code": 400})
        if parsed.path == "/api/ng/device/detail":
            if q.get("deviceId") and q.get("channelId"):
                return self.send_json({"code": 0, "data": {"deviceId": 1, "channelId": 1, "streamUrl": "rtsp://10.1.1.1/live"}})
            return self.send_json({"code": 400})
        if parsed.path == "/api/jquery/config/detail":
            if q.get("configId"):
                return self.send_json({"code": 0, "data": {"configId": 1, "secretKey": "demo-secret-key"}})
            return self.send_json({"code": 400})
        return self.not_found()


def start(handler):
    server = LabServer(handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def flatten(report):
    return [fi for host in report.get("findings", []) for fi in host.get("findings", [])]


def main():
    servers = [start(ObjectStyleHandler), start(QsAndAngularHandler)]
    try:
        targets = [{"url": s.url, "title": name, "score": 100} for s, name in zip(servers, ["object-style", "qs-angular"])]
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
                    "--file-max-probes",
                    "4",
                    "--param-max-probes",
                    "14",
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
            urls = {fi.get("url", "") for fi in findings}
            def has(path, **params):
                for url in urls:
                    parsed = urlparse(url)
                    q = parse_qs(parsed.query)
                    if parsed.path.endswith(path) and all(q.get(k) == [v] for k, v in params.items()):
                        return True
                return False

            assert has("/api/order/page", pageNo="1", pageSize="10"), "axios object data combo missing"
            assert has("/api/member/detail", memberId="1"), "request(url, params) missing"
            assert has("/api/mobile/patient/list", hospitalId="1", pageNum="1"), "uni.request data combo missing"
            assert has("/api/doc/download", docId="1", fileType="pdf"), "FormData append combo missing"
            assert has("/api/report/export", reportId="1", format="xlsx"), "qs.stringify export combo missing"
            assert has("/api/audit/search", operatorId="1", page="1"), "URLSearchParams combo missing"
            assert has("/api/ng/user/search", deptId="1", pageNum="1"), "Angular post combo missing"
            assert has("/api/ng/device/detail", deviceId="1", channelId="1"), "Angular get params combo missing"
            assert has("/api/jquery/config/detail", configId="1"), "jQuery getJSON combo missing"
            assert not any(("this." in u or "undefined" in u) and "?" in u for u in urls), "expression leaked into query value"
            print("LAB PASS")
            print(f"targets={report.get('targets')} live={report.get('live')} vulnerable={report.get('vulnerable')} findings={len(findings)}")
            for fi in findings[:12]:
                print(f"  {fi.get('method')} {fi.get('url','')[:100]}")
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
