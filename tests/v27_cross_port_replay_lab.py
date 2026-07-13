#!/usr/bin/env python3
"""Regression for same-host API port fanout (--expand-api-ports) + cross-base
API inventory replay (--replay-scope host).

Scenario mirrors a real 前后端分离 deployment:
  * Frontend base (given target): serves HTML+JS that reveals /auth/* API paths,
    but those paths require auth (401) on the frontend port.
  * Backend base (a sibling port on the SAME host): serves the SAME /auth/* paths
    unauthenticated (200 + data JSON). The backend root is pure JSON, so Phase 2
    cannot crawl any API from it directly.

Only the frontend URL is provided. The scanner must:
  1. Fan out to the backend port on the same host (Phase 1).
  2. Replay the frontend-discovered API inventory onto the backend base (post Phase 2).
  3. Flag the unauthenticated data exposure on the backend (Phase 3).
"""

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

# APIs revealed only by the frontend JS bundle.
UNAUTH_DATA = {
    "/auth/user/list": [
        {"id": 1, "userName": "zhangsan", "phone": "13800000001", "idCard": "310..."},
        {"id": 2, "userName": "lisi", "phone": "13800000002", "idCard": "320..."},
    ],
    "/auth/device/list": [
        {"id": 11, "deviceName": "闸机-01", "sn": "FE220513B064", "status": 1},
    ],
    "/auth/leaveSchool/list": [
        {"id": 21, "name": "1班", "parentId": "100", "companyId": "9"},
    ],
}
QUERY_REQUIRED_DATA = {
    "/auth/student/detail": [
        {"userId": 42, "studentName": "wangwu", "phone": "13800000003"},
    ],
}
BODY_REQUIRED_DATA = {
    "/auth/student/search": [
        {"userId": 43, "studentName": "zhaoliu", "className": "2班"},
    ],
}
FRONTEND_ONLY_APIS = set(UNAUTH_DATA) | set(QUERY_REQUIRED_DATA) | set(BODY_REQUIRED_DATA)


class LabServer(ThreadingHTTPServer):
    daemon_threads = True

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}"


def _base_handler(role):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def _send(self, body, content_type="application/json", status=200):
            data = body if isinstance(body, bytes) else body.encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _json(self, obj, status=200):
            self._send(json.dumps(obj, ensure_ascii=False), "application/json", status)

        def do_GET(self):
            path = urlparse(self.path).path.rstrip("/") or "/"
            if role == "frontend":
                if path == "/":
                    return self._send(
                        '<!doctype html><html><head><title>智能一卡通平台</title>'
                        '<script src="/assets/app.js"></script></head>'
                        '<body><div id="app"></div></body></html>',
                        "text/html",
                    )
                if path == "/assets/app.js":
                    js = (
                        'const baseURL="/";\n'
                        'export function userList(p){return request({url:"/auth/user/list",method:"get",params:p});}\n'
                        'export function deviceList(p){return request({url:"/auth/device/list",method:"get",params:p});}\n'
                        'export function leaveList(p){return request({url:"/auth/leaveSchool/list",method:"get",params:p});}\n'
                        'export function studentDetail(userId){return request({url:"/auth/student/detail",method:"get",params:{userId:userId}});}\n'
                        'export function studentSearch(keyword){return request({url:"/auth/student/search",method:"post",data:{keyword:keyword,page:1,size:10}});}\n'
                    )
                    return self._send(js, "application/javascript")
                if path in FRONTEND_ONLY_APIS:
                    # Protected on the frontend port.
                    return self._json({"code": 401, "message": "请先登录", "result": None}, status=401)
                return self._json({"code": 404, "message": "not found"}, status=404)

            # role == "backend": pure API, root is JSON, endpoints are unauthenticated.
            if path == "/":
                return self._json({"code": 403, "message": "请先登录"}, status=403)
            if path in UNAUTH_DATA:
                return self._json({"code": 200, "message": "OK", "result": UNAUTH_DATA[path]})
            if path in QUERY_REQUIRED_DATA:
                if "userId=" in urlparse(self.path).query:
                    return self._json({"code": 200, "message": "OK", "result": QUERY_REQUIRED_DATA[path]})
                return self._json({"code": 400, "message": "missing userId", "result": []}, status=400)
            return self._json({"code": 404, "message": "not found"}, status=404)

        def do_POST(self):
            path = urlparse(self.path).path.rstrip("/") or "/"
            if role == "frontend" and path in FRONTEND_ONLY_APIS:
                return self._json({"code": 401, "message": "请先登录", "result": None}, status=401)
            if role == "backend" and path in BODY_REQUIRED_DATA:
                length = int(self.headers.get("Content-Length", "0") or 0)
                body = self.rfile.read(length).decode(errors="ignore")
                if "keyword" in body:
                    return self._json({"code": 200, "message": "OK", "result": BODY_REQUIRED_DATA[path]})
                return self._json({"code": 400, "message": "missing keyword", "result": []}, status=400)
            return self.do_GET()

    return Handler


def flatten(report):
    return [fi for host in report.get("findings", []) for fi in host.get("findings", [])]


def main():
    frontend = LabServer(("127.0.0.1", 0), _base_handler("frontend"))
    backend = LabServer(("127.0.0.1", 0), _base_handler("backend"))
    threading.Thread(target=frontend.serve_forever, daemon=True).start()
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    backend_port = backend.server_address[1]
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target_file = tmp / "targets.json"
            outdir = tmp / "out"
            # Only the frontend URL is in scope.
            target_file.write_text(
                json.dumps([{"url": frontend.url, "title": "cross-port-replay-lab", "score": 100}]),
                encoding="utf-8",
            )
            cmd = [
                sys.executable, str(SCANNER),
                "--input", str(target_file),
                "--outdir", str(outdir),
                "--workers", "8",
                "--timeout", "3",
                "--phase3a-timeout", "60",
                "--rescue-timeout", "30",
                "--phase3b-layer-timeout", "60",
                "--no-proxy",
                "--disable-api-fuzz",
                "--full-bypass",
                "--expand-api-ports", str(backend_port),
                "--replay-scope", "host",
            ]
            proc = subprocess.run(cmd, text=True, capture_output=True, timeout=200)
            if proc.returncode != 0:
                print(proc.stdout)
                print(proc.stderr)
                raise SystemExit(proc.returncode)

            inventory = [
                json.loads(line)
                for line in (outdir / "phase2_inventory.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            bases = {rec["base"]: rec for rec in inventory}
            backend_base = f"http://127.0.0.1:{backend_port}"

            # Phase 1 fanout: both frontend and backend ports must be discovered
            # from a single frontend target.
            assert frontend.url in bases, f"frontend base missing: {list(bases)}"
            assert backend_base in bases, f"backend base (port fanout) missing: {list(bases)}"

            # Frontend JS extraction produced the /auth/* inventory.
            frontend_rec = bases[frontend.url]
            for api in FRONTEND_ONLY_APIS:
                assert api in frontend_rec["apis"], (api, frontend_rec["apis"][:40])
            # Backend inventory file is written pre-replay: it must NOT already
            # contain the frontend-only paths (proves the replay, not crawling).
            backend_rec = bases[backend_base]
            assert not (FRONTEND_ONLY_APIS & set(backend_rec["apis"])), backend_rec["apis"]

            # Cross-base replay must be reported, persisted in the stream used by
            # Phase 3, and covered by the all-exact sweep without a duplicate
            # legacy replay queue.
            assert "跨base回放" in proc.stdout, proc.stdout[-2000:]
            assert "3a/exact:" in proc.stdout, proc.stdout[-2000:]
            replay_streams = sorted(outdir.glob("phase2_full.jsonl*.replay"))
            assert replay_streams, sorted(p.name for p in outdir.iterdir())
            replay_records = [
                json.loads(line)
                for line in replay_streams[-1].read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            replay_bases = {rec["base"]: rec for rec in replay_records}
            backend_replay_apis = set(replay_bases[backend_base].get("replay_apis", []))
            assert FRONTEND_ONLY_APIS.issubset(backend_replay_apis), backend_replay_apis
            backend_profile = replay_bases[backend_base].get("param_profile", {})
            assert "userId" in backend_profile["api_params"]["/auth/student/detail"], backend_profile
            assert "keyword" in backend_profile["api_params"]["/auth/student/search"], backend_profile
            assert "post" in backend_profile["api_methods"]["/auth/student/search"], backend_profile

            # Phase 3: the unauthenticated data exposure — discovered only from the
            # frontend JS, replayed onto the sibling backend port — must be flagged
            # ON THE BACKEND, never on the (protected) frontend.
            report = json.loads((outdir / "report.json").read_text(encoding="utf-8"))
            coverage = report["api_coverage"]
            assert coverage["replay_exact_scheduled"] >= len(FRONTEND_ONLY_APIS), coverage
            assert coverage["coverage_complete"] is True, coverage
            findings = flatten(report)
            backend_hits = {
                urlparse(fi.get("url", "")).path
                for fi in findings
                if urlparse(fi.get("url", "")).netloc == f"127.0.0.1:{backend_port}"
            }
            frontend_hits = {
                urlparse(fi.get("url", "")).path
                for fi in findings
                if urlparse(fi.get("url", "")).netloc == urlparse(frontend.url).netloc
            }
            assert {"/auth/student/detail", "/auth/student/search"}.issubset(backend_hits), f"param/body replay findings missing: {backend_hits}"
            assert backend_hits & set(UNAUTH_DATA), f"no backend unauth finding: {backend_hits}"
            assert not (frontend_hits & FRONTEND_ONLY_APIS), f"frontend should stay protected: {frontend_hits}"
            print("CROSS PORT REPLAY LAB PASS")
    finally:
        for s in (frontend, backend):
            s.shutdown()
            s.server_close()


if __name__ == "__main__":
    main()
