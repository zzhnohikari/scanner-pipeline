#!/usr/bin/env python3
"""Regression for API-only JSON backends with no crawlable frontend.

Scenario:
  * The target root is a pure JSON response and exposes no HTML/JS API inventory.
  * Several high-value /auth/* endpoints are nevertheless reachable unauthenticated.
  * Default scanner behavior must stay quiet: the extra backend dictionary is opt-in.
  * With --enable-backend-baseline, Phase 2 inventories and Phase 3 tests those
    endpoints and flags the data/JWT exposures.
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

BACKEND_DATA = {
    "/auth/externalInterfaceApi/list": [
        {"id": "1465", "interfaceName": "syncStudent", "companyId": "9", "status": 1},
    ],
    "/auth/leaveSchool/list": [
        {"id": "21", "studentName": "masked", "companyId": "9", "leaveStatus": 0},
    ],
    "/auth/company/api/getCompanyList": [
        {"id": "9", "companyName": "demo-company", "companyCode": "demo"},
    ],
    "/auth/getRandomCode": [
        "uuid-demo",
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB",
    ],
    "/auth/account/getByOpenid/aaaa": [
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.signature",
        "2074034712734646274",
    ],
    "/auth/cameraFile/api/outApiCheckPhotos": [
        {"photoId": "1", "cameraId": "cam-1", "photoUrl": "https://example.invalid/masked.jpg"},
    ],
}


class LabServer(ThreadingHTTPServer):
    daemon_threads = True

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def _json(self, obj, status=200):
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path == "/":
            return self._json({"code": 200, "message": "OK", "result": {"service": "api-only"}})
        if path == "/auth/cameraFile/api/outApiCheckPhotos":
            if "photoId=1" in urlparse(self.path).query:
                return self._json({"code": 200, "message": "OK", "result": BACKEND_DATA[path]})
            return self._json({"code": 400, "message": "missing parameter", "result": None}, status=400)
        if path in BACKEND_DATA:
            return self._json({"code": 200, "message": "OK", "result": BACKEND_DATA[path]})
        return self._json({"code": 404, "message": "not found"}, status=404)

    def do_POST(self):
        return self.do_GET()


def flatten(report):
    return [fi for host in report.get("findings", []) for fi in host.get("findings", [])]


def run_scan(target_file, outdir, enable_backend_baseline=False):
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
        "--full-bypass",
        "--fresh",
    ]
    if enable_backend_baseline:
        cmd.append("--enable-backend-baseline")
    proc = subprocess.run(cmd, text=True, capture_output=True, timeout=200)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr)
        raise SystemExit(proc.returncode)
    return proc


def main():
    server = LabServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target_file = tmp / "targets.json"
            target_file.write_text(
                json.dumps([{"url": server.url, "title": "api-only-backend-lab", "score": 100}]),
                encoding="utf-8",
            )

            default_out = tmp / "default"
            run_scan(target_file, default_out, enable_backend_baseline=False)
            default_inventory = json.loads((default_out / "phase2_inventory.jsonl").read_text(encoding="utf-8").splitlines()[0])
            assert not (set(BACKEND_DATA) & set(default_inventory["apis"])), default_inventory["apis"]

            wordlist = tmp / "extra_apis.txt"
            wordlist.write_text(
                "# user supplied backend paths\n"
                f"{server.url}/auth/externalInterfaceApi/list\n"
                "/auth/leaveSchool/list\n",
                encoding="utf-8",
            )
            wordlist_out = tmp / "wordlist"
            cmd = [
                sys.executable, str(SCANNER),
                "--input", str(target_file),
                "--outdir", str(wordlist_out),
                "--workers", "8",
                "--timeout", "3",
                "--phase3a-timeout", "60",
                "--rescue-timeout", "30",
                "--phase3b-layer-timeout", "60",
                "--no-proxy",
                "--full-bypass",
                "--fresh",
                "--extra-api-wordlist", str(wordlist),
            ]
            proc_wordlist = subprocess.run(cmd, text=True, capture_output=True, timeout=200)
            if proc_wordlist.returncode != 0:
                print(proc_wordlist.stdout)
                print(proc_wordlist.stderr)
                raise SystemExit(proc_wordlist.returncode)
            wordlist_inventory = json.loads((wordlist_out / "phase2_inventory.jsonl").read_text(encoding="utf-8").splitlines()[0])
            assert wordlist_inventory["api_sources"].get("/auth/externalInterfaceApi/list") == ["extra_wordlist"], wordlist_inventory["api_sources"]
            assert wordlist_inventory["api_sources"].get("/auth/leaveSchool/list") == ["extra_wordlist"], wordlist_inventory["api_sources"]

            opt_in_out = tmp / "opt-in"
            proc = run_scan(target_file, opt_in_out, enable_backend_baseline=True)
            assert "backend-baseline=True" in proc.stdout, proc.stdout
            assert "3a/backend-param" in proc.stdout, proc.stdout

            inventory = json.loads((opt_in_out / "phase2_inventory.jsonl").read_text(encoding="utf-8").splitlines()[0])
            for api in BACKEND_DATA:
                assert api in inventory["apis"], (api, inventory["apis"][:60])
                assert "backend_baseline" in inventory["api_sources"].get(api, []), inventory["api_sources"].get(api)

            report = json.loads((opt_in_out / "report.json").read_text(encoding="utf-8"))
            paths = {urlparse(fi.get("url", "")).path for fi in flatten(report)}
            expected_hits = set(BACKEND_DATA)
            assert expected_hits.issubset(paths), f"missing hits: {expected_hits - paths}; got={paths}"
            jwt_finding = [
                fi for fi in flatten(report)
                if urlparse(fi.get("url", "")).path == "/auth/account/getByOpenid/aaaa"
            ]
            assert jwt_finding and jwt_finding[0].get("credential_leak"), jwt_finding
            print("BACKEND BASELINE LAB PASS")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
