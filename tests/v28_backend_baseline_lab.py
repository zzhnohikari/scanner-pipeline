#!/usr/bin/env python3
"""Regression for API-only JSON backends with no crawlable frontend.

Scenario:
  * The target root is a pure JSON response and exposes no HTML/JS API inventory.
  * Several generic synthetic REST endpoints are reachable unauthenticated.
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
QUERY_MARKER = "v28_query_must_not_persist"
CREDENTIAL_MARKER = "v28_credential_must_not_persist"

BACKEND_DATA = {
    "/api/v1/status": [
        {"id": "1465", "serviceName": "synthetic-service", "status": 1},
    ],
    "/api/v1/health": [
        {"id": "21", "componentName": "synthetic-component", "status": "up"},
    ],
    "/api/v1/users": [
        {"id": "9", "userName": "synthetic-user", "status": "active"},
    ],
    "/api/v1/search": [
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.signature",
        "synthetic-record",
    ],
    "/rest/status": [
        {"id": "1", "name": "synthetic-rest", "status": "ready"},
    ],
    "/rest/users": [
        {"id": "1", "userName": "synthetic-rest-user", "status": "active"},
    ],
}


class LabServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.hits = []

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

    def _handle(self):
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path == "/":
            return self._json({"code": 200, "message": "OK", "result": {"service": "api-only"}})
        if path == "/rest/users":
            if "id=1" in urlparse(self.path).query:
                return self._json({"code": 200, "message": "OK", "result": BACKEND_DATA[path]})
            return self._json({"code": 400, "message": "missing parameter", "result": None}, status=400)
        if path in BACKEND_DATA:
            return self._json({"code": 200, "message": "OK", "result": BACKEND_DATA[path]})
        return self._json({"code": 404, "message": "not found"}, status=404)

    def do_GET(self):
        self.server.hits.append((self.command, urlparse(self.path).path))
        return self._handle()

    def do_POST(self):
        self.server.hits.append((self.command, urlparse(self.path).path))
        return self._handle()


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
                f"{server.url}/api/v1/status?probe={QUERY_MARKER}#ignored\n"
                f"HTTP://127.0.0.1:{server.server_address[1]}/api/v1/users#ignored\n"
                f"HTTP://user:pass@127.0.0.1:{server.server_address[1]}/{CREDENTIAL_MARKER}\n"
                f"//127.0.0.1:{server.server_address[1]}/network-path-must-not-persist\n"
                f"http://127.0.0.1:{server.server_address[1]}//double-slash-must-not-persist\n",
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
            wordlist_hit_start = len(server.hits)
            proc_wordlist = subprocess.run(cmd, text=True, capture_output=True, timeout=200)
            if proc_wordlist.returncode != 0:
                print(proc_wordlist.stdout)
                print(proc_wordlist.stderr)
                raise SystemExit(proc_wordlist.returncode)
            wordlist_inventory = json.loads((wordlist_out / "phase2_inventory.jsonl").read_text(encoding="utf-8").splitlines()[0])
            assert wordlist_inventory["api_sources"].get("/api/v1/status") == ["extra_wordlist"], wordlist_inventory["api_sources"]
            assert wordlist_inventory["api_sources"].get("/api/v1/users") == ["extra_wordlist"], wordlist_inventory["api_sources"]
            wordlist_hits = server.hits[wordlist_hit_start:]
            for path in ("/api/v1/status", "/api/v1/users"):
                assert ("GET", path) in wordlist_hits, (path, wordlist_hits)
                assert ("POST", path) not in wordlist_hits, (path, wordlist_hits)
            wordlist_report = json.loads((wordlist_out / "report.json").read_text(encoding="utf-8"))
            wordlist_paths = {urlparse(fi.get("url", "")).path for fi in flatten(wordlist_report)}
            assert {
                "/api/v1/status", "/api/v1/users",
            } <= wordlist_paths, wordlist_paths

            dry_out = tmp / "wordlist-dry"
            dry_cmd = [
                sys.executable, str(SCANNER),
                "--input", str(target_file),
                "--outdir", str(dry_out),
                "--workers", "4",
                "--timeout", "3",
                "--no-proxy",
                "--skip-port-probe",
                "--disable-api-fuzz",
                "--replay-scope", "none",
                "--dry-run",
                "--fresh",
                "--extra-api-wordlist", str(wordlist),
            ]
            dry_proc = subprocess.run(dry_cmd, text=True, capture_output=True, timeout=120)
            if dry_proc.returncode != 0:
                print(dry_proc.stdout)
                print(dry_proc.stderr)
                raise SystemExit(dry_proc.returncode)
            for name in ("phase2_full.jsonl", "phase2_inventory.jsonl", "apis.json"):
                persisted = (dry_out / name).read_text(encoding="utf-8")
                assert QUERY_MARKER not in persisted, name
                assert CREDENTIAL_MARKER not in persisted, name
                assert "network-path-must-not-persist" not in persisted, name
                assert "double-slash-must-not-persist" not in persisted, name
            dry_inventory = json.loads((dry_out / "phase2_inventory.jsonl").read_text().splitlines()[0])
            for path in ("/api/v1/status", "/api/v1/users"):
                assert path in dry_inventory["apis"], (path, dry_inventory["apis"])
                assert not any(api.startswith(path + "?") for api in dry_inventory["apis"]), dry_inventory["apis"]
                assert dry_inventory["api_sources"].get(path) == ["extra_wordlist"]

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
                if urlparse(fi.get("url", "")).path == "/api/v1/search"
            ]
            assert jwt_finding and jwt_finding[0].get("credential_leak"), jwt_finding
            print("BACKEND BASELINE LAB PASS")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
