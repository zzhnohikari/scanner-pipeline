#!/usr/bin/env python3
"""Regression: HTTP DELETE method endpoints are skipped by default."""

import json
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "pipeline" / "deep_scanner.py"


class LabServer(ThreadingHTTPServer):
    def __init__(self, addr, handler):
        super().__init__(addr, handler)
        self.hits = []

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

    def do_GET(self):
        self.server.hits.append((self.command, self.path))
        if self.path == "/":
            return self.send_body('<script src="/app.js"></script>')
        if self.path == "/app.js":
            return self.send_body(
                'const delPath = "/api/user/delete";\n'
                'const fetchDel = "/api/user/fetchDelete";\n'
                'const objectDel = "/api/user/objectDelete";\n'
                'const methodConst = "DELETE";\n'
                'const constDel = "/api/user/constDelete";\n'
                'axios.delete(delPath, {data: {id: 1}});\n'
                'fetch(fetchDel, {method: "DELETE", body: JSON.stringify({id: 1})});\n'
                'request({url: objectDel, method: "delete", data: {id: 1}});\n'
                'fetch(constDel, {method: methodConst, body: JSON.stringify({id: 1})});\n'
                'request({url: "/api/user/constObjectDelete", method: methodConst, data: {id: 1}});\n'
                'axios.get("/api/user/deleteLog", {params: {page: 1}});\n'
                'axios.post("/api/user/update", {id: 1});\n',
                "application/javascript",
            )
        if self.path == "/v3/api-docs":
            return self.send_body(
                json.dumps({
                    "openapi": "3.0.0",
                    "paths": {
                        "/api/swagger/deleteOnly": {"delete": {"responses": {"200": {"description": "ok"}}}},
                        "/api/swagger/list": {"get": {"responses": {"200": {"description": "ok"}}}},
                        "/api/swagger/mixed": {
                            "delete": {"responses": {"200": {"description": "ok"}}},
                            "get": {"responses": {"200": {"description": "ok"}}},
                        },
                    },
                }),
                "application/json",
            )
        return self.send_body("not found", "text/plain", 404)

    def do_DELETE(self):
        self.server.hits.append((self.command, self.path))
        return self.send_body(json.dumps({"code": 200, "data": [{"deleted": True}]}), "application/json")


def run_scan(server_url, include_delete=False):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        target_file = tmp / "targets.json"
        outdir = tmp / "out"
        target_file.write_text(json.dumps([{"url": server_url, "title": "delete-method-lab", "score": 100}]), encoding="utf-8")
        cmd = [
            sys.executable,
            str(SCANNER),
            "--input",
            str(target_file),
            "--outdir",
            str(outdir),
            "--workers",
            "4",
            "--timeout",
            "3",
            "--phase2-timeout",
            "30",
            "--dry-run",
            "--no-proxy",
        ]
        if include_delete:
            cmd.append("--include-delete-method")
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=90)
        if proc.returncode != 0:
            print(proc.stdout)
            print(proc.stderr)
            raise SystemExit(proc.returncode)
        lines = [
            json.loads(line)
            for line in (outdir / "phase2_inventory.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert len(lines) == 1, lines
        return set(lines[0]["apis"])


def run_active_include_delete(server_url):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        target_file = tmp / "targets.json"
        outdir = tmp / "out"
        target_file.write_text(json.dumps([{"url": server_url, "title": "delete-method-lab", "score": 100}]), encoding="utf-8")
        cmd = [
            sys.executable,
            str(SCANNER),
            "--input",
            str(target_file),
            "--outdir",
            str(outdir),
            "--workers",
            "4",
            "--timeout",
            "3",
            "--phase3a-timeout",
            "20",
            "--phase3b-layer-timeout",
            "20",
            "--include-delete-method",
            "--disable-api-fuzz",
            "--replay-scope",
            "none",
            "--no-proxy",
        ]
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=90)
        if proc.returncode != 0:
            print(proc.stdout)
            print(proc.stderr)
            raise SystemExit(proc.returncode)


def main():
    server = LabServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        default_apis = run_scan(server.url)
        assert "/api/user/delete" not in default_apis, default_apis
        assert "/api/user/fetchDelete" not in default_apis, default_apis
        assert "/api/user/objectDelete" not in default_apis, default_apis
        assert "/api/user/constDelete" not in default_apis, default_apis
        assert "/api/user/constObjectDelete" not in default_apis, default_apis
        assert "/api/swagger/deleteOnly" not in default_apis, default_apis
        assert "/api/user/deleteLog" in default_apis, default_apis
        assert "/api/user/update" in default_apis, default_apis
        assert "/api/swagger/list" in default_apis, default_apis
        assert "/api/swagger/mixed" in default_apis, default_apis

        opt_in_apis = run_scan(server.url, include_delete=True)
        assert "/api/user/delete" in opt_in_apis, opt_in_apis
        assert "/api/user/fetchDelete" in opt_in_apis, opt_in_apis
        assert "/api/user/objectDelete" in opt_in_apis, opt_in_apis
        # Identifier-valued methods remain ambiguous even when the binding is a
        # const literal; include-delete cannot turn uncertain syntax into truth.
        assert "/api/user/constDelete" not in opt_in_apis, opt_in_apis
        assert "/api/user/constObjectDelete" not in opt_in_apis, opt_in_apis
        assert "/api/swagger/deleteOnly" in opt_in_apis, opt_in_apis

        server.hits = []
        run_active_include_delete(server.url)
        delete_only_paths = {
            "/api/user/delete",
            "/api/user/fetchDelete",
            "/api/user/objectDelete",
            "/api/swagger/deleteOnly",
        }
        active_hits = {
            (method, path.split("?", 1)[0])
            for method, path in server.hits
            if path.split("?", 1)[0] in delete_only_paths
        }
        assert not active_hits, active_hits
        print("SKIP DELETE METHOD LAB PASS")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
