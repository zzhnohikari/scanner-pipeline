#!/usr/bin/env python3
"""Regression for persisting Phase 2 inventory for non-vulnerable targets."""

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

    def send_json(self, obj, status=200):
        self.send_body(json.dumps(obj), "application/json", status)

    def do_GET(self):
        if self.path == "/":
            return self.send_body(
                '<html><head><title>inventory-lab</title><script src="/app.js"></script></head><body></body></html>'
            )
        if self.path == "/app.js":
            return self.send_body(
                'fetch("/api/public/list?pageNum=1");'
                'fetch("/api/public/detail?id=42");'
                'axios.post("/api/report/export", {deptId: 1, keyword: "demo"});',
                "application/javascript",
            )
        if self.path.startswith("/api/"):
            return self.send_json({"code": 401, "message": "未登录"}, status=401)
        return self.send_json({"code": 404}, status=404)

    def do_POST(self):
        if self.path.startswith("/api/"):
            return self.send_json({"code": 401, "message": "未登录"}, status=401)
        return self.send_json({"code": 404}, status=404)


def main():
    server = LabServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target_file = tmp / "targets.json"
            outdir = tmp / "out"
            target_file.write_text(
                json.dumps([{"url": server.url, "title": "phase2-inventory-lab", "score": 100}]),
                encoding="utf-8",
            )
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
                "--phase3b-layer-timeout",
                "20",
                "--phase3a-timeout",
                "20",
                "--rescue-timeout",
                "20",
                "--no-proxy",
            ]
            proc = subprocess.run(cmd, text=True, capture_output=True, timeout=120)
            if proc.returncode != 0:
                print(proc.stdout)
                print(proc.stderr)
                raise SystemExit(proc.returncode)

            inventory_path = outdir / "phase2_inventory.jsonl"
            assert inventory_path.exists(), "phase2 inventory file should exist"
            lines = [json.loads(line) for line in inventory_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            assert len(lines) == 1, f"expected one phase2 record, got {len(lines)}"
            item = lines[0]
            assert item["base"] == server.url
            assert item["title"] == "inventory-lab"
            assert item["api_count"] >= 3, item
            assert "/api/public/list" in item["apis"], item["apis"][:10]
            assert "/api/public/detail" in item["apis"], item["apis"][:10]
            assert "/api/report/export" in item["apis"], item["apis"][:10]
            assert item["js_count"] == 1, item
            assert item["param_name_count"] >= 4, item
            assert "pageNum" in item["param_names"], item["param_names"]
            assert "deptId" in item["param_profile"]["api_params"]["/api/report/export"], item["param_profile"]

            report = json.loads((outdir / "report.json").read_text(encoding="utf-8"))
            assert report["vulnerable"] == 0, report
            coverage_checkpoint = json.loads((outdir / "api_coverage.json").read_text(encoding="utf-8"))
            assert report["api_inventory_total"] == coverage_checkpoint["api_inventory_total"]
            assert report["api_coverage"] == coverage_checkpoint["api_coverage"]
            assert report["stats"]["api_coverage"] == report["api_coverage"]
            assert len(report["api_coverage_by_target"]) == 1
            assert report["apis"] == 1, "legacy report.apis remains the base-record count"
            checkpoint_wire = json.dumps(coverage_checkpoint, sort_keys=True)
            assert "/api/public" not in checkpoint_wire and "?" not in checkpoint_wire
            markdown = (outdir / "report.md").read_text(encoding="utf-8")
            assert "## API 覆盖（仅聚合计数）" in markdown
            assert "api_inventory_total:" in markdown and "coverage_complete:" in markdown
            assert not list(outdir.glob("http*.json")), "non-vulnerable target should not create checkpoint json"

            # Reusing an outdir must rebuild current-run streams. Appending the
            # previous Phase 2 records would put historical targets back into
            # Phase 3 and can send probes outside the current input scope.
            rerun = subprocess.run(cmd + ["--dry-run"], text=True, capture_output=True, timeout=120)
            if rerun.returncode != 0:
                print(rerun.stdout)
                print(rerun.stderr)
                raise SystemExit(rerun.returncode)
            inventory_lines = [
                json.loads(line)
                for line in inventory_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            assert len(inventory_lines) == 1, inventory_lines
            full_stream = outdir / "phase2_full.jsonl"
            full_lines = [line for line in full_stream.read_text(encoding="utf-8").splitlines() if line.strip()]
            assert len(full_lines) == 1, full_lines
            print("PHASE2 INVENTORY PERSIST LAB PASS")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
