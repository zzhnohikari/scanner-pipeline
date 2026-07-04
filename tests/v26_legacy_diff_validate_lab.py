#!/usr/bin/env python3
"""v26 tests for legacy recovery, safe inventory diff, validate-from-report."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "pipeline" / "deep_scanner.py"


def load_scanner_module():
    old_argv = sys.argv[:]
    try:
        sys.argv = [str(SCANNER)]
        spec = importlib.util.spec_from_file_location("deep_scanner_v26", SCANNER)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        sys.argv = old_argv


class LabServer(ThreadingHTTPServer):
    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}"


class Handler(BaseHTTPRequestHandler):
    hits = []

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
        self.send_body(json.dumps(obj, ensure_ascii=False), "application/json", status)

    def do_GET(self):
        type(self).hits.append(self.path)
        if self.path == "/" or self.path.startswith("/?"):
            return self.send_body("<html><title>legacy</title><script src='/app.js'></script></html>")
        if self.path == "/app.js":
            return self.send_body('fetch("/api/real/list");', "application/javascript")
        if self.path.startswith("/api/real/list"):
            return self.send_json({"code": 0, "data": [{"phone": "13900000000"}]})
        if self.path.startswith("/v3/api-docs"):
            return self.send_json({"openapi": "3.0.0", "paths": {"/api/real/list": {}}})
        if self.path.startswith("/api/file/download"):
            return self.send_body(b"%PDF-1.4\n" + b"0" * 64, "application/pdf")
        return self.send_body("not found", status=404)

    def do_POST(self):
        return self.do_GET()


def run_dry(base, outdir, legacy=False, old=None):
    cmd = [sys.executable, str(SCANNER), "--input", str(outdir / "targets.json"), "--outdir", str(outdir), "--workers", "4", "--timeout", "3", "--no-proxy", "--dry-run", "--phase12-workers", "2"]
    if legacy:
        cmd.append("--legacy-recovery")
    if old:
        cmd += ["--compare-inventory", str(old)]
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "targets.json").write_text(json.dumps([{"url": base, "title": "legacy", "score": 100}]), encoding="utf-8")
    proc = subprocess.run(cmd, text=True, capture_output=True, timeout=80)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr)
        raise SystemExit(proc.returncode)
    return json.loads((outdir / "apis.json").read_text(encoding="utf-8"))[0]


def test_legacy_recovery_flag_low_confidence_only_when_enabled():
    server = LabServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            normal = run_dry(server.url, root / "normal", legacy=False)
            legacy = run_dry(server.url, root / "legacy", legacy=True)
            assert "/openapi.yaml" not in normal["apis"], normal["apis"][:30]
            assert "/api/file/download" not in normal["apis"], normal["apis"][:30]
            assert "/openapi.yaml" in legacy["apis"], legacy["apis"][:80]
            assert "/api/file/download" in legacy["apis"], legacy["apis"][:80]
            assert "legacy_recovery" in legacy["api_sources"]["/openapi.yaml"], legacy["api_sources"]["/openapi.yaml"]
            assert legacy["api_confidence"]["/openapi.yaml"] == 0.3, legacy["api_confidence"]
            assert not any("foo.bar.baz" in api for api in legacy["apis"]), legacy["apis"]
    finally:
        server.shutdown(); server.server_close()


def test_inventory_diff_safe_aggregate_no_host_leak_and_artifact_categories():
    ds = load_scanner_module()
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        old = root / "old.json"
        cur = root / "cur.json"
        old.write_text(json.dumps([
            {"base": "https://secret-old.example", "apis": ["/api/real/list", "/foo.bar.baz", "/v2/api-docs", "/api/file/download"], "api_confidence": {"/foo.bar.baz": 0.2}}
        ]), encoding="utf-8")
        cur.write_text(json.dumps([
            {"base": "https://secret-new.example", "apis": ["/api/real/list", "/api/new/list"], "api_confidence": {"/api/new/list": 0.8}, "api_sources": {"/api/new/list": ["js-graph"]}}
        ]), encoding="utf-8")
        report = ds.compare_inventory_files(cur, old, include_samples=False)
        serialized = json.dumps(report, ensure_ascii=False)
        assert report["counts"]["common"] == 1, report
        assert report["counts"]["old_only"] == 3, report
        assert report["old_only_categories"]["dot_path_artifact"] == 1, report
        assert report["old_only_categories"]["swagger_openapi_doc"] == 1, report
        assert "secret-old.example" not in serialized and "secret-new.example" not in serialized, serialized
        assert "/foo.bar.baz" not in serialized and "/v2/api-docs" not in serialized, serialized


def test_validate_from_report_plan_and_local_active_redacted():
    Handler.hits = []
    server = LabServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            report = root / "report.json"
            report.write_text(json.dumps({"findings": [{"url": server.url, "findings": [{"url": server.url + "/api/real/list", "risk": "HIGH", "sample_urls": [server.url + "/api/real/list"]}]}]}), encoding="utf-8")
            out_plan = root / "plan"
            cmd = [sys.executable, str(SCANNER), "--validate-from-report", str(report), "--validate-plan-only", "--outdir", str(out_plan), "--no-proxy"]
            proc = subprocess.run(cmd, text=True, capture_output=True, timeout=60)
            if proc.returncode != 0:
                print(proc.stdout); print(proc.stderr); raise SystemExit(proc.returncode)
            plan = json.loads((out_plan / "validate_plan.json").read_text(encoding="utf-8"))
            assert plan["task_count"] == 1, plan
            assert server.url not in json.dumps(plan), plan
            assert "/api/real/list" not in json.dumps(plan), plan

            out_active = root / "active"
            cmd = [sys.executable, str(SCANNER), "--validate-from-report", str(report), "--outdir", str(out_active), "--workers", "50", "--no-proxy"]
            proc = subprocess.run(cmd, text=True, capture_output=True, timeout=80)
            if proc.returncode != 0:
                print(proc.stdout); print(proc.stderr); raise SystemExit(proc.returncode)
            summary = json.loads((out_active / "validate_report.json").read_text(encoding="utf-8"))
            assert summary["safety"]["redact_raw_findings"] is True, summary
            assert summary["safety"]["workers"] <= 4, summary
            serialized = json.dumps(summary, ensure_ascii=False)
            assert '"raw"' not in serialized, serialized[:1000]
            assert server.url not in serialized and "/api/real/list" not in serialized, serialized[:1000]
            assert summary["results"][0]["finding_count"] >= 1, summary
    finally:
        server.shutdown(); server.server_close()


def main():
    test_legacy_recovery_flag_low_confidence_only_when_enabled()
    test_inventory_diff_safe_aggregate_no_host_leak_and_artifact_categories()
    test_validate_from_report_plan_and_local_active_redacted()
    print("V26 LEGACY DIFF VALIDATE LAB PASS")


if __name__ == "__main__":
    main()
