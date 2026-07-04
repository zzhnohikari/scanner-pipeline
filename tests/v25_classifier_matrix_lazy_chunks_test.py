#!/usr/bin/env python3
"""v25 focused tests: classifier, lazy chunks, unauth matrix, rate limits."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "pipeline" / "deep_scanner.py"
sys.path.insert(0, str(ROOT))

from pipeline.classifier import classify_response
from pipeline.js_extractor import extract_lazy_chunk_urls


def load_scanner_module():
    old_argv = sys.argv[:]
    try:
        sys.argv = [str(SCANNER)]
        spec = importlib.util.spec_from_file_location("deep_scanner_v25", SCANNER)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        sys.argv = old_argv


def test_classifier():
    auth = classify_response(200, '{"code":401,"message":"请登录后再访问","data":[]}')
    assert auth["verdict"] == "auth_failed", auth
    assert "raw" not in auth and "body" not in auth, auth

    success = classify_response(200, json.dumps({
        "retCode": 0,
        "data": {"records": [{"phone": "13800138000", "idCard": "X", "address": "Nanjing"}], "total": 1},
    }))
    assert success["verdict"] == "success_data", success
    assert success["risk"] in ("HIGH", "CRITICAL"), success
    assert {"phone", "idCard", "address"} & set(success["sensitive_fields"]), success

    nested = classify_response(200, '{"status":{"code":200},"result":{"items":[{"accessToken":"x"}]}}')
    assert nested["verdict"] == "success_data", nested
    assert "accessToken" in nested["sensitive_fields"], nested


def test_lazy_chunk_extraction():
    base = "https://example.test/static/js/app.js"
    content = r'''
    __webpack_require__.u = function(e){ return {123:"user-center",456:"admin"}[e] + ".chunk.js"; };
    __webpack_require__.e(123).then(__webpack_require__.bind(__webpack_require__, 123));
    const __vite__fileDeps=["assets/lazy-a.abc.js","assets/lazy-b.def.css","/static/js/lazy-c.js"];
    __vite__mapDeps([0,2]);
    import("./views/profile.789.js");
    '''
    urls = extract_lazy_chunk_urls(content, base)
    joined = "\n".join(sorted(urls))
    assert "user-center.chunk.js" in joined, joined
    assert "admin.chunk.js" in joined, joined
    assert "assets/lazy-a.abc.js" in joined, joined
    assert "/static/js/lazy-c.js" in joined, joined
    assert "views/profile.789.js" in joined, joined


def test_matrix_builder():
    ds = load_scanner_module()
    profile = ds.empty_param_profile()
    ds.add_param_name(profile, "userId", "/api/user/detail", "query")
    ds.add_param_name(profile, "page", "/api/user/list", "json")
    preview = ds.build_unauth_matrix_preview("http://lab", ["/api/user/detail", "/api/user/list"], profile)
    by_path = {item["path"]: item for item in preview}
    assert by_path["/api/user/detail"]["active_probe"] is False, preview
    assert any(v["style"] == "query" and "userId" in v["param_names"] for v in by_path["/api/user/detail"]["variants"]), preview
    assert any(v["style"] == "json" and "page" in v["param_names"] for v in by_path["/api/user/list"]["variants"]), preview


class RateServer(ThreadingHTTPServer):
    request_times = []

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}"


class RateHandler(BaseHTTPRequestHandler):
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
        if self.path == "/" or self.path.startswith("/?"):
            return self.send_body('<script src="/app.js"></script>')
        if self.path == "/app.js":
            return self.send_body('fetch("/api/one");fetch("/api/two");fetch("/api/three");', "application/javascript")
        if self.path.startswith("/api/"):
            self.server.request_times.append(time.time())
            return self.send_body(json.dumps({"code": 0, "data": [{"phone": "13800138000"}]}), "application/json")
        return self.send_body("not found", status=404)

    def do_POST(self):
        return self.do_GET()


def test_rate_limit_cap_and_delay():
    RateServer.request_times = []
    server = RateServer(("127.0.0.1", 0), RateHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target_file = tmp / "targets.json"
            outdir = tmp / "out"
            target_file.write_text(json.dumps([{"url": server.url, "title": "rate", "score": 100}]), encoding="utf-8")
            cmd = [
                sys.executable, str(SCANNER), "--input", str(target_file), "--outdir", str(outdir),
                "--workers", "8", "--timeout", "3", "--no-proxy", "--fresh",
                "--phase3a-timeout", "40", "--phase3b-layer-timeout", "20",
                "--disable-rescue-baseline", "--max-requests-per-host", "2", "--min-delay-ms", "250",
            ]
            proc = subprocess.run(cmd, text=True, capture_output=True, timeout=90)
            if proc.returncode != 0:
                print(proc.stdout)
                print(proc.stderr)
                raise SystemExit(proc.returncode)
            times = list(server.request_times)
            assert len(times) <= 2, times
            if len(times) >= 2:
                assert times[1] - times[0] >= 0.20, times
    finally:
        server.shutdown()
        server.server_close()


def test_dry_run_matrix_and_lazy_stats():
    class Handler(RateHandler):
        def do_GET(self):
            if self.path == "/" or self.path.startswith("/?"):
                return self.send_body('<script src="/runtime.js"></script>')
            if self.path == "/runtime.js":
                return self.send_body('__webpack_require__.u=function(e){return {123:"lazy-user"}[e]+".js"};fetch("/api/user/list",{data:{userId:id}});', "application/javascript")
            if self.path == "/lazy-user.js":
                return self.send_body('fetch("/api/lazy/detail");', "application/javascript")
            return self.send_body("not found", status=404)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target_file = tmp / "targets.json"
            outdir = tmp / "out"
            target_file.write_text(json.dumps([{"url": base, "title": "lazy", "score": 100}]), encoding="utf-8")
            cmd = [sys.executable, str(SCANNER), "--input", str(target_file), "--outdir", str(outdir), "--workers", "4", "--timeout", "3", "--no-proxy", "--dry-run", "--unauth-matrix"]
            proc = subprocess.run(cmd, text=True, capture_output=True, timeout=80)
            if proc.returncode != 0:
                print(proc.stdout)
                print(proc.stderr)
                raise SystemExit(proc.returncode)
            data = json.loads((outdir / "apis.json").read_text(encoding="utf-8"))[0]
            assert data["lazy_chunks_discovered"] >= 1, data
            assert data["lazy_chunks_attempted"] >= 1, data
            assert data["lazy_chunks_downloaded"] >= 1, data
            assert data.get("unauth_matrix_preview"), data
            assert any(item["path"] == "/api/user/list" for item in data["unauth_matrix_preview"]), data["unauth_matrix_preview"]
            assert data.get("api_confidence", {}).get("/api/user/list", 0) >= 0.8, data.get("api_confidence")
            assert "js-graph" in data.get("api_sources", {}).get("/api/user/list", []), data.get("api_sources")
    finally:
        server.shutdown()
        server.server_close()


def main():
    test_classifier()
    test_lazy_chunk_extraction()
    test_matrix_builder()
    test_rate_limit_cap_and_delay()
    test_dry_run_matrix_and_lazy_stats()
    print("V25 CLASSIFIER MATRIX LAZY CHUNKS RATE LIMIT PASS")


if __name__ == "__main__":
    main()
