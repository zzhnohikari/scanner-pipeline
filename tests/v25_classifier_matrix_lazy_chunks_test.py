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


def test_webpack_runtime_chunk_hash_manifest_extraction():
    base = "https://example.test/deploy/static/js/runtime.123.js"
    content = r'''
    function f(c){
      return a.p+"static/js/"+({}[c]||c)+"."+{
        "chunk-2738fe2c":"a6ce7486",
        2738:"5582e5e3",
        chunkAdmin:"1122aabb"
      }[c]+".js"
    }
    '''
    urls = extract_lazy_chunk_urls(content, base)
    joined = "\n".join(sorted(urls))
    assert "https://example.test/deploy/static/js/chunk-2738fe2c.a6ce7486.js" in urls, joined
    assert "https://example.test/deploy/static/js/2738.5582e5e3.js" in urls, joined
    assert "https://example.test/deploy/static/js/chunkAdmin.1122aabb.js" in urls, joined
    assert "/static/js/static/js/" not in joined, joined
    assert "https://example.test/a6ce7486.js" not in urls, joined

    explicit_public_path = r'''
    a.p="/tenant/app/";
    function f(c){
      return a.p+"static/js/"+({17:"chunk-users"}[c]||c)+"."+{17:"facefeed"}[c]+".js"
    }
    '''
    explicit_urls = extract_lazy_chunk_urls(explicit_public_path, base)
    assert "https://example.test/tenant/app/static/js/chunk-users.facefeed.js" in explicit_urls, explicit_urls


def test_phase25_uses_full_stream_api_meta():
    ds = load_scanner_module()
    with tempfile.TemporaryDirectory() as tmp:
        outdir = Path(tmp)
        source = outdir / "phase2_full.jsonl"
        writer = ds._JsonlWriter(str(source))
        existing_many = [f"/api/base/{i:03d}" for i in range(60)]
        writer.write({
            "base": "http://swagger.test",
            "apis": ["/api/tenant/search"],
            "api_meta": {"/api/tenant/search": {"confidence": 0.95, "sources": ["swagger"]}},
            "js_count": 0,
            "param_profile": ds.empty_param_profile(),
        })
        writer.write({
            "base": "http://sparse.test",
            "apis": existing_many,
            "api_meta": {
                api: {"confidence": 0.35, "sources": ["baseline"]}
                for api in existing_many
            },
            "js_count": 0,
            "param_profile": ds.empty_param_profile(),
        })
        writer.write({
            "base": "http://sparse-small.test",
            "apis": list(ds.BASELINE_PATHS)[:3],
            "api_meta": {
                api: {"confidence": 0.35, "sources": ["baseline"]}
                for api in list(ds.BASELINE_PATHS)[:3]
            },
            "js_count": 0,
            "param_profile": ds.empty_param_profile(),
        })
        inventory_path = outdir / "phase2_inventory.jsonl"
        with inventory_path.open("w", encoding="utf-8") as fh:
            for item in ds.StreamedResultSet(str(source), writer.count):
                limit = 50 if item["base"] == "http://sparse.test" else None
                fh.write(json.dumps(ds.phase2_inventory_record(item, api_limit=limit), ensure_ascii=False) + "\n")
        stream = ds.StreamedResultSet(str(source), writer.count)
        result_path = ds._phase25_sparse_api_fuzz(
            str(source), stream, ["/api/fuzz-only"], str(outdir), "phase2_inventory.jsonl"
        )
        records = {item["base"]: item for item in ds.StreamedResultSet(result_path, 3)}
        assert "/api/fuzz-only" not in records["http://swagger.test"]["apis"], records
        sparse = records["http://sparse.test"]
        assert "/api/fuzz-only" in sparse["apis"], sparse
        assert sparse["api_meta"]["/api/fuzz-only"]["sources"] == ["api_fuzz"], sparse
        assert sparse["api_meta"]["/api/fuzz-only"]["confidence"] == 0.45, sparse
        small = records["http://sparse-small.test"]
        assert small["api_meta"]["/api/fuzz-only"]["sources"] == ["api_fuzz"], small
        assert small["api_meta"]["/api/fuzz-only"]["confidence"] == 0.45, small
        inventory = {
            item["base"]: item
            for item in (
                json.loads(line)
                for line in inventory_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            )
        }
        sparse_inv = inventory["http://sparse.test"]
        assert sparse_inv["api_count"] == 61, sparse_inv
        assert len(sparse_inv["apis"]) == 50, sparse_inv
        for api in sparse_inv["apis"]:
            assert sparse_inv["api_sources"][api], (api, sparse_inv)
            assert api in sparse_inv["api_confidence"], (api, sparse_inv)
        small_inv = inventory["http://sparse-small.test"]
        assert small_inv["api_count"] == len(small_inv["apis"]) == 4, small_inv
        assert "/api/fuzz-only" in small_inv["apis"], small_inv
        assert small_inv["api_sources"]["/api/fuzz-only"] == ["api_fuzz"], small_inv
        assert small_inv["api_confidence"]["/api/fuzz-only"] == 0.45, small_inv
        assert any(
            small_inv["api_sources"].get(api) == ["api_fuzz"]
            and small_inv["api_confidence"].get(api) == 0.45
            for api in small_inv["apis"]
        ), small_inv


def test_redirect_liveness_keeps_original_scope():
    class RedirectHandler(BaseHTTPRequestHandler):
        requested_paths = []

        def log_message(self, fmt, *args):
            return

        def do_GET(self):
            type(self).requested_paths.append(self.path)
            if self.path == "/outside":
                body = b"outside should not be fetched"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{self.server.server_address[1]}/outside")
            self.end_headers()

    RedirectHandler.requested_paths = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target_file = tmp / "targets.json"
            outdir = tmp / "out"
            target_file.write_text(json.dumps([{"url": base, "score": 100}]), encoding="utf-8")
            proc = subprocess.run([
                sys.executable, str(SCANNER), "--input", str(target_file), "--outdir", str(outdir),
                "--workers", "2", "--timeout", "2", "--no-proxy", "--dry-run",
                "--disable-api-fuzz", "--replay-scope", "none",
            ], text=True, capture_output=True, timeout=60)
            if proc.returncode != 0:
                print(proc.stdout)
                print(proc.stderr)
                raise SystemExit(proc.returncode)
            inventory = [
                json.loads(line)
                for line in (outdir / "phase2_inventory.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            assert "存活: 1" in proc.stdout, proc.stdout
            assert [item["base"] for item in inventory] == [base], inventory
            assert "/outside" not in RedirectHandler.requested_paths, RedirectHandler.requested_paths
    finally:
        server.shutdown()
        server.server_close()


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
                return self.send_body('<script src="/deploy/static/js/runtime.js"></script>')
            if self.path == "/deploy/static/js/runtime.js":
                return self.send_body(
                    'a.p="/deploy/";function u(c){return a.p+"static/js/"+({}[c]||c)+"."+{123:"abc12345"}[c]+".js"};'
                    'fetch("/api/user/list",{data:{userId:id}});',
                    "application/javascript",
                )
            if self.path == "/deploy/static/js/123.abc12345.js":
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
            assert "/api/lazy/detail" in data["apis"], data["apis"]
            assert data.get("unauth_matrix_preview"), data
            assert any(item["path"] == "/api/user/list" for item in data["unauth_matrix_preview"]), data["unauth_matrix_preview"]
            assert data.get("api_confidence", {}).get("/api/user/list", 0) >= 0.8, data.get("api_confidence")
            assert "js_request" in data.get("api_sources", {}).get("/api/user/list", []), data.get("api_sources")
    finally:
        server.shutdown()
        server.server_close()



class RedactHandler(RateHandler):
    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            return self.send_body('<script src="/app.js"></script>')
        if self.path == "/app.js":
            return self.send_body('axios.get("/api/pii", {params:{userId:1}});', "application/javascript")
        if self.path.startswith("/api/pii"):
            if "?" in self.path:
                return self.send_body(json.dumps({"code": 0, "data": [{"phone": "PII_MARKER_8675309", "address": "Redact Lab"}]}), "application/json")
            return self.send_body(json.dumps({"code": 401, "msg": "authentication required", "data": []}), "application/json")
        return self.send_body("not found", status=404)


def run_redact_scan(redact):
    server = ThreadingHTTPServer(("127.0.0.1", 0), RedactHandler)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        tmp_obj = tempfile.TemporaryDirectory()
        tmp = Path(tmp_obj.name)
        target_file = tmp / "targets.json"
        outdir = tmp / "out"
        target_file.write_text(json.dumps([{"url": base, "title": "redact", "score": 100}]), encoding="utf-8")
        cmd = [
            sys.executable, str(SCANNER), "--input", str(target_file), "--outdir", str(outdir),
            "--workers", "4", "--timeout", "3", "--no-proxy", "--fresh",
            "--phase3a-timeout", "40", "--phase3b-layer-timeout", "20", "--disable-rescue-baseline",
            "--max-requests-per-host", "100", "--phase12-workers", "2",
            "--phase3a-param-rescue", "--param-probe-mode", "broad",
        ]
        if redact:
            cmd.append("--redact-raw-findings")
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=90)
        if proc.returncode != 0:
            print(proc.stdout)
            print(proc.stderr)
            raise SystemExit(proc.returncode)
        return tmp_obj, outdir
    finally:
        server.shutdown()
        server.server_close()


def test_redact_raw_findings_removes_raw_and_pii_marker():
    scanner = load_scanner_module()
    scanner.args.redact_raw_findings = True
    original = {
        "url": "http://example.test/api/item?marker=value#fragment",
        "sample_urls": ["/api/item?first=value#one", "/api/item?second=value#two"],
        "raw": "private",
    }
    sanitized = scanner.maybe_redact_raw_findings(original)
    assert original["url"].endswith("#fragment") and "raw" in original, original
    assert sanitized == {
        "url": "http://example.test/api/item",
        "sample_urls": ["/api/item", "/api/item"],
    }, sanitized
    tmp_obj, outdir = run_redact_scan(redact=True)
    try:
        serialized = (outdir / "report.json").read_text(encoding="utf-8")
        markdown = (outdir / "report.md").read_text(encoding="utf-8")
        assert '"raw"' not in serialized, serialized[:1000]
        assert "PII_MARKER_8675309" not in serialized, serialized[:1000]
        assert "userId=" not in serialized and "userId=" not in markdown, (serialized[:1000], markdown[:1000])
        checkpoints = [p for p in outdir.glob("*.json") if p.name not in {"report.json", "apis.json"}]
        assert checkpoints, list(outdir.iterdir())
        for path in checkpoints:
            text = path.read_text(encoding="utf-8")
            assert '"raw"' not in text, path
            assert "PII_MARKER_8675309" not in text, path
            assert "userId=" not in text, path
        report = json.loads(serialized)
        finding = report["findings"][0]["findings"][0]
        assert finding.get("classifier_verdict"), finding
        assert finding.get("sensitive_fields") is not None, finding
    finally:
        tmp_obj.cleanup()


def test_raw_findings_compatibility_default_keeps_raw():
    tmp_obj, outdir = run_redact_scan(redact=False)
    try:
        serialized = (outdir / "report.json").read_text(encoding="utf-8")
        assert '"raw"' in serialized, serialized[:1000]
        assert "PII_MARKER_8675309" in serialized, serialized[:1000]
        report = json.loads(serialized)
        findings = [item for host in report.get("findings", []) for item in host.get("findings", [])]
        assert any("?" in url for item in findings for url in item.get("sample_urls", [])), findings
    finally:
        tmp_obj.cleanup()

def main():
    test_classifier()
    test_lazy_chunk_extraction()
    test_webpack_runtime_chunk_hash_manifest_extraction()
    test_phase25_uses_full_stream_api_meta()
    test_redirect_liveness_keeps_original_scope()
    test_matrix_builder()
    test_rate_limit_cap_and_delay()
    test_dry_run_matrix_and_lazy_stats()
    test_redact_raw_findings_removes_raw_and_pii_marker()
    test_raw_findings_compatibility_default_keeps_raw()
    print("V25 CLASSIFIER MATRIX LAZY CHUNKS RATE LIMIT PASS")


if __name__ == "__main__":
    main()
