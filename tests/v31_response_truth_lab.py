#!/usr/bin/env python3
"""v31 response-truth regression lab.

Covers classifier admission order, envelope-vs-record auth phrases, stable vs
unstable catch-all baselines, schema-v2 candidate/observation counters, public
download/swagger observations, and private data candidates.
"""

import json
import importlib.util
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "pipeline" / "deep_scanner.py"
sys.path.insert(0, str(ROOT))

from pipeline.classifier import classify_response


def load_scanner_module():
    old_argv = sys.argv[:]
    try:
        sys.argv = [str(SCANNER)]
        spec = importlib.util.spec_from_file_location("deep_scanner_v31_budget", SCANNER)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        sys.argv = old_argv


def test_classifier_matrix():
    assert classify_response(200, '{"code":401,"message":"请登录","data":[{"phone":"138"}]}')["verdict"] == "auth_failed"
    assert classify_response(500, '{"code":0,"data":[{"phone":"13800138000"}]}')["verdict"] == "http_error"
    assert classify_response(200, '{"code":500,"data":[{"phone":"13800138000"}]}')["verdict"] == "business_error"
    record = classify_response(200, json.dumps({"code": 0, "data": [{"message": "Access Denied for user X", "phone": "13800138000"}]}))
    assert record["verdict"] == "success_data" and "phone" in record["sensitive_fields"], record
    record_obj = classify_response(200, json.dumps({"code": 0, "data": {"message": "Access Denied for user X", "phone": "13800138000"}}))
    assert record_obj["verdict"] == "success_data" and "phone" in record_obj["sensitive_fields"], record_obj
    empty = classify_response(200, json.dumps({"code": 0, "data": {"phone": "", "token": "-", "idCard": None, "name": "demo"}}))
    assert empty["verdict"] == "success_data" and not empty["sensitive_fields"] and empty["risk"] != "HIGH", empty
    for payload in (
        {"code": 0, "msg": "ok"},
        {"code": 0, "data": [{"phone": None, "address": ""}]},
        {"code": 0, "data": [], "total": 0},
        {"success": True, "message": "ok"},
        {"code": 0, "data": False},
        {"data": {"message": "ok"}},
        {"data": [{"message": "Access denied"}]},
    ):
        result = classify_response(200, json.dumps(payload))
        assert result["verdict"] == "unknown" and not result["data_signals"], (payload, result)
    positive_record_message = classify_response(200, json.dumps({"data": [{"message": "Access Denied for user X", "phone": "13800138000"}]}))
    assert positive_record_message["verdict"] == "success_data" and "phone" in positive_record_message["sensitive_fields"], positive_record_message
    positive_zero = classify_response(200, json.dumps({"data": 0}))
    assert positive_zero["verdict"] == "success_data" and positive_zero["data_signals"].get("scalar"), positive_zero
    positive_data_scalar = classify_response(200, json.dumps({"data": "ok"}))
    assert positive_data_scalar["verdict"] == "success_data" and positive_data_scalar["data_signals"].get("scalar"), positive_data_scalar
    positive_scalar = classify_response(200, json.dumps({"code": 0, "Result": "ok"}))
    assert positive_scalar["verdict"] == "success_data" and positive_scalar["data_signals"].get("scalar"), positive_scalar
    positive_nested = classify_response(200, json.dumps({"code": 0, "Data": {"Rows": [{"phone": "13800138006"}]}}))
    assert positive_nested["verdict"] == "success_data" and "phone" in positive_nested["sensitive_fields"], positive_nested
    rows = classify_response(200, json.dumps({"Code": 0, "Data": {"Rows": [{"id": 1}]}}))
    assert rows["verdict"] == "success_data" and rows["data_signals"].get("container") == "Rows", rows
    scalar = classify_response(200, json.dumps({"code": 0, "Result": "ok"}))
    assert scalar["verdict"] == "success_data" and scalar["data_signals"].get("scalar"), scalar
    assert classify_response(200, '{"code":0,"data":[{"id":1}]}', catch_all_match=True)["verdict"] == "catch_all"


def test_check_response_uses_classifier_gate():
    mod = load_scanner_module()
    for payload in (
        {"code": 0, "data": False},
        {"code": 0, "msg": "ok"},
        {"code": 0, "data": [], "total": 0},
        {"code": 0, "data": {"token": None, "phone": ""}},
    ):
        body = json.dumps(payload)
        assert mod.check_response(body, "http://example.test/config-api/list", "GET", "truth", 200) is None, payload

    meaningful = mod.check_response(
        json.dumps({"code": 0, "data": [{"id": 1, "name": "record"}]}),
        "http://example.test/config-api/list",
        "GET",
        "truth",
        200,
    )
    assert meaningful and meaningful["assessment"] == "exposure_candidate", meaningful

    sensitive = mod.check_response(
        json.dumps({"code": 0, "message": "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.signature"}),
        "http://example.test/config-api/info",
        "GET",
        "truth",
        200,
    )
    assert sensitive and sensitive["classifier_verdict"] == "sensitive_signal", sensitive

    observation = mod.check_response("{}", "http://example.test/v3/api-docs", "GET", "truth", 200)
    assert observation and observation["assessment"] == "observation", observation
    assert not observation.get("data_count") and not observation.get("data_keys"), observation


def test_catch_all_path_echo_normalization_and_fail_closed():
    mod = load_scanner_module()

    def baseline_for(control_urls, content_type, body_for):
        fingerprints = [
            mod.catch_all_fingerprint(
                200,
                {"Content-Type": content_type},
                body_for(url),
                tokens=mod.catch_all_request_tokens(url),
            )
            for url in control_urls
        ]
        assert mod.catch_all_fingerprint_core(fingerprints[0]) == mod.catch_all_fingerprint_core(fingerprints[1]), fingerprints
        return {"fingerprint": fingerprints[0], "scope": "/config-api"}

    controls = [
        "http://example.test/config-api/__scanner_not_found_aaaaaaaa",
        "http://example.test/config-api/__scanner_not_found_bbbbbbbb",
    ]
    candidate = "http://example.test/config-api/list"

    json_body = lambda url: json.dumps({
        "code": 0,
        "message": "No route " + urlparse(url).path,
        "data": [{"item": "same"}],
    })
    json_baseline = baseline_for(controls, "application/json", json_body)
    assert mod.response_matches_catch_all(
        json_baseline,
        200,
        {"Content-Type": "application/json"},
        json_body(candidate),
        request_url_or_path=candidate,
    )

    text_body = lambda url: "No route " + url
    text_baseline = baseline_for(controls, "text/plain", text_body)
    assert mod.response_matches_catch_all(
        text_baseline,
        200,
        {"Content-Type": "text/plain"},
        text_body(candidate),
        request_url_or_path=candidate,
    )

    assert mod.catch_all_probe_allowed(None) is True
    assert mod.catch_all_probe_allowed(None, require_stable=True) is False
    attempts = []
    mod.get_catch_all_baseline = lambda *_args, **_kwargs: (None, "")
    mod.acquire_phase3_request_slot = lambda *_args, **_kwargs: attempts.append("slot") or (True, "")
    mod.scoped_urlopen = lambda *_args, **_kwargs: attempts.append("request")
    assert mod.test_api(
        "http://example.test",
        "/config-api/list",
        [("GET_no_auth", "GET", None, None, {})],
        allow_param_probe=False,
        require_stable_catch_all=True,
    ) == []
    assert attempts == [], attempts


class LabServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler):
        super().__init__(addr, handler)
        self.control_hits = []

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def send_body(self, body, content_type="application/json", status=200, headers=None):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, obj, status=200):
        return self.send_body(json.dumps(obj, ensure_ascii=False), "application/json", status=status)

    def stable_catch_all(self):
        return self.send_json({
            "code": 0,
            "message": "No route " + urlparse(self.path).path,
            "data": [{"item": "same"}],
        })

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/":
            js = """
            fetch("/api/stable-catch/list");
            fetch("/unstable-catch/list");
            fetch("/api/http500");
            fetch("/api/business500");
            fetch("/api/record-auth");
            fetch("/api/empty-sensitive");
            fetch("/api/case-rows");
            fetch("/api/scalar");
            fetch("/api/private/users");
            fetch("/api/empty-data-false");
            fetch("/api/empty-envelope");
            fetch("/api/empty-list");
            fetch("/v3/api-docs");
            fetch("/download/client.exe");
            """
            return self.send_body(f'<script>{js}</script>', "text/html")
        if path.startswith("/api/__scanner_not_found_"):
            self.server.control_hits.append(path)
            return self.stable_catch_all()
        if path.startswith("/unstable-catch/__scanner_not_found_"):
            self.server.control_hits.append(path)
            return self.send_json({"code": 0, "data": [{"nonce": str(time.time_ns())}]})
        if path == "/api/stable-catch/list":
            return self.stable_catch_all()
        if path == "/unstable-catch/list":
            return self.send_json({"code": 0, "data": [{"id": 7, "phone": "13800138001"}]})
        if path == "/api/http500":
            return self.send_json({"code": 0, "data": [{"phone": "13800138002"}]}, status=500)
        if path == "/api/business500":
            return self.send_json({"code": 500, "data": [{"phone": "13800138003"}], "message": "boom"})
        if path == "/api/record-auth":
            return self.send_json({"code": 0, "data": [{"message": "Access Denied for user alice", "phone": "13800138004"}]})
        if path == "/api/empty-sensitive":
            return self.send_json({"code": 0, "data": {"phone": "", "token": "-", "idCard": None, "name": "demo"}})
        if path == "/api/case-rows":
            return self.send_json({"Code": 0, "Data": {"Rows": [{"rowId": 1, "name": "row"}]}})
        if path == "/api/scalar":
            return self.send_json({"code": 0, "Result": "ok"})
        if path == "/api/private/users":
            return self.send_json({"code": 0, "data": [{"userId": 1, "phone": "13800138005", "address": "Nanjing"}]})
        if path == "/api/empty-data-false":
            return self.send_json({"code": 0, "data": False})
        if path == "/api/empty-envelope":
            return self.send_json({"code": 0, "msg": "ok"})
        if path == "/api/empty-list":
            return self.send_json({"code": 0, "data": [], "total": 0})
        if path == "/v3/api-docs":
            return self.send_json({"openapi": "3.0.0", "paths": {"/api/private/users": {"get": {"responses": {"200": {"description": "ok"}}}}}})
        if path == "/download/client.exe":
            return self.send_body(b"MZ" + b"0" * 4096, "application/x-msdownload", headers={"Content-Disposition": 'attachment; filename="client.exe"'})
        return self.send_json({"code": 404, "message": "not found", "path": path}, status=404)

    def do_POST(self):
        return self.do_GET()


def flatten_candidates(report):
    return [fi for host in report.get("findings", []) for fi in host.get("findings", [])]


def flatten_observations(report):
    return [fi for host in report.get("observations", []) for fi in host.get("observations", [])]


def test_scanner_lab():
    server = LabServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target_file = tmp / "targets.json"
            outdir = tmp / "out"
            target_file.write_text(json.dumps([{"url": server.url, "title": "v31", "score": 100}]), encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable, str(SCANNER),
                    "--input", str(target_file),
                    "--outdir", str(outdir),
                    "--workers", "4",
                    "--timeout", "3",
                    "--phase3a-timeout", "60",
                    "--phase3b-layer-timeout", "60",
                    "--disable-rescue-baseline",
                    "--disable-api-fuzz",
                    "--replay-scope", "none",
                    "--file-max-probes", "2",
                    "--no-proxy",
                    "--fresh",
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
            candidates = flatten_candidates(report)
            observations = flatten_observations(report)
            candidate_paths = {urlparse(fi.get("url", "")).path for fi in candidates}
            observation_paths = {urlparse(fi.get("url", "")).path for fi in observations}

            assert report["schema_version"] == 2, report
            assert report["vulnerable"] == 0, report
            assert report["candidate_targets"] == 1, report
            assert report["observation_targets"] == 1, report
            assert report["stats"]["confirmed_findings"] == 0, report["stats"]
            assert report["stats"]["exposure_candidates"] == len(candidates), report["stats"]
            assert report["stats"]["observations"] == len(observations), report["stats"]
            assert report["stats"]["catch_all_suppressed"] >= 1, report["stats"]

            assert "/api/stable-catch/list" not in candidate_paths, candidate_paths
            assert "/api/http500" not in candidate_paths, candidate_paths
            assert "/api/business500" not in candidate_paths, candidate_paths
            assert "/unstable-catch/list" in candidate_paths, candidate_paths
            assert "/api/record-auth" in candidate_paths, candidate_paths
            assert "/api/case-rows" in candidate_paths, candidate_paths
            assert "/api/scalar" in candidate_paths, candidate_paths
            assert "/api/private/users" in candidate_paths, candidate_paths
            assert "/api/empty-data-false" not in candidate_paths, candidate_paths
            assert "/api/empty-envelope" not in candidate_paths, candidate_paths
            assert "/api/empty-list" not in candidate_paths, candidate_paths
            assert "/v3/api-docs" in observation_paths, observation_paths
            assert "/download/client.exe" in observation_paths, observation_paths

            empty = [fi for fi in candidates if urlparse(fi.get("url", "")).path == "/api/empty-sensitive"]
            assert empty and empty[0].get("risk") != "HIGH" and not empty[0].get("sensitive_fields"), empty
            record = next(fi for fi in candidates if urlparse(fi.get("url", "")).path == "/api/record-auth")
            assert record.get("assessment") == "exposure_candidate" and record.get("confirmed") is False, record
            public = next(fi for fi in observations if urlparse(fi.get("url", "")).path == "/download/client.exe")
            assert public.get("assessment") == "observation" and public.get("public_download_intel"), public
            assert not any(urlparse(fi.get("url", "")).path == "/api/stable-catch/list" and fi.get("evidence_file") for fi in candidates), candidates
            assert len(server.control_hits) >= 2, server.control_hits
            print("V31 RESPONSE TRUTH LAB PASS")
    finally:
        server.shutdown()
        server.server_close()


def test_atomic_catch_all_budget_reservation():
    mod = load_scanner_module()
    assert mod.phase3_host_key("http://example.test:80/a") == mod.phase3_host_key("https://example.test:8443/b") == "example.test"
    mod.args.max_requests_per_host = 3
    mod.args.min_delay_ms = 0
    mod.args.max_rps_per_host = 0.0
    mod.PHASE3_RATE_STATE.clear()
    mod.CATCH_ALL_BASELINES.clear()
    for key in list(mod.CATCH_ALL_STATS.keys()):
        mod.CATCH_ALL_STATS[key] = 0

    class FakeResp:
        def __init__(self, url):
            self.url = url
            self.headers = {"Content-Type": "application/json"}
            self._body = json.dumps({"code": 0, "data": [], "path": urlparse(url).path}).encode()

        def getcode(self):
            return 200

        def read(self, _size=-1):
            body, self._body = self._body, b""
            return body

    attempts = []
    first_control_started = threading.Event()
    release_controls = threading.Event()
    attempt_lock = threading.Lock()

    def fake_urlopen(req, timeout=None, follow_redirects=True):
        url = getattr(req, "full_url", str(req))
        with attempt_lock:
            attempts.append(url)
        first_control_started.set()
        release_controls.wait(2)
        return FakeResp(url)

    mod.scoped_urlopen = fake_urlopen
    holder = {}
    base = "http://127.0.0.1:65530"

    def build_baseline():
        holder["result"] = mod.get_catch_all_baseline(base, "/api/real", "GET", {}, None)

    builder = threading.Thread(target=build_baseline)
    builder.start()
    assert first_control_started.wait(2), "first control was not attempted"

    noise_allowed = []
    def noisy_probe(idx):
        allowed, _reason = mod.acquire_phase3_request_slot(f"{base}/api/noise{idx}")
        if allowed:
            noise_allowed.append(idx)

    noise_threads = [threading.Thread(target=noisy_probe, args=(i,)) for i in range(12)]
    for thread in noise_threads:
        thread.start()
    for thread in noise_threads:
        thread.join()
    release_controls.set()
    builder.join(2)
    assert not builder.is_alive(), "baseline builder did not finish"

    baseline, probe_hold = holder.get("result", (None, ""))
    stats = dict(mod.CATCH_ALL_STATS)
    assert not noise_allowed, noise_allowed
    assert baseline and probe_hold, (baseline, probe_hold, stats)
    assert stats["catch_all_baseline_attempted"] == 1, stats
    assert stats["catch_all_baseline_stable"] == 1, stats
    assert stats["catch_all_baseline_skipped_budget"] == 0, stats
    allowed, reason = mod.acquire_phase3_request_slot(f"{base}/api/real", consume_probe_hold=True)
    assert allowed, reason
    host_state = mod.PHASE3_RATE_STATE[mod.phase3_host_key(base)]
    assert int(host_state.get("count") or 0) == 3, host_state
    assert int(host_state.get("reserved_controls") or 0) == 0, host_state
    assert int(host_state.get("probe_holds") or 0) == 0, host_state
    assert len(attempts) == 2, attempts
    assert len(attempts) + 1 <= 3, attempts

    # A later baseline with only the retained real-probe slot left must be
    # skipped, not partially built by consuming the final slot.
    skipped, skipped_hold = mod.get_catch_all_baseline(base, "/other/real", "GET", {}, None)
    assert skipped is None and not skipped_hold, (skipped, skipped_hold)
    assert mod.CATCH_ALL_STATS["catch_all_baseline_skipped_budget"] == 1, mod.CATCH_ALL_STATS
    assert len(attempts) == 2, attempts


def main():
    test_classifier_matrix()
    test_check_response_uses_classifier_gate()
    test_catch_all_path_echo_normalization_and_fail_closed()
    test_atomic_catch_all_budget_reservation()
    test_scanner_lab()


if __name__ == "__main__":
    main()
