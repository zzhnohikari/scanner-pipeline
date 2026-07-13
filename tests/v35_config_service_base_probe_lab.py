#!/usr/bin/env python3
"""End-to-end config service-base discovery and safe REST probing regression."""

import json
import re
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urljoin, urlparse

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from pipeline.js_extractor import build_js_graph


SCANNER = ROOT / "pipeline" / "deep_scanner.py"
PREFIX = "/synthetic-api/catalog"
SUFFIXES = ("", "/users", "/profile", "/list", "/page", "/all", "/tree", "/info")


class RecordingServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.hits = []

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}"


class QuietHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def send_body(self, body, content_type="application/json", status=200):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, value, status=200):
        self.send_body(json.dumps(value, ensure_ascii=False), status=status)


def frontend_handler(backend_port, cross_port):
    class FrontendHandler(QuietHandler):
        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path == "/":
                return self.send_body(
                    '<!doctype html><title>config base lab</title>'
                    '<div id="app"></div>'
                    '<script>window.USERURL="http://localhost:%d//synthetic-api/catalog";</script>'
                    '<script src="/assets/serverconfig.js?cache=secret-value#fragment"></script>'
                    '<script src="/assets/app.js"></script>'
                    '<a href="/subpage">settings</a>' % backend_port,
                    "text/html",
                )
            if parsed.path == "/assets/serverconfig.js":
                cross_bases = "\n".join(
                    'window.apiconfig.cross%02dUrl="http://127.0.0.1:%d/external%02d";'
                    % (index, cross_port, index)
                    for index in range(8)
                )
                return self.send_body(
                    'window.WORKURL="http://localhost:%d//synthetic-api/catalog/";\n%s\n'
                    % (backend_port, cross_bases),
                    "application/javascript",
                )
            if parsed.path == "/assets/app.js":
                dense = "\n".join('fetch("/dense/read/%d");' % index for index in range(60))
                return self.send_body(dense, "application/javascript")
            if parsed.path == "/subpage":
                return self.send_body(
                    '<script>window.ACCOUNTURL="http://localhost:%d//synthetic-api/catalog";</script>'
                    '<script src="/assets/subconfig.js?nonce=private"></script>'
                    '<div>subpage config service discovery padding for graph traversal</div>' % backend_port,
                    "text/html",
                )
            if parsed.path == "/assets/subconfig.js":
                return self.send_body(
                    'window.CATALOGAPIURL="http://localhost:%d//synthetic-api/catalog";' % backend_port,
                    "application/javascript",
                )
            return self.send_json({"code": 404, "message": "not found"}, status=404)

    return FrontendHandler


class BackendHandler(QuietHandler):
    def _record(self):
        parsed = urlparse(self.path)
        self.server.hits.append({
            "method": self.command,
            "path": parsed.path,
            "query": parsed.query,
            "content_length": int(self.headers.get("Content-Length", "0") or 0),
            "authorization": bool(self.headers.get("Authorization")),
        })
        return parsed

    def do_GET(self):
        parsed = self._record()
        if parsed.path == PREFIX + "/users":
            return self.send_json({"code": 0, "data": [{"userId": 7, "phone": "13800138007"}]})
        if parsed.path == PREFIX + "/profile":
            return self.send_json({"code": 0, "data": {"name": "operator", "address": "Nanjing"}})
        return self.send_json({
            "code": 0,
            "message": "No route " + parsed.path,
            "data": [{"kind": "stable-fallback"}],
        })

    def do_POST(self):
        self._record()
        return self.send_json({"code": 500, "message": "POST forbidden"}, status=500)


class CrossHostHandler(QuietHandler):
    def do_GET(self):
        self.server.hits.append({"method": self.command, "path": urlparse(self.path).path})
        return self.send_json({"code": 0, "data": [{"should": "never be requested"}]})


def run_scanner(target_file, outdir, extra):
    cmd = [
        "/usr/bin/python3", str(SCANNER),
        "--input", str(target_file),
        "--outdir", str(outdir),
        "--workers", "6",
        "--timeout", "3",
        "--phase3a-timeout", "60",
        "--rescue-timeout", "20",
        "--phase3b-layer-timeout", "30",
        "--no-proxy",
        "--disable-api-fuzz",
        "--disable-rescue-baseline",
        "--no-capture-finding-evidence",
        *extra,
    ]
    proc = subprocess.run(cmd, text=True, capture_output=True, timeout=180)
    if proc.returncode:
        print(proc.stdout)
        print(proc.stderr)
        raise AssertionError((proc.returncode, cmd))
    return proc


def test_graph_source_merging():
    page = "http://127.0.0.1:18080/"
    service = "http://127.0.0.1:18877/synthetic-api/catalog"
    documents = {
        page + "assets/serverconfig.js?cache=secret": 'window.WORKURL="%s";' % service,
        page + "subpage": (
            '<script>window.ACCOUNTURL="%s";</script>'
            '<script src="/assets/subconfig.js?nonce=private"></script>'
            '<div>padding for a subpage longer than one hundred bytes during graph traversal</div>' % service
        ),
        page + "assets/subconfig.js?nonce=private": 'window.CATALOGAPIURL="%s";' % service,
    }

    def extract_js(html, base):
        return {
            urljoin(base, match.group(1))
            for match in re.finditer(r'<script[^>]+src="([^"]+)"', html)
        }

    def fetch(url, max_size=500_000):
        body = documents.get(url, "")[:max_size]
        content_type = "text/html" if url.endswith("subpage") else "application/javascript"
        return (200, url, body, content_type) if body else (404, url, "", "text/plain")

    def merge_profile(dst, src):
        dst.update(src or {})
        return dst

    graph = build_js_graph(
        page_url=page,
        html=(
            '<script>window.USERURL="%s";</script>'
            '<script src="/assets/serverconfig.js?cache=secret"></script>'
            '<a href="/subpage">subpage</a>' % service
        ),
        fetch_text=fetch,
        extract_js_from_html=extract_js,
        extract_links_from_html=lambda _html, _base: [page + "subpage"],
        extract_apis=lambda _content: set(),
        extract_module_urls_from_content=lambda _content, _base: set(),
        extract_prefixes_from_content=lambda _content: set(),
        extract_param_profile=lambda _content: {},
        empty_param_profile=dict,
        merge_param_profiles=merge_profile,
        common_libs=re.compile(r"$^"),
        valid_sensitive_value=lambda _value: False,
    )
    assert len(graph.config_service_bases) == 1, graph.config_service_bases
    item = graph.config_service_bases[0]
    assert set(item["config_keys"]) == {"ACCOUNTURL", "CATALOGAPIURL", "USERURL", "WORKURL"}, item
    assert any(value.endswith("/subpage") for value in item["source_pages"]), item
    assert any(value.endswith("/assets/subconfig.js") for value in item["source_assets"]), item
    assert all("?" not in value and "#" not in value and "@" not in value for value in item["source_assets"]), item


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def assert_inventory_provenance(records, frontend_url, backend_url, cross_port, expect_candidates):
    front = next(record for record in records if record["base"] == frontend_url)
    assert front["config_service_base_count"] == 9, front
    bases = {item["url"]: item for item in front["config_service_bases"]}
    cross_urls = {
        "http://127.0.0.1:%d/external%02d" % (cross_port, index)
        for index in range(8)
    }
    assert cross_urls.issubset(bases), bases
    assert all(not bases[url]["active_eligible"] for url in cross_urls), bases
    work_base = backend_url + PREFIX
    assert work_base in bases, bases
    assert bases[work_base]["path_prefix"] == PREFIX, bases[work_base]
    assert set(bases[work_base]["config_keys"]) == {"ACCOUNTURL", "CATALOGAPIURL", "USERURL", "WORKURL"}, bases[work_base]
    assert bases[work_base]["source_asset"].endswith("/assets/serverconfig.js"), bases[work_base]
    assert "?" not in bases[work_base]["source_asset"] and "#" not in bases[work_base]["source_asset"], bases[work_base]
    if not expect_candidates:
        assert not any(record.get("config_rest_candidates") for record in records), records
        assert not any(record.get("config_service_synthetic") for record in records), records
        return
    backend = next(record for record in records if record["base"] == backend_url)
    assert backend["config_service_synthetic"] is True, backend
    candidates = {item["path"]: item for item in backend["config_rest_candidates"]}
    assert set(candidates) == {PREFIX + suffix for suffix in SUFFIXES}, candidates
    users = candidates[PREFIX + "/users"]
    assert users["source"] == "rest_convention" and users["confidence"] == 0.45, users
    assert users["config_service_prefix"] == PREFIX, users
    assert users["config_service_base"] == work_base, users
    assert set(users["config_keys"]) == {"ACCOUNTURL", "CATALOGAPIURL", "USERURL", "WORKURL"}, users
    assert users["config_source_asset"].endswith("/assets/serverconfig.js"), users


def main():
    test_graph_source_merging()
    backend = RecordingServer(("127.0.0.1", 0), BackendHandler)
    cross = RecordingServer(("127.0.0.1", 0), CrossHostHandler)
    frontend = RecordingServer(
        ("127.0.0.1", 0),
        frontend_handler(backend.server_address[1], cross.server_address[1]),
    )
    for server in (backend, cross, frontend):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            target_file = tmp / "targets.json"
            frontend_url = "http://localhost:%d" % frontend.server_address[1]
            backend_url = "http://localhost:%d" % backend.server_address[1]
            cross_port = cross.server_address[1]
            target_file.write_text(json.dumps([{"url": frontend_url, "title": "config-base"}]), encoding="utf-8")

            active_out = tmp / "active"
            active = run_scanner(target_file, active_out, [])
            assert "3a/config-rest: 8 safe GET tasks" in active.stdout, active.stdout[-4000:]
            inventory = read_jsonl(active_out / "phase2_inventory.jsonl")
            assert_inventory_provenance(inventory, frontend_url, backend_url, cross_port, expect_candidates=True)
            stream_paths = sorted(active_out.glob("phase2_full.jsonl*.config"))
            assert stream_paths, sorted(path.name for path in active_out.iterdir())
            assert_inventory_provenance(
                [
                    {**record, "config_service_base_count": len(record.get("config_service_bases") or [])}
                    for record in read_jsonl(stream_paths[-1])
                ],
                frontend_url,
                backend_url,
                cross_port,
                expect_candidates=True,
            )

            candidate_hits = [hit for hit in backend.hits if hit["path"] in {PREFIX + suffix for suffix in SUFFIXES}]
            assert len(candidate_hits) == 8, backend.hits
            assert {hit["path"] for hit in candidate_hits} == {PREFIX + suffix for suffix in SUFFIXES}, candidate_hits
            assert all(hit["method"] == "GET" for hit in backend.hits), backend.hits
            assert all(not hit["query"] and hit["content_length"] == 0 and not hit["authorization"] for hit in backend.hits), backend.hits
            controls = [hit for hit in backend.hits if hit["path"].startswith(PREFIX + "/__scanner_not_found_")]
            assert len(controls) == 2, backend.hits
            assert not cross.hits, cross.hits

            report = json.loads((active_out / "report.json").read_text(encoding="utf-8"))
            findings = [finding for target in report.get("findings", []) for finding in target.get("findings", [])]
            config_findings = {urlparse(item.get("url", "")).path: item for item in findings if item.get("discovery_source") == "rest_convention"}
            assert set(config_findings) == {PREFIX + "/users", PREFIX + "/profile"}, config_findings
            for finding in config_findings.values():
                assert finding["assessment"] == "exposure_candidate" and finding["confirmed"] is False, finding
                assert finding["config_service_prefix"] == PREFIX and finding["discovery_confidence"] == 0.45, finding
            assert not (active_out / "evidence").exists(), list(active_out.iterdir())

            backend.hits.clear()
            dry_out = tmp / "dry"
            run_scanner(target_file, dry_out, ["--dry-run"])
            dry_inventory = json.loads((dry_out / "apis.json").read_text(encoding="utf-8"))
            assert_inventory_provenance(dry_inventory, frontend_url, backend_url, cross_port, expect_candidates=True)
            assert [hit["path"] for hit in backend.hits] == ["/"], backend.hits

            for mode in ("inventory", "off"):
                backend.hits.clear()
                mode_out = tmp / mode
                run_scanner(target_file, mode_out, ["--dry-run", "--config-service-base-mode", mode])
                assert_inventory_provenance(
                    read_jsonl(mode_out / "phase2_inventory.jsonl"),
                    frontend_url,
                    backend_url,
                    cross_port,
                    expect_candidates=False,
                )
                assert not backend.hits, (mode, backend.hits)
                assert not cross.hits, cross.hits

        print("CONFIG SERVICE BASE PROBE LAB PASS")
    finally:
        for server in (frontend, backend, cross):
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
