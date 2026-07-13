#!/usr/bin/env python3
"""Local regression for large Vite bundles, truncation, and request priority."""

import gzip
import io
import json
import os
import copy
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "pipeline" / "deep_scanner.py"
sys.path.insert(0, str(ROOT))

from pipeline.js_extractor import build_js_graph  # noqa: E402
from pipeline.js_advanced_inventory import analyze_javascript_ast  # noqa: E402
from pipeline.path_safety import canonical_http_origin, canonical_page_api_path  # noqa: E402


RAW_SOURCE_MARKER = "V37_RAW_JS_SOURCE_MUST_NOT_PERSIST"
QUERY_MARKER = "V37_INTERNAL_QUERY_MUST_NOT_PERSIST"
TARGET_API = "/iot-api/sensors/overview"
GENERIC_API = "/telemetry-api/metrics/status"
NEGATIVE_ROUTE = "/rapid-route/ordinary"
NEGATIVE_METHOD_ROUTE = "/rapid-route/router-method"
LAZY_PATH = "/assets/feature-lazy.js"


def load_scanner():
    old_argv = sys.argv
    sys.argv = [str(SCANNER), "--no-proxy"]
    try:
        import pipeline.deep_scanner as scanner
        return scanner
    finally:
        sys.argv = old_argv


def make_main_bundle():
    routes = "\n".join(
        'const route%02d="/admin/user/ordinary-route-%02d";' % (index, index)
        for index in range(64)
    )
    prefix = routes + '\nconst retained="/api/retained-before-truncation";\nconst raw="%s";\n' % RAW_SOURCE_MARKER
    padding_size = 930_000 - len(prefix.encode("utf-8"))
    assert padding_size > 0
    padding_unit = "/*vite-pad*/\n"
    padding = padding_unit * ((padding_size // len(padding_unit)) + 1)
    linkage = '\nimport("%s?build=%s");\n' % (LAZY_PATH, QUERY_MARKER)
    bundle = prefix + padding + linkage + ("\n/*tail*/" * 12000)
    size = len(bundle.encode("utf-8"))
    assert 500_000 < size < 2 * 1024 * 1024, size
    assert bundle.index("import(") > 900_000, bundle.index("import(")
    return bundle


class LabServer(ThreadingHTTPServer):
    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.hits = []
        self.main_bundle = make_main_bundle()

    @property
    def url(self):
        return "http://127.0.0.1:%d" % self.server_address[1]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _fmt, *_args):
        return

    def send_body(self, body, content_type="text/plain", content_length=True, invalid_length=False, encoding=""):
        data = body if isinstance(body, bytes) else str(body).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        if content_length:
            self.send_header("Content-Length", "invalid" if invalid_length else str(len(data)))
        if encoding:
            self.send_header("Content-Encoding", encoding)
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        self.server.hits.append(self.path)
        parsed = urlparse(self.path)
        if parsed.path == "/":
            return self.send_body('<script type="module" src="/assets/main.js"></script>', "text/html")
        if parsed.path == "/assets/main.js":
            return self.send_body(self.server.main_bundle, "application/javascript")
        if parsed.path == LAZY_PATH:
            if parse_qs(parsed.query).get("build") != [QUERY_MARKER]:
                return self.send_body("missing", "text/plain")
            return self.send_body(
                'const ordinary="%s";const baseURL="/telemetry-api";const metricPath="metrics/status";'
                'n.get("%s");axios.get(metricPath);router.get("%s");'
                % (NEGATIVE_ROUTE, TARGET_API, NEGATIVE_METHOD_ROUTE),
                "application/javascript",
            )
        if parsed.path == "/missing-length.js":
            return self.send_body("z" * 20000, "application/javascript", content_length=False)
        if parsed.path == "/invalid-length.js":
            return self.send_body("z" * 20000, "application/javascript", invalid_length=True)
        if parsed.path == "/compressed-large.js":
            return self.send_body(gzip.compress(b"z" * 20000), "application/javascript", encoding="gzip")
        return self.send_body("not found")


def run_scan(scanner, server, outdir, js_max_bytes=None):
    target_file = outdir.parent / (outdir.name + "-targets.json")
    target_file.write_text(json.dumps([{"url": server.url + "/", "title": "v37", "score": 100}]), encoding="utf-8")
    cmd = [
        sys.executable, str(SCANNER), "--input", str(target_file), "--outdir", str(outdir),
        "--workers", "2", "--phase12-workers", "1", "--timeout", "2", "--phase2-timeout", "60",
        "--no-proxy", "--skip-port-probe", "--dry-run", "--disable-api-fuzz",
        "--js-ast-mode", "required", "--no-capture-finding-evidence",
    ]
    if js_max_bytes is not None:
        cmd.extend(["--js-max-bytes", str(js_max_bytes)])
    proc = subprocess.run(cmd, text=True, capture_output=True, timeout=90)
    if proc.returncode != 0:
        raise AssertionError("scanner failed rc=%d" % proc.returncode)
    inventory = [
        json.loads(line) for line in (outdir / "phase2_inventory.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    return next(item for item in inventory if item["base"].startswith(server.url))


def assert_default_large_bundle(scanner, server, tmp):
    outdir = tmp / "default"
    record = run_scan(scanner, server, outdir)
    assert TARGET_API in record["apis"], record["apis"][:10]
    assert GENERIC_API in record["apis"], record["apis"][:10]
    assert LAZY_PATH in {urlparse(hit).path for hit in server.hits}, server.hits
    assert "js_request" not in record["api_sources"][TARGET_API], record["api_sources"][TARGET_API]
    assert "js_request" in record["api_sources"][GENERIC_API], record["api_sources"][GENERIC_API]
    assert record["api_confidence"][TARGET_API] < 0.96, record["api_confidence"][TARGET_API]
    assert TARGET_API not in record["param_profile"]["api_methods"], record["param_profile"]["api_methods"]
    assert record["js_advanced_stats"]["content_truncated"] == 0, record["js_advanced_stats"]
    assert record["js_advanced_stats"]["js_max_bytes"] == 2 * 1024 * 1024, record["js_advanced_stats"]

    ordinary = "/admin/user/ordinary-route-00"
    assert ordinary in record["apis"], record["apis"][:20]
    assert "js_request" not in record["api_sources"][ordinary], record["api_sources"][ordinary]
    assert NEGATIVE_ROUTE in record["apis"], record["apis"][:20]
    assert "js_request" not in record["api_sources"][NEGATIVE_ROUTE], record["api_sources"][NEGATIVE_ROUTE]
    assert NEGATIVE_METHOD_ROUTE in record["apis"], record["apis"][:20]
    assert "js_request" not in record["api_sources"][NEGATIVE_METHOD_ROUTE], record["api_sources"][NEGATIVE_METHOD_ROUTE]
    assert -scanner.api_priority(ordinary)[0] > -scanner.api_priority(TARGET_API)[0]
    legacy_order = sorted(record["apis"], key=scanner.api_priority)
    assert legacy_order.index(TARGET_API) > 30, legacy_order.index(TARGET_API)

    api_meta = {
        api: {"confidence": record["api_confidence"][api], "sources": record["api_sources"][api]}
        for api in record["apis"]
    }
    seeds = scanner.phase3_seed_candidates({"apis": record["apis"], "api_meta": api_meta})
    assert TARGET_API in seeds, seeds[:40]
    assert GENERIC_API in seeds, seeds[:40]
    assert NEGATIVE_ROUTE not in seeds, seeds[:40]
    assert NEGATIVE_METHOD_ROUTE not in seeds, seeds[:40]
    assert "/iot-api" in scanner.normalize_api_prefixes(TARGET_API)
    assert "/telemetry-api" in scanner.normalize_api_prefixes(GENERIC_API)
    assert TARGET_API in scanner.extract_apis('const endpoint="%s";' % TARGET_API)
    assert GENERIC_API in scanner.extract_apis('const endpoint="%s";' % GENERIC_API)
    assert -scanner.api_priority(TARGET_API)[0] == 15, scanner.api_priority(TARGET_API)
    assert -scanner.api_priority(GENERIC_API)[0] == 15, scanner.api_priority(GENERIC_API)
    assert -scanner.api_priority(NEGATIVE_ROUTE)[0] == 0
    assert -scanner.api_priority(NEGATIVE_METHOD_ROUTE)[0] == 0

    dry = json.loads((outdir / "apis.json").read_text(encoding="utf-8"))[0]
    assert "js_request" not in dry.get("api_sources", {}).get(TARGET_API, []), dry.get("api_sources", {}).get(TARGET_API)
    persisted = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in outdir.rglob("*") if path.is_file()
    )
    assert RAW_SOURCE_MARKER not in persisted
    assert QUERY_MARKER not in persisted
    assert "_fetch_url" not in persisted
    assert "fetch(\"" not in persisted
    assert not (outdir / "evidence").exists(), list(outdir.iterdir())


def assert_truncated_run(scanner, server, tmp):
    before = len(server.hits)
    record = run_scan(scanner, server, tmp / "small", js_max_bytes=400000)
    new_hits = server.hits[before:]
    assert record["js_advanced_stats"]["content_truncated"] == 1, record["js_advanced_stats"]
    assert record["js_advanced_stats"]["ast_parse_errors"] == 0, record["js_advanced_stats"]
    assert record["js_advanced_stats"]["js_max_bytes"] == 400000, record["js_advanced_stats"]
    assert "/api/retained-before-truncation" in record["apis"], record["apis"]
    assert TARGET_API not in record["apis"], record["apis"]
    assert LAZY_PATH not in {urlparse(hit).path for hit in new_hits}, new_hits


def assert_http_bounds(scanner, server):
    for path in ("/missing-length.js", "/invalid-length.js", "/compressed-large.js"):
        status, _final, text, _content_type, metadata = scanner.http_get(
            server.url + path, max_size=4096, retries=0, include_metadata=True,
        )
        assert status == 200, path
        assert metadata["content_truncated"] is True, (path, metadata)
        assert len(text.encode("utf-8")) <= 4096, (path, len(text))

    class CountingResponse(io.BytesIO):
        def __init__(self, value):
            super().__init__(value)
            self.headers = {"Content-Type": "application/javascript"}
            self.returned = 0

        def read(self, size=-1):
            chunk = super().read(size)
            self.returned += len(chunk)
            return chunk

    response = CountingResponse(b"x" * 10000)
    _raw, body, _text, metadata = scanner.read_http_response(response, max_size=1024, include_metadata=True)
    assert response.returned == 1025, response.returned
    assert len(body) == 1024 and metadata["content_truncated"] is True


def assert_legacy_fetch_callback(scanner):
    calls = []

    def legacy_fetch(url, max_size=500000):
        calls.append((url, max_size))
        return 200, url, 'fetch("%s")' % TARGET_API, "application/javascript"

    graph = build_js_graph(
        page_url="http://example.test/",
        html='<script src="/legacy.js"></script>',
        fetch_text=legacy_fetch,
        extract_js_from_html=scanner.extract_js_from_html,
        extract_links_from_html=lambda _html, _base: set(),
        extract_apis=scanner.extract_apis,
        extract_module_urls_from_content=scanner.extract_module_urls_from_content,
        extract_prefixes_from_content=scanner.extract_prefixes_from_content,
        extract_param_profile=scanner.extract_param_profile,
        empty_param_profile=scanner.empty_param_profile,
        merge_param_profiles=scanner.merge_param_profiles,
        common_libs=scanner.COMMON_LIBS,
        valid_sensitive_value=scanner.valid_sensitive_value,
        ast_mode="off",
        import_maps=False,
        manifest_inventory=False,
        source_map_mode="off",
        js_max_bytes=8192,
    )
    endpoint = next(item for item in graph.apis if item.path == TARGET_API)
    assert endpoint.source == "js_request", endpoint
    assert graph.stats["content_truncated"] == 0, graph.stats
    assert calls == [("http://example.test/legacy.js", 8192)], calls

    calls.clear()
    zero_graph = build_js_graph(
        page_url="http://example.test/",
        html='<script src="/legacy.js"></script>',
        fetch_text=legacy_fetch,
        extract_js_from_html=scanner.extract_js_from_html,
        extract_links_from_html=lambda _html, _base: set(),
        extract_apis=scanner.extract_apis,
        extract_module_urls_from_content=scanner.extract_module_urls_from_content,
        extract_prefixes_from_content=scanner.extract_prefixes_from_content,
        extract_param_profile=scanner.extract_param_profile,
        empty_param_profile=scanner.empty_param_profile,
        merge_param_profiles=scanner.merge_param_profiles,
        common_libs=scanner.COMMON_LIBS,
        valid_sensitive_value=scanner.valid_sensitive_value,
        ast_mode="off",
        import_maps=False,
        manifest_inventory=False,
        source_map_mode="off",
        js_max_bytes=0,
    )
    assert zero_graph.stats["js_max_bytes"] == 2 * 1024 * 1024, zero_graph.stats
    assert calls == [("http://example.test/legacy.js", 2 * 1024 * 1024)], calls


def build_inline_graph(scanner, source, ast_mode="off", include_delete_method=False):
    no_fetch = lambda url, max_size=500000: (_ for _ in ()).throw(AssertionError("unexpected fetch " + url))
    return build_js_graph(
        page_url="http://example.test/",
        html="<script>%s</script>" % source,
        fetch_text=no_fetch,
        extract_js_from_html=scanner.extract_js_from_html,
        extract_links_from_html=lambda _html, _base: set(),
        extract_apis=scanner.extract_apis,
        extract_module_urls_from_content=scanner.extract_module_urls_from_content,
        extract_prefixes_from_content=scanner.extract_prefixes_from_content,
        extract_param_profile=scanner.extract_param_profile,
        empty_param_profile=scanner.empty_param_profile,
        merge_param_profiles=scanner.merge_param_profiles,
        common_libs=scanner.COMMON_LIBS,
        valid_sensitive_value=scanner.valid_sensitive_value,
        ast_mode=ast_mode,
        import_maps=False,
        manifest_inventory=False,
        source_map_mode="off",
        include_delete_method=include_delete_method,
    )


def assert_request_sink_matrix(scanner):
    positive = {
        "/sink/fetch", "/sink/window-fetch", "/sink/global-fetch", "/sink/axios",
        "/sink/axios-method", "/sink/request", "/sink/service", "/sink/http",
        "/sink/jquery-get", "/sink/jquery-ajax", "/sink/uni", "/sink/wx", "/sink/search",
    }
    ambiguous = {
        "/negative/myrequest", "/negative/customhttp", "/negative/microservice", "/negative/fakeaxios",
        "/negative/myrequest-get", "/negative/customhttp-get", "/negative/microservice-get", "/negative/fakeaxios-get",
        "/negative/request-factory", "/negative/member-request", "/negative/member-http",
        "/negative/member-service", "/negative/member-axios", "/negative/router-get",
        "/negative/map-get", "/negative/storage-get", "/negative/object-open", "/negative/literal",
        "/negative/spaced-request", "/negative/tight-spaced-request", "/negative/multiline-request",
        "/negative/member-jquery", "/negative/optional-request", "/negative/namespace-fetch",
        "/negative/domain-service", "/negative/model-client", "/negative/router-service",
        "/negative/cache-client", "/negative/user-service", "/negative/domain-post",
        "/negative/chained-client", "/negative/xhr-before-init", "/negative/model-before-init",
        "/negative/property-xhr", "/negative/client-bound", "/negative/client-before-bind",
        "/negative/client-before-reassign",
        "/negative/xhr-direct", "/negative/xhr-two-step", "/negative/xhr-before-reassign",
        "/negative/shadow-axios", "/negative/comment-block-member", "/negative/comment-line-member",
        "/negative/comment-before-dot", "/negative/comment-member-jquery",
        "/negative/comment-only", "/negative/string-only", "/negative/shadow-request",
        "/negative/client-after-reassign",
    }
    ambiguous_delete_only = {
        "/negative/xhr-after-reassign", "/negative/shadow-xhr",
    }
    direct_delete_only = {"/sink/delete-method", "/sink/delete-object"}
    positive_source = """
const ordinary = "/negative/literal";
fetch("/sink/fetch", {method:"GET"});
window.fetch("/sink/window-fetch", {method:"GET"});
globalThis.fetch("/sink/global-fetch", {method:"GET"});
axios("/sink/axios", {method:"GET"});
axios.get("/sink/axios-method");
request({url:"/sink/request", method:"GET"});
service("/sink/service", {method:"GET"});
http("/sink/http", {method:"GET"});
$.get("/sink/jquery-get");
$ . ajax({url:"/sink/jquery-ajax", method:"GET"});
uni . request({url:"/sink/uni"});
wx . request({url:"/sink/wx"});
service.post("/sink/search", {page:1});
axios.delete("/sink/delete-method");
request({url:"/sink/delete-object", method:"DELETE"});
"""
    negative_source = """
const ordinary = "/negative/literal";
const apiClient = axios.create({});
apiClient.get("/negative/client-bound");
lateClient.get("/negative/client-before-bind");
const lateClient = axios.create({});
let mutableClient = axios.create({});
mutableClient.post("/negative/client-before-reassign", {page:1});
mutableClient = otherClient;
mutableClient.delete("/negative/client-after-reassign");
const directXhr = new XMLHttpRequest();
directXhr.open("GET", "/negative/xhr-direct");
let twoStepXhr;
twoStepXhr = new XMLHttpRequest();
twoStepXhr.open("POST", "/negative/xhr-two-step");
let mutableXhr = new XMLHttpRequest();
mutableXhr.open("POST", "/negative/xhr-before-reassign");
mutableXhr = otherXhr;
mutableXhr.open("DELETE", "/negative/xhr-after-reassign");
myrequest("/negative/myrequest");
customhttp("/negative/customhttp");
microservice("/negative/microservice");
fakeaxios("/negative/fakeaxios");
myrequest.get("/negative/myrequest-get");
customhttp.get("/negative/customhttp-get");
microservice.get("/negative/microservice-get");
fakeaxios.get("/negative/fakeaxios-get");
requestFactory("/negative/request-factory");
holder.request("/negative/member-request");
holder.http("/negative/member-http");
holder.service("/negative/member-service");
holder.axios("/negative/member-axios");
object . request("/negative/spaced-request");
object. request("/negative/tight-spaced-request");
object
  .
  request("/negative/multiline-request");
object . $ . ajax({url:"/negative/member-jquery", method:"GET"});
object?.request("/negative/optional-request");
namespace . fetch("/negative/namespace-fetch");
object./*member*/request("/negative/comment-block-member");
object.// member
request("/negative/comment-line-member");
object /*member*/ . request("/negative/comment-before-dot");
object . /*member*/ $ . ajax({url:"/negative/comment-member-jquery", method:"POST"});
/* fetch("/negative/comment-only", {method:"POST"}); */
const stringSink = 'request({url:"/negative/string-only",method:"DELETE"})';
router.get("/negative/router-get");
map.get("/negative/map-get");
storage.get("/negative/storage-get");
domainService.get("/negative/domain-service");
modelClient.get("/negative/model-client");
router_service.get("/negative/router-service");
cacheClient.get("/negative/cache-client");
userService.get("/negative/user-service");
domainService.post("/negative/domain-post", {page:1});
namespace . apiClient . get("/negative/chained-client");
object.open("GET", "/negative/object-open");
lateXhr.open("GET", "/negative/xhr-before-init");
lateXhr = new XMLHttpRequest();
model.open("GET", "/negative/model-before-init");
model = new XMLHttpRequest();
holder.xhr = new XMLHttpRequest();
holder.xhr.open("GET", "/negative/property-xhr");
function nestedClients(axios, request) {
  axios.post("/negative/shadow-axios", {page:1});
  request({url:"/negative/shadow-request", method:"DELETE"});
}
function nestedXhr(directXhr) {
  directXhr.open("DELETE", "/negative/shadow-xhr");
}
"""
    positive_graph = build_inline_graph(scanner, positive_source)
    negative_graph = build_inline_graph(scanner, negative_source)
    positive_endpoints = {item.path: item for item in positive_graph.apis}
    negative_endpoints = {item.path: item for item in negative_graph.apis}
    assert positive <= set(positive_endpoints), sorted(positive - set(positive_endpoints))
    assert ambiguous <= set(negative_endpoints), sorted(ambiguous - set(negative_endpoints))
    assert not (ambiguous_delete_only & set(negative_endpoints)), ambiguous_delete_only & set(negative_endpoints)
    assert not (direct_delete_only & set(positive_endpoints)), direct_delete_only & set(positive_endpoints)
    assert all(positive_endpoints[path].source == "js_request" and positive_endpoints[path].confidence >= 0.96 for path in positive), positive_endpoints
    assert all(negative_endpoints[path].source != "js_request" and negative_endpoints[path].confidence < 0.96 for path in ambiguous), negative_endpoints

    ast_positive = {item.path: item for item in build_inline_graph(scanner, positive_source, ast_mode="required").apis}
    ast_source = negative_source.replace('object?.request("/negative/optional-request");', '')
    ast_endpoints = {item.path: item for item in build_inline_graph(scanner, ast_source, ast_mode="required").apis}
    ast_negative = ambiguous - {"/negative/optional-request"}
    assert all(ast_positive[path].source == "js_request" and ast_positive[path].confidence >= 0.96 for path in positive), ast_positive
    assert ast_negative <= set(ast_endpoints), sorted(ast_negative - set(ast_endpoints))
    assert not (ambiguous_delete_only & set(ast_endpoints)), ambiguous_delete_only & set(ast_endpoints)
    assert all(ast_endpoints[path].source != "js_request" and ast_endpoints[path].confidence < 0.96 for path in ast_negative), ast_endpoints

    methods = positive_graph.param_profile["api_methods"]
    for path in positive - {"/sink/search"}:
        assert "get" in methods.get(path, set()), (path, methods.get(path))
    assert methods.get("/sink/search") == {"post"}, methods.get("/sink/search")
    explicit_positive = scanner.explicit_js_method_map(positive_source)
    for path in {"/sink/fetch", "/sink/window-fetch", "/sink/global-fetch", "/sink/axios-method"}:
        assert explicit_positive.get(path) == {"get"}, (path, explicit_positive.get(path))
    assert explicit_positive.get("/sink/search") == {"post"}, explicit_positive.get("/sink/search")
    scheduled_post = scanner.scheduled_bypass_tests("/sink/search", scanner.FAST_BYPASS, positive_graph.param_profile)
    assert scheduled_post and {item[1] for item in scheduled_post} == {"POST"}, scheduled_post
    negative_methods = negative_graph.param_profile["api_methods"]
    assert not (ambiguous & set(negative_methods)), {path: negative_methods[path] for path in ambiguous & set(negative_methods)}
    explicit_negative = scanner.explicit_js_method_map(negative_source)
    assert not (ambiguous & set(explicit_negative)), {path: explicit_negative[path] for path in ambiguous & set(explicit_negative)}
    assert all(explicit_negative.get(path) == {"delete"} for path in ambiguous_delete_only), explicit_negative
    enabled_negative = build_inline_graph(scanner, negative_source, include_delete_method=True)
    enabled_endpoints = {item.path: item for item in enabled_negative.apis}
    assert ambiguous_delete_only <= set(enabled_endpoints), sorted(ambiguous_delete_only - set(enabled_endpoints))
    assert all(enabled_endpoints[path].source != "js_request" for path in ambiguous_delete_only), enabled_endpoints
    for path in ambiguous_delete_only:
        assert enabled_negative.param_profile["api_methods"].get(path) == {"delete"}, (path, enabled_negative.param_profile["api_methods"].get(path))
        assert scanner.scheduled_bypass_tests(path, scanner.FAST_BYPASS, enabled_negative.param_profile) == [], path
    scheduled_unknown = scanner.scheduled_bypass_tests("/negative/literal", scanner.FAST_BYPASS, negative_graph.param_profile)
    assert scheduled_unknown and {item[1] for item in scheduled_unknown} == {"GET"}, scheduled_unknown
    scheduled_false_post = scanner.scheduled_bypass_tests("/negative/domain-post", scanner.FAST_BYPASS, negative_graph.param_profile)
    assert scheduled_false_post and {item[1] for item in scheduled_false_post} == {"GET"}, scheduled_false_post
    actual_request = {path for path, endpoint in positive_endpoints.items() if endpoint.source == "js_request"}
    assert actual_request == positive, (sorted(actual_request - positive), sorted(positive - actual_request))

    ordinary = ["/admin/user/priority-%02d" % index for index in range(40)]
    matrix_paths = sorted(positive | ambiguous | ambiguous_delete_only)
    api_meta = {
        path: {
            "confidence": (positive_endpoints.get(path) or negative_endpoints.get(path) or enabled_endpoints[path]).confidence,
            "sources": [(positive_endpoints.get(path) or negative_endpoints.get(path) or enabled_endpoints[path]).source],
        } for path in matrix_paths
    }
    api_meta.update({path: {"confidence": 0.8, "sources": ["js-graph"]} for path in ordinary})
    seeded = scanner.phase3_seed_candidates({"apis": ordinary + matrix_paths, "api_meta": api_meta})
    assert positive <= set(seeded), sorted(positive - set(seeded))
    assert not ((ambiguous | ambiguous_delete_only) & set(seeded)), (ambiguous | ambiguous_delete_only) & set(seeded)

    quota_paths = ["/sink/quota-%02d" % index for index in range(20)]
    quota_source = "\n".join('fetch("%s");' % path for path in quota_paths)
    quota_graph = build_inline_graph(scanner, quota_source)
    quota_endpoints = {item.path: item for item in quota_graph.apis}
    assert all(quota_endpoints[path].source == "js_request" for path in quota_paths), quota_endpoints
    quota_meta = {
        path: {"confidence": quota_endpoints[path].confidence, "sources": [quota_endpoints[path].source]}
        for path in quota_paths
    }
    quota_target = {"apis": ordinary + quota_paths + [quota_paths[0] + "?duplicate=1"], "api_meta": quota_meta}
    first = scanner.phase3_seed_candidates(quota_target)
    second = scanner.phase3_seed_candidates(quota_target)
    selected = {path.split("?", 1)[0] for path in first} & set(quota_paths)
    assert first == second, (first, second)
    assert len(selected) == 16, selected
    assert len([path for path in first if path.split("?", 1)[0] in quota_paths]) == 16, first


def assert_lexically_honest_method_options(scanner):
    retained = {
        "/method/string-fetch", "/method/cache-string", "/method/model-string",
        "/method/block-comment", "/method/line-comment", "/method/plain-options",
        "/method/nested-unrelated", "/method/unrelated-array",
        "/method/unrelated-call",
    }
    proven_get = {
        "/method/shared", "/method/window-shared", "/method/global-shared",
        "/method/duplicate-last-get",
    }
    delete_only = {
        "/method/actual-delete", "/method/actual-type-delete", "/method/quoted-delete",
        "/method/computed-delete", "/method/spread-delete", "/method/duplicate-last-delete",
        "/method/xhr-delete",
    }
    ambiguous_options = {
        "/method/sibling-expression", "/method/let-method", "/method/var-method",
        "/method/shadowed-const", "/method/inner-shadow", "/method/cross-scope",
        "/method/late-const", "/method/reassigned-const", "/method/unknown-spread",
        "/method/constant-delete", "/method/constant-get", "/method/arrow-shadow",
        "/method/comma-declarator", "/method/nested-block-const",
    }
    source = r'''
const M = "DELETE";
fetch("/method/string-fetch", {note:"method: DELETE"});
cache.get("/method/cache-string", {note:"type: DELETE"});
model.request({url:"/method/model-string", note:"method: DELETE"});
fetch("/method/block-comment", {/* method: "DELETE", */ note:true});
fetch("/method/line-comment", {// type: "DELETE",
  note:true});
fetch("/method/plain-options", {cache:"no-store"});
fetch("/method/nested-unrelated", {meta:{method:"DELETE"}});
fetch("/method/unrelated-array", {method:"POST", meta:[{method:"DELETE"}], body:JSON.stringify({recordId:1})});
fetch("/method/unrelated-call", {meta:buildMetadata(), cache:["x"]});
fetch("/method/actual-delete", {method:"DELETE"});
fetch("/method/actual-type-delete", {type:"DELETE"});
fetch("/method/quoted-delete", {"method":"DELETE"});
fetch("/method/computed-delete", {["method"]:"DELETE"});
fetch("/method/spread-delete", {...{method:"DELETE"}});
fetch("/method/duplicate-last-delete", {method:"GET", method:"DELETE"});
fetch("/method/duplicate-last-get", {method:"DELETE", method:"GET"});
fetch("/method/constant-delete", {method:M, body:JSON.stringify({deleteId:1})});
const G = "GET";
fetch("/method/constant-get", {method:G, body:JSON.stringify({lookupId:1})});
fetch("/method/late-const", {method:LATE, body:JSON.stringify({lateId:1})});
const LATE = "GET";
const REASSIGNED = "DELETE";
REASSIGNED = "GET";
fetch("/method/reassigned-const", {method:REASSIGNED, body:JSON.stringify({reassignedId:1})});
fetch("/method/sibling-expression", choose({method:"GET"}, {method:"DELETE"}));
let mutableMethod = "GET";
mutableMethod = "DELETE";
fetch("/method/let-method", {method:mutableMethod});
var varMethod = "DELETE";
fetch("/method/var-method", {method:varMethod});
const shadowMethod = "DELETE";
function shadowed(shadowMethod) { fetch("/method/shadowed-const", {method:shadowMethod}); }
const INNER = "DELETE";
function innerShadow() { const INNER = "GET"; fetch("/method/inner-shadow", {method:INNER}); }
const CROSS = "GET";
function crossScope() { fetch("/method/cross-scope", {method:CROSS}); }
const ARROW_METHOD = "GET";
const arrowShadow = (ARROW_METHOD) => fetch("/method/arrow-shadow", {method:ARROW_METHOD});
const COMMA_METHOD = "DELETE", commaMarker = 1;
fetch("/method/comma-declarator", {method:COMMA_METHOD});
const BLOCK_METHOD = "GET";
{ fetch("/method/nested-block-const", {method:BLOCK_METHOD}); }
fetch("/method/unknown-spread", {...runtimeOptions});
let methodXhr = new XMLHttpRequest();
methodXhr.open("DELETE", "/method/xhr-delete");
const shared = "/method/shared";
cache.delete(shared);
fetch(shared);
const windowShared = "/method/window-shared";
cache.delete(windowShared);
window.fetch(windowShared);
const globalShared = "/method/global-shared";
cache.delete(globalShared);
globalThis.fetch(globalShared);
'''
    default_graph = build_inline_graph(scanner, source)
    default_endpoints = {item.path: item for item in default_graph.apis}
    assert retained | proven_get <= set(default_endpoints), sorted((retained | proven_get) - set(default_endpoints))
    assert not (delete_only & set(default_endpoints)), delete_only & set(default_endpoints)
    assert not (ambiguous_options & set(default_endpoints)), ambiguous_options & set(default_endpoints)
    for path in retained:
        assert "delete" not in default_graph.param_profile["api_methods"].get(path, set()), (path, default_graph.param_profile["api_methods"].get(path))
    for path in proven_get:
        assert default_endpoints[path].source == "js_request", default_endpoints[path]
        assert "get" in default_graph.param_profile["api_methods"].get(path, set()), (path, default_graph.param_profile["api_methods"].get(path))
        scheduled = scanner.scheduled_bypass_tests(path, scanner.FAST_BYPASS, default_graph.param_profile)
        assert scheduled and {item[1] for item in scheduled} == {"GET"}, (path, scheduled)

    explicit, blocked = scanner.explicit_js_method_map(source, return_blocked=True)
    for path in retained:
        assert "delete" not in explicit.get(path, set()), (path, explicit.get(path))
    for path in proven_get:
        assert "get" in explicit.get(path, set()), (path, explicit.get(path))
    assert all(explicit.get(path) == {"delete"} for path in delete_only), explicit
    assert not (ambiguous_options & set(explicit)), {path: explicit[path] for path in ambiguous_options & set(explicit)}
    assert ambiguous_options <= blocked, sorted(ambiguous_options - blocked)
    body_sources = scanner._extract_url_body_sources(source)
    unrelated = [item for item in body_sources if item[0] == "/method/unrelated-array"]
    assert unrelated and unrelated[0][2] == "json" and "recordId" in unrelated[0][1], unrelated
    blocked_body_paths = {
        "/method/constant-delete", "/method/constant-get", "/method/late-const",
        "/method/reassigned-const",
    }
    assert not (blocked_body_paths & {item[0] for item in body_sources}), body_sources

    ast_graph = build_inline_graph(scanner, source, ast_mode="required")
    ast_endpoints = {item.path: item for item in ast_graph.apis}
    assert retained | proven_get <= set(ast_endpoints), sorted((retained | proven_get) - set(ast_endpoints))
    assert not (delete_only & set(ast_endpoints)), delete_only & set(ast_endpoints)
    assert not (ambiguous_options & set(ast_endpoints)), ambiguous_options & set(ast_endpoints)
    assert all(ast_endpoints[path].source == "js_request" for path in proven_get), ast_endpoints

    seed_target = {
        "apis": sorted(default_endpoints),
        "api_meta": {
            path: {"sources": [endpoint.source], "confidence": endpoint.confidence}
            for path, endpoint in default_endpoints.items()
        },
    }
    seeded = {path.split("?", 1)[0] for path in scanner.phase3_seed_candidates(seed_target)}
    assert not (ambiguous_options & seeded), ambiguous_options & seeded

    included = build_inline_graph(scanner, source, ast_mode="required", include_delete_method=True)
    included_endpoints = {item.path: item for item in included.apis}
    assert delete_only <= set(included_endpoints), sorted(delete_only - set(included_endpoints))
    assert not (ambiguous_options & set(included_endpoints)), ambiguous_options & set(included_endpoints)
    for path in delete_only:
        assert included.param_profile["api_methods"].get(path) == {"delete"}, (path, included.param_profile["api_methods"].get(path))
        assert scanner.scheduled_bypass_tests(path, scanner.FAST_BYPASS, included.param_profile) == [], path


def assert_callee_proven_method_contract(scanner):
    active = {
        "/callee/users/page": "post",
        "/callee/users/list": "get",
        "/callee/audit/search": "put",
        "/callee/factory/page": "post",
    }
    delete_only = "/callee/users/delete"
    blocked = {"/callee/generic-fetch", "/callee/generic-request"}
    factory_blocked = {
        "/callee/factory-before-bind", "/callee/factory-reassigned", "/callee/factory-shadowed",
        "/callee/concise-arrow-shadow", "/callee/destructured-arrow-shadow",
        "/callee/object-method-shadow", "/callee/class-method-shadow", "/callee/catch-shadow",
        "/callee/for-of-shadow", "/callee/destructured-local", "/callee/local-axios-shadow",
        "/callee/mutated-axios", "/callee/case-mismatch", "/callee/conditional-factory",
        "/callee/mutate-or", "/callee/mutate-and", "/callee/mutate-xor",
        "/callee/mutate-shift-left", "/callee/mutate-shift-right", "/callee/mutate-shift-unsigned",
        "/callee/mutate-logical-and", "/callee/mutate-logical-or", "/callee/mutate-nullish",
    }
    body_noise = {"/callee/domain-noise", "/callee/myhttp-noise"}
    source = r'''
axios.post("/callee/users/page", {method:"DELETE", page:1, size:20});
axios.get("/callee/users/list", {method:"DELETE", page:1});
service.put("/callee/audit/search", {type:"DELETE", keyword:"x"});
axios.delete("/callee/users/delete", {method:"GET", id:1});
var http = axios.create({baseURL:"/api/v1"});
http.post("/callee/factory/page", {method:"DELETE", page:1, size:20});
const METHOD = "POST";
fetch("/callee/generic-fetch", {method:METHOD, body:JSON.stringify({page:1})});
request("/callee/generic-request", {method:METHOD, data:{page:1}});
domainService.post("/callee/untrusted/page", {method:"GET", page:1});
'''
    unsafe_factory_source = r'''
http.post("/callee/factory-before-bind", {page:1});
var http = axios.create({});
var service = axios.create({});
service = otherService;
service.post("/callee/factory-reassigned", {page:1});
var request = axios.create({});
function shadowedFactory(request) { request.post("/callee/factory-shadowed", {page:1}); }
const concise = http => http.post("/callee/concise-arrow-shadow", {page:1});
const destructured = ({http}) => http.post("/callee/destructured-arrow-shadow", {page:1});
const objectMethods = { run(http) { http.post("/callee/object-method-shadow", {page:1}); } };
class FactoryClass { run(http) { http.post("/callee/class-method-shadow", {page:1}); } }
try { work(); } catch (http) { http.post("/callee/catch-shadow", {page:1}); }
for (const http of clients) { http.post("/callee/for-of-shadow", {page:1}); }
const {http: destructuredHttp} = clients;
destructuredHttp.post("/callee/destructured-local", {page:1});
function localAxios(axios) { http.post("/callee/local-axios-shadow", {page:1}); }
axios = otherAxios;
http.post("/callee/mutated-axios", {page:1});
HTTP.post("/callee/case-mismatch", {page:1});
if (enabled) var service = axios.create({});
service.post("/callee/conditional-factory", {page:1});
http |= other; http.post("/callee/mutate-or", {page:1});
http &= other; http.post("/callee/mutate-and", {page:1});
http ^= other; http.post("/callee/mutate-xor", {page:1});
http <<= 1; http.post("/callee/mutate-shift-left", {page:1});
http >>= 1; http.post("/callee/mutate-shift-right", {page:1});
http >>>= 1; http.post("/callee/mutate-shift-unsigned", {page:1});
http &&= other; http.post("/callee/mutate-logical-and", {page:1});
http ||= other; http.post("/callee/mutate-logical-or", {page:1});
http ??= other; http.post("/callee/mutate-nullish", {page:1});
domainService.post("/callee/domain-noise", {page:1});
myhttp.post("/callee/myhttp-noise", {page:1});
'''
    for mode in ("off", "required"):
        graph = build_inline_graph(scanner, source, ast_mode=mode)
        endpoints = {item.path: item for item in graph.apis}
        assert set(active) <= set(endpoints), (mode, sorted(set(active) - set(endpoints)))
        assert delete_only not in endpoints, (mode, endpoints.get(delete_only))
        assert not (blocked & set(endpoints)), (mode, blocked & set(endpoints))
        assert all(endpoints[path].source == "js_request" for path in active), (mode, endpoints)
        assert endpoints["/callee/untrusted/page"].source != "js_request", (mode, endpoints["/callee/untrusted/page"])
        for path, method in active.items():
            assert graph.param_profile["api_methods"].get(path) == {method}, (
                mode, path, graph.param_profile["api_methods"].get(path),
            )
        assert "/callee/untrusted/page" not in graph.param_profile["api_methods"], (
            mode, graph.param_profile["api_methods"],
        )
        assert not (blocked & set(graph.param_profile["api_methods"])), (
            mode, graph.param_profile["api_methods"],
        )
        unsafe_graph = build_inline_graph(scanner, unsafe_factory_source, ast_mode=mode)
        unsafe_endpoints = {item.path: item for item in unsafe_graph.apis}
        assert factory_blocked | body_noise <= set(unsafe_endpoints), (
            mode, (factory_blocked | body_noise) - set(unsafe_endpoints),
        )
        assert all(unsafe_endpoints[path].source != "js_request" for path in factory_blocked), (
            mode, unsafe_endpoints,
        )
        assert not ((factory_blocked | body_noise) & set(unsafe_graph.param_profile["api_methods"])), (
            mode, unsafe_graph.param_profile["api_methods"],
        )

    explicit, explicit_blocked = scanner.explicit_js_method_map(source, return_blocked=True)
    assert all(explicit.get(path) == {method} for path, method in active.items()), explicit
    assert explicit.get(delete_only) == {"delete"}, explicit
    assert blocked <= explicit_blocked and not (blocked & set(explicit)), (explicit, explicit_blocked)
    assert "/callee/untrusted/page" not in explicit, explicit
    unsafe_explicit = scanner.explicit_js_method_map(unsafe_factory_source)
    assert not ((factory_blocked | body_noise) & set(unsafe_explicit)), unsafe_explicit
    unsafe_bodies = {item[0] for item in scanner._extract_url_body_sources(unsafe_factory_source)}
    assert not ((factory_blocked | body_noise) & unsafe_bodies), unsafe_bodies
    unsafe_profile = scanner.extract_param_profile(unsafe_factory_source)
    assert not ((factory_blocked | body_noise) & set(unsafe_profile["api_params"])), unsafe_profile["api_params"]
    for path in factory_blocked | body_noise:
        scheduled = scanner.scheduled_bypass_tests(path, scanner.FAST_BYPASS, unsafe_profile)
        assert not scheduled or {item[1] for item in scheduled} == {"GET"}, (path, scheduled)
    unsafe_meta = {
        path: {"sources": ["js-graph"], "confidence": 0.8}
        for path in factory_blocked | body_noise
    }
    padding = ["/ordinary/padding-%02d" % index for index in range(40)]
    unsafe_seed = scanner.phase3_seed_candidates({
        "apis": padding + sorted(factory_blocked | body_noise),
        "api_meta": unsafe_meta,
    })
    assert not ((factory_blocked | body_noise) & set(unsafe_seed)), unsafe_seed

    ast_only = analyze_javascript_ast(
        source,
        "http://example.test/app.js",
        "http://example.test/",
        mode="required",
        limits={"max_bytes": 200000, "max_nodes": 10000, "max_depth": 64, "max_expressions": 3000},
    )
    ast_methods = {(item["path"], item["method"].lower()) for item in ast_only["apis"]}
    assert {
        ("/callee/users/page", "post"),
        ("/callee/users/list", "get"),
        ("/callee/audit/search", "put"),
        (delete_only, "delete"),
    } <= ast_methods, ast_methods
    assert not any(path in blocked for path, _method in ast_methods), ast_methods

    ast_scope_source = r'''
const concise = http => http.post("/ast/concise-shadow", {page:1});
const destructured = ({request}) => request.post("/ast/destructured-arrow", {page:1});
const restArgs = (...service) => service.post("/ast/rest-shadow", {page:1});
const defaults = (http = client) => http.post("/ast/default-shadow", {page:1});
const objectMethods = { run(http) { http.post("/ast/object-method", {page:1}); } };
class FactoryClass { run(request) { request.post("/ast/class-method", {page:1}); } }
try { work(); } catch ({http}) { http.post("/ast/catch-shadow", {page:1}); }
for (const service of clients) { service.post("/ast/for-shadow", {page:1}); }
const {request} = clients; request.post("/ast/object-local", {page:1});
let [http] = clients; http.post("/ast/array-local", {page:1});
function localAxios(axios) { axios.post("/ast/axios-shadow", {page:1}); }
axios = otherAxios; axios.post("/ast/axios-mutated", {page:1});
'''
    ast_scope = analyze_javascript_ast(
        ast_scope_source,
        "http://example.test/scope.js",
        "http://example.test/",
        mode="required",
        limits={"max_bytes": 200000, "max_nodes": 10000, "max_depth": 64, "max_expressions": 3000},
    )
    assert ast_scope["status"] == "parsed", ast_scope["status"]
    assert not ast_scope["apis"], ast_scope["apis"]

    isolated_cases = {
        "concise_arrow": ('const f = axios => axios.post("/isolated/concise/page", {page:1});', "/isolated/concise/page"),
        "destructured_arrow": ('const f = ({request}) => request.post("/isolated/destructured/page", {page:1});', "/isolated/destructured/page"),
        "rest_arrow": ('const f = (...service) => service.post("/isolated/rest/page", {page:1});', "/isolated/rest/page"),
        "object_method_param": ('const o={run(http){http.post("/isolated/object/page", {page:1});}};', "/isolated/object/page"),
        "class_method_param": ('class C{run(axios){axios.post("/isolated/class/page", {page:1});}}', "/isolated/class/page"),
        "catch_plain": ('try{work();}catch(http){http.post("/isolated/catch/page", {page:1});}', "/isolated/catch/page"),
        "catch_destructured": ('try{work();}catch({request}){request.post("/isolated/catch-object/page", {page:1});}', "/isolated/catch-object/page"),
        "for_of": ('for(const service of clients){service.post("/isolated/for/page", {page:1});}', "/isolated/for/page"),
        "object_pattern": ('const {http}=clients;http.post("/isolated/object-local/page", {page:1});', "/isolated/object-local/page"),
        "array_pattern": ('const [request]=clients;request.post("/isolated/array-local/page", {page:1});', "/isolated/array-local/page"),
        "local_alias": ('const axios=client;axios.post("/isolated/local-alias/page", {page:1});', "/isolated/local-alias/page"),
        "alias_capture": ('const local=axios;axios.post("/isolated/alias-capture/page", {page:1});', "/isolated/alias-capture/page"),
        "assign_or": ('http|=other;http.post("/isolated/or/page", {page:1});', "/isolated/or/page"),
        "assign_and": ('http&=other;http.post("/isolated/and/page", {page:1});', "/isolated/and/page"),
        "assign_xor": ('http^=other;http.post("/isolated/xor/page", {page:1});', "/isolated/xor/page"),
        "assign_shift_left": ('http<<=1;http.post("/isolated/shift-left/page", {page:1});', "/isolated/shift-left/page"),
        "assign_shift_right": ('http>>=1;http.post("/isolated/shift-right/page", {page:1});', "/isolated/shift-right/page"),
        "assign_shift_unsigned": ('http>>>=1;http.post("/isolated/shift-unsigned/page", {page:1});', "/isolated/shift-unsigned/page"),
        "assign_logical_and": ('http&&=other;http.post("/isolated/logical-and/page", {page:1});', "/isolated/logical-and/page"),
        "assign_logical_or": ('http||=other;http.post("/isolated/logical-or/page", {page:1});', "/isolated/logical-or/page"),
        "assign_nullish": ('http??=other;http.post("/isolated/nullish/page", {page:1});', "/isolated/nullish/page"),
        "assign_power": ('http**=2;http.post("/isolated/power/page", {page:1});', "/isolated/power/page"),
        "mutated_axios": ('axios||=other;axios.post("/isolated/axios-mutated/page", {page:1});', "/isolated/axios-mutated/page"),
        "case_mismatch": ('HTTP.post("/isolated/case/page", {page:1});', "/isolated/case/page"),
        "conditional_factory": ('if(flag)var http=axios.create({});http.post("/isolated/conditional/page", {page:1});', "/isolated/conditional/page"),
        "unicode_http_shadow": ('let h\\u0074tp=fake;http.post("/isolated/unicode-http/page", {page:1});', "/isolated/unicode-http/page"),
        "unicode_axios_shadow": ('let ax\\u0069os=fake;axios.post("/isolated/unicode-axios/page", {page:1});', "/isolated/unicode-axios/page"),
        "domain_service_noise": ('domainService.post("/isolated/domain-noise/page", {page:1});', "/isolated/domain-noise/page"),
        "myhttp_noise": ('myhttp.post("/isolated/myhttp-noise/page", {page:1});', "/isolated/myhttp-noise/page"),
        "template_plain_mutation": ('var http=axios.create({});const x=`${ http = fake }`;http.post("/isolated/template-plain/page", {page:1});', "/isolated/template-plain/page"),
        "template_compound_mutation": ('var http=axios.create({});const x=`${ http |= fake }`;http.post("/isolated/template-compound/page", {page:1});', "/isolated/template-compound/page"),
        "template_nested_unicode": (r'var http=axios.create({});const x=`outer ${`inner ${ h\u0074tp = fake }`}`;http.post("/isolated/template-nested/page", {page:1});', "/isolated/template-nested/page"),
        "division_not_regex": ('const ratio=total/http/count;http.post("/isolated/division/page", {page:1});', "/isolated/division/page"),
        "object_shorthand": ('const meta={http};http.post("/isolated/shorthand/page", {page:1});', "/isolated/shorthand/page"),
        "bracket_indirect": ('var http=axios.create({});http["post"]("/isolated/bracket/page", {page:1});', "/isolated/bracket/page"),
        "optional_indirect": ('var http=axios.create({});http?.post("/isolated/optional/page", {page:1});', "/isolated/optional/page"),
        "property_indirect": ('obj.http.post("/isolated/property-indirect/page", {page:1});', "/isolated/property-indirect/page"),
        "interpolation_regex_brace": ('var http=axios.create({});const x=`${ /}/.test(v) }`;http.post("/isolated/interpolation-brace/page", {page:1});', "/isolated/interpolation-brace/page"),
        "interpolation_regex_class_brace": ('var http=axios.create({});const x=`${ /[}]/.test(v) }`;http.post("/isolated/interpolation-class/page", {page:1});', "/isolated/interpolation-class/page"),
        "control_if_regex": ('if(flag)/http.post("\\/isolated\\/control-if\\/page",{page:1})/;', "/isolated/control-if/page"),
        "control_else_regex": ('if(flag)work();else /http.post("\\/isolated\\/control-else\\/page",{page:1})/;', "/isolated/control-else/page"),
        "control_do_regex": ('do /service.post("\\/isolated\\/control-do\\/page",{page:1})/;while(flag);', "/isolated/control-do/page"),
        "control_for_regex": ('for(;flag;) /request.post("\\/isolated\\/control-for\\/page",{page:1})/;', "/isolated/control-for/page"),
        "control_break_regex": ('while(flag){break /axios.post("\\/isolated\\/control-break\\/page",{page:1})/;}', "/isolated/control-break/page"),
        "postfix_increment_division": ('http++/fake/.test(v);http.post("/isolated/postfix-increment/page", {page:1});', "/isolated/postfix-increment/page"),
        "postfix_decrement_division": ('http--/fake/.test(v);http.post("/isolated/postfix-decrement/page", {page:1});', "/isolated/postfix-decrement/page"),
        "harmless_interpolation_string": ('var http=axios.create({});const x=`${ "http" }`;http.post("/isolated/harmless-string/page", {page:1});', "/isolated/harmless-string/page"),
        "harmless_interpolation_comment": ('var http=axios.create({});const x=`${ /* http */ 1 }`;http.post("/isolated/harmless-comment/page", {page:1});', "/isolated/harmless-comment/page"),
        "harmless_interpolation_regex": ('var http=axios.create({});const x=`${ /http/.test(v) }`;http.post("/isolated/harmless-interpolation-regex/page", {page:1});', "/isolated/harmless-interpolation-regex/page"),
        "safe_factory_regex": ('const matcher=/safe/;var http=axios.create({});http.post("/isolated/safe-regex/page", {page:1});', "/isolated/safe-regex/page"),
        "safe_factory_regex_unicode": (r'const matcher=/h\u0074tp|ax\u0069os/;var http=axios.create({});http.post("/isolated/safe-regex-unicode/page", {page:1});', "/isolated/safe-regex-unicode/page"),
        "this_http": ('this.http.post("/isolated/this-http/page", {page:1});', "/isolated/this-http/page"),
        "this_http_bracket": ('this["http"].post("/isolated/this-bracket/page", {page:1});', "/isolated/this-bracket/page"),
        "this_http_optional": ('this?.http.post("/isolated/this-optional/page", {page:1});', "/isolated/this-optional/page"),
        "this_http_assignment": ('this.http=fake;this.http.post("/isolated/this-assigned/page", {page:1});', "/isolated/this-assigned/page"),
        "object_assign_call": ('Object.assign({},client).post("/isolated/object-assign/page", {page:1});', "/isolated/object-assign/page"),
        "reflect_call": ('Reflect.get(client,"post")("/isolated/reflect/page", {page:1});', "/isolated/reflect/page"),
        "computed_method": ('client["post"]("/isolated/computed/page", {page:1});', "/isolated/computed/page"),
        "prototype_method": ('client.__proto__.post("/isolated/prototype/page", {page:1});', "/isolated/prototype/page"),
        "dynamic_this_method": ('this[method]("/isolated/dynamic-this/page", {page:1});', "/isolated/dynamic-this/page"),
        "object_literal_call": ('({post:function(){}}).post("/isolated/object-literal/page", {page:1});', "/isolated/object-literal/page"),
    }
    padding = ["/ordinary/isolated-padding-%02d" % index for index in range(40)]
    for case_name, (case_source, case_path) in isolated_cases.items():
        for mode in ("off", "required"):
            case_graph = build_inline_graph(scanner, case_source, ast_mode=mode)
            case_endpoints = {item.path: item for item in case_graph.apis}
            assert case_path in case_endpoints, (case_name, mode, case_endpoints)
            assert case_endpoints[case_path].source != "js_request", (case_name, mode, case_endpoints[case_path])
            assert case_path not in case_graph.param_profile["api_methods"], (
                case_name, mode, case_graph.param_profile["api_methods"],
            )
        ast_case = analyze_javascript_ast(
            case_source,
            "http://example.test/%s.js" % case_name,
            "http://example.test/",
            mode="required",
            limits={"max_bytes": 100000, "max_nodes": 5000, "max_depth": 64, "max_expressions": 2000},
        )
        if ast_case["status"] == "parsed":
            assert case_path not in {item["path"] for item in ast_case["apis"]}, (case_name, ast_case["apis"])
        else:
            assert ast_case["status"] == "parse_error", (case_name, ast_case["status"])
        case_explicit = scanner.explicit_js_method_map(case_source)
        assert case_path not in case_explicit, (case_name, case_explicit)
        case_bodies = {item[0] for item in scanner._extract_url_body_sources(case_source)}
        assert case_path not in case_bodies, (case_name, case_bodies)
        case_profile = scanner.extract_param_profile(case_source)
        assert case_path not in case_profile["api_methods"], (case_name, case_profile["api_methods"])
        assert case_path not in case_profile["api_params"], (case_name, case_profile["api_params"])
        scheduled = scanner.scheduled_bypass_tests(case_path, scanner.FAST_BYPASS, case_profile)
        assert not scheduled or {item[1] for item in scheduled} == {"GET"}, (case_name, scheduled)
        seed_target = {
            "apis": padding + [case_path],
            "api_meta": {case_path: {"sources": ["js-graph"], "confidence": 0.8}},
        }
        request_candidates = [
            api for api in seed_target["apis"]
            if "js_request" in set((seed_target["api_meta"].get(api) or {}).get("sources") or [])
        ]
        request_reserved = scanner._bounded_canonical_seed(request_candidates, seed_target, 16)
        assert case_path not in request_reserved, (case_name, request_reserved)

    positive_factory_cases = {
        "asi_boundary": ('const marker=1\nvar http=axios.create({});http.post("/positive/asi/page", {page:1});', "/positive/asi/page"),
        "member_property": ('const holder={};void holder.http;var http=axios.create({});http.post("/positive/member/page", {page:1});', "/positive/member/page"),
        "object_key": ('const metadata={http:"label"};var http=axios.create({});http.post("/positive/key/page", {page:1});', "/positive/key/page"),
    }
    for case_name, (case_source, case_path) in positive_factory_cases.items():
        for mode in ("off", "required"):
            case_graph = build_inline_graph(scanner, case_source, ast_mode=mode)
            case_endpoints = {item.path: item for item in case_graph.apis}
            assert case_endpoints[case_path].source == "js_request", (case_name, mode, case_endpoints)
            assert case_graph.param_profile["api_methods"].get(case_path) == {"post"}, (
                case_name, mode, case_graph.param_profile["api_methods"],
            )
        case_explicit = scanner.explicit_js_method_map(case_source)
        assert case_explicit.get(case_path) == {"post"}, (case_name, case_explicit)
        case_bodies = {item[0] for item in scanner._extract_url_body_sources(case_source)}
        assert case_path in case_bodies, (case_name, case_bodies)
        case_profile = scanner.extract_param_profile(case_source)
        assert case_path in case_profile["api_params"], (case_name, case_profile["api_params"])
        scheduled = scanner.scheduled_bypass_tests(case_path, scanner.FAST_BYPASS, case_profile)
        assert scheduled and {item[1] for item in scheduled} == {"POST"}, (case_name, scheduled)
        reserved = scanner._bounded_canonical_seed(
            [case_path],
            {"apis": [case_path], "api_meta": {case_path: {"sources": ["js_request"], "confidence": 0.96}}},
            16,
        )
        assert reserved == [case_path], (case_name, reserved)

    ast_independent_source = 'const matcher=/safe/;axios.post("/ast-independent/regex/page", {page:1});'
    ast_independent_path = "/ast-independent/regex/page"
    static_only = build_inline_graph(scanner, ast_independent_source, ast_mode="off")
    static_endpoints = {item.path: item for item in static_only.apis}
    assert static_endpoints[ast_independent_path].source != "js_request", static_endpoints
    assert ast_independent_path not in static_only.param_profile["api_methods"], static_only.param_profile
    assert ast_independent_path not in static_only.param_profile["api_params"], static_only.param_profile
    ast_independent = analyze_javascript_ast(
        ast_independent_source,
        "http://example.test/ast-independent.js",
        "http://example.test/",
        mode="required",
        limits={"max_bytes": 100000, "max_nodes": 5000, "max_depth": 64, "max_expressions": 2000},
    )
    assert (ast_independent_path, "POST") in {
        (item["path"], item["method"]) for item in ast_independent["apis"]
    }, ast_independent["apis"]
    required_merge = build_inline_graph(scanner, ast_independent_source, ast_mode="required")
    required_endpoints = {item.path: item for item in required_merge.apis}
    assert required_endpoints[ast_independent_path].source == "js_request", required_endpoints
    assert required_merge.param_profile["api_methods"].get(ast_independent_path) == {"post"}, required_merge.param_profile
    assert ast_independent_path not in required_merge.param_profile["api_params"], required_merge.param_profile
    assert scanner.scheduled_bypass_tests(
        ast_independent_path, scanner.FAST_BYPASS, required_merge.param_profile
    ) == [], required_merge.param_profile

    class FactorySafetyHandler(BaseHTTPRequestHandler):
        def log_message(self, _fmt, *_args):
            return

        def send_content(self, content, content_type="text/plain", status=200):
            data = content.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self.server.hits.append((self.command, urlparse(self.path).path))
            if urlparse(self.path).path == "/":
                return self.send_content('<script src="/unsafe.js"></script>', "text/html")
            if urlparse(self.path).path == "/unsafe.js":
                return self.send_content(self.server.script, "application/javascript")
            return self.send_content("not found", status=404)

        def do_POST(self):
            self.server.hits.append((self.command, urlparse(self.path).path))
            return self.send_content("not found", status=404)

        def do_DELETE(self):
            self.server.hits.append((self.command, urlparse(self.path).path))
            return self.send_content("not found", status=404)

    def assert_loopback(script, protected_paths, title, expect_post=False):
        safety_server = ThreadingHTTPServer(("127.0.0.1", 0), FactorySafetyHandler)
        safety_server.hits = []
        safety_server.script = script
        safety_thread = threading.Thread(target=safety_server.serve_forever, daemon=True)
        safety_thread.start()
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                target_file = temp_path / "targets.json"
                outdir = temp_path / "out"
                base_url = "http://127.0.0.1:%d" % safety_server.server_address[1]
                target_file.write_text(json.dumps([{"url": base_url, "title": title, "score": 100}]))
                proc = subprocess.run(
                    [
                        sys.executable, str(SCANNER), "--input", str(target_file), "--outdir", str(outdir),
                        "--workers", "2", "--timeout", "2", "--phase2-timeout", "30",
                        "--phase3a-timeout", "20", "--phase3b-layer-timeout", "20",
                        "--no-proxy", "--skip-port-probe", "--disable-api-fuzz", "--replay-scope", "none",
                        "--no-capture-finding-evidence",
                    ],
                    text=True,
                    capture_output=True,
                    timeout=90,
                )
                assert proc.returncode == 0, (title, proc.returncode)
            active_hits = {
                (method, path) for method, path in safety_server.hits
                if path in protected_paths and method in {"POST", "DELETE"}
            }
            if expect_post:
                assert any(method == "POST" for method, _path in active_hits), (title, active_hits)
                assert not any(method == "DELETE" for method, _path in active_hits), (title, active_hits)
            else:
                assert not active_hits, (title, active_hits)
        finally:
            safety_server.shutdown()
            safety_server.server_close()

    assert_loopback(unsafe_factory_source, factory_blocked | body_noise, "factory-safety")
    for isolated_name in (
        "concise_arrow", "catch_destructured", "template_plain_mutation", "template_compound_mutation",
        "interpolation_regex_brace", "interpolation_regex_class_brace",
        "control_if_regex", "control_else_regex", "control_do_regex", "control_for_regex", "control_break_regex",
        "postfix_increment_division", "postfix_decrement_division",
        "harmless_interpolation_string", "harmless_interpolation_comment", "harmless_interpolation_regex",
        "safe_factory_regex", "safe_factory_regex_unicode",
        "this_http", "this_http_bracket", "this_http_optional", "this_http_assignment",
        "object_assign_call", "reflect_call", "computed_method", "prototype_method",
        "dynamic_this_method", "object_literal_call",
    ):
        isolated_source, isolated_path = isolated_cases[isolated_name]
        assert_loopback(isolated_source, {isolated_path}, "isolated-" + isolated_name)
    for positive_name, (positive_source, positive_path) in positive_factory_cases.items():
        assert_loopback(positive_source, {positive_path}, "positive-" + positive_name, expect_post=True)

    body_sources = scanner._extract_url_body_sources(source)
    bound_paths = {item[0] for item in body_sources}
    assert {"/callee/users/page", "/callee/audit/search", "/callee/factory/page"} <= bound_paths, body_sources
    assert not (blocked & bound_paths), blocked & bound_paths

    profile = scanner.extract_param_profile(source)
    for path in ("/callee/users/page", "/callee/factory/page"):
        scheduled = scanner.scheduled_bypass_tests(path, scanner.FAST_BYPASS, profile)
        assert scheduled and {item[1] for item in scheduled} == {"POST"}, (path, scheduled)
    get_scheduled = scanner.scheduled_bypass_tests("/callee/users/list", scanner.FAST_BYPASS, profile)
    assert get_scheduled and {item[1] for item in get_scheduled} == {"GET"}, get_scheduled

    included = build_inline_graph(scanner, source, ast_mode="required", include_delete_method=True)
    included_endpoints = {item.path: item for item in included.apis}
    assert delete_only in included_endpoints, included_endpoints
    assert included.param_profile["api_methods"].get(delete_only) == {"delete"}, included.param_profile["api_methods"]
    assert scanner.scheduled_bypass_tests(delete_only, scanner.FAST_BYPASS, included.param_profile) == [], delete_only


def assert_cross_asset_body_method_isolation(scanner):
    collision_path = "/api/collision/search"
    assets = {
        "http://example.test/body.js": (
            'this.http.post("%s", {page:1, size:20});' % collision_path
        ),
        # The slash makes the static source fail closed; the real AST can still
        # prove this source's method independently. It has no body to bind.
        "http://example.test/method.js": (
            'const matcher=/safe/;axios.post("%s");' % collision_path
        ),
    }

    def fetch_asset(url, max_size=500000):
        assert url in assets, url
        return 200, url, assets[url], "application/javascript"

    graph = build_js_graph(
        page_url="http://example.test/",
        html='<script src="/body.js"></script><script src="/method.js"></script>',
        fetch_text=fetch_asset,
        extract_js_from_html=scanner.extract_js_from_html,
        extract_links_from_html=lambda _html, _base: set(),
        extract_apis=scanner.extract_apis,
        extract_module_urls_from_content=scanner.extract_module_urls_from_content,
        extract_prefixes_from_content=scanner.extract_prefixes_from_content,
        extract_param_profile=scanner.extract_param_profile,
        empty_param_profile=scanner.empty_param_profile,
        merge_param_profiles=scanner.merge_param_profiles,
        common_libs=scanner.COMMON_LIBS,
        valid_sensitive_value=scanner.valid_sensitive_value,
        ast_mode="required",
        import_maps=False,
        manifest_inventory=False,
        source_map_mode="off",
    )
    endpoints = {item.path: item for item in graph.apis}
    assert endpoints[collision_path].source == "js_request", endpoints
    assert graph.param_profile["api_methods"].get(collision_path) == {"post"}, graph.param_profile
    assert collision_path not in graph.param_profile["api_params"], graph.param_profile
    assert collision_path not in graph.param_profile["api_param_sources"], graph.param_profile
    assert collision_path not in graph.param_profile.get("_apis_from_params", set()), graph.param_profile
    assert scanner.scheduled_bypass_tests(
        collision_path, scanner.FAST_BYPASS, graph.param_profile
    ) == [], graph.param_profile

    class CollisionHandler(BaseHTTPRequestHandler):
        def log_message(self, _fmt, *_args):
            return

        def respond(self, content, content_type="text/plain", status=200):
            data = content.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            path = urlparse(self.path).path
            self.server.hits.append((self.command, path))
            if path == "/":
                return self.respond(
                    '<script src="/body.js"></script><script src="/method.js"></script>',
                    "text/html",
                )
            if path == "/body.js":
                return self.respond(assets["http://example.test/body.js"], "application/javascript")
            if path == "/method.js":
                return self.respond(assets["http://example.test/method.js"], "application/javascript")
            return self.respond("not found", status=404)

        def do_POST(self):
            self.server.hits.append((self.command, urlparse(self.path).path))
            return self.respond("not found", status=404)

    server = ThreadingHTTPServer(("127.0.0.1", 0), CollisionHandler)
    server.hits = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            target_file = temp / "targets.json"
            outdir = temp / "out"
            base = "http://127.0.0.1:%d" % server.server_address[1]
            target_file.write_text(json.dumps([{"url": base, "title": "cross-source", "score": 100}]))
            proc = subprocess.run(
                [
                    sys.executable, str(SCANNER), "--input", str(target_file), "--outdir", str(outdir),
                    "--workers", "2", "--timeout", "2", "--phase2-timeout", "30",
                    "--phase3a-timeout", "20", "--phase3b-layer-timeout", "20",
                    "--no-proxy", "--skip-port-probe", "--disable-api-fuzz", "--replay-scope", "none",
                    "--js-ast-mode", "required", "--no-capture-finding-evidence",
                ],
                text=True,
                capture_output=True,
                timeout=90,
                env=dict(os.environ, PYTHONPATH="/tmp/scanner-pipeline-esprima"),
            )
            assert proc.returncode == 0, proc.returncode
            inventory = [
                json.loads(line)
                for line in (outdir / "phase2_inventory.jsonl").read_text().splitlines()
                if line.strip()
            ]
            record = next(item for item in inventory if item.get("base") == base)
            profile = record.get("param_profile") or {}
            assert collision_path not in (profile.get("api_params") or {}), profile
            assert collision_path not in (profile.get("api_param_sources") or {}), profile
        assert ("POST", collision_path) not in server.hits, server.hits
    finally:
        server.shutdown()
        server.server_close()


def assert_canonical_quota_dedup(scanner):
    ordinary = ["/admin/user/quota-padding-%02d" % index for index in range(40)]
    request_variants = ["/sink/shared?variant=%02d" % index for index in range(20)]
    request_distinct = ["/sink/distinct-%02d" % index for index in range(20)]
    request_items = request_variants + request_distinct
    request_meta = {
        item: {"confidence": 0.96, "sources": ["js_request"]}
        for item in request_items
    }
    request_target = {"apis": ordinary + request_items, "api_meta": request_meta}

    root_variants = ["/iot-api/shared?variant=%02d" % index for index in range(20)]
    root_distinct = ["/root%02d-api/item" % index for index in range(20)]
    root_items = root_variants + root_distinct
    root_target = {
        "apis": ordinary + root_items,
        "api_meta": {item: {"confidence": 0.8, "sources": ["js-graph"]} for item in root_items},
    }

    def selected_canonical(target, candidates):
        chosen = scanner.phase3_seed_candidates(target)
        candidate_roots = {item.split("?", 1)[0] for item in candidates}
        return [item.split("?", 1)[0] for item in chosen if item.split("?", 1)[0] in candidate_roots]

    request_first = selected_canonical(request_target, request_items)
    request_second = selected_canonical(request_target, request_items)
    root_first = selected_canonical(root_target, root_items)
    root_second = selected_canonical(root_target, root_items)
    assert request_first == request_second and len(request_first) == len(set(request_first)) == 16, request_first
    assert root_first == root_second and len(root_first) == len(set(root_first)) == 16, root_first

    overlap = ["/overlap%02d-api/item" % index for index in range(20)]
    request_only = ["/sink/request-only-%02d" % index for index in range(20)]
    root_only = ["/rootonly%02d-api/item" % index for index in range(20)]
    overlap_target = {
        "apis": ordinary + overlap + request_only + root_only,
        "api_meta": {
            **{item: {"confidence": 0.96, "sources": ["js_request"]} for item in overlap + request_only},
            **{item: {"confidence": 0.8, "sources": ["js-graph"]} for item in root_only},
        },
    }
    request_bucket = scanner._bounded_canonical_seed(overlap + request_only, overlap_target, 16)
    request_seen = {scanner._canonical_seed_path(item) for item in request_bucket}
    root_bucket = scanner._bounded_canonical_seed(overlap + root_only, overlap_target, 16, excluded=request_seen)
    root_seen = {scanner._canonical_seed_path(item) for item in root_bucket}
    assert len(request_seen) == 16 and len(root_seen) == 16 and request_seen.isdisjoint(root_seen), (request_seen, root_seen)
    combined = scanner.phase3_seed_candidates(overlap_target)
    combined_seen = {
        item.split("?", 1)[0] for item in combined
        if item.split("?", 1)[0] in {entry.split("?", 1)[0] for entry in overlap + request_only + root_only}
    }
    assert len(combined_seen) == 32, combined_seen

    higher_ranked = ["/admin/user/operator-padding-%02d" % index for index in range(48)]
    extra_variants = [
        "/operator/explicit-late?page=2",
        "/operator/explicit-late?page=1",
    ]
    extra_plain = "/operator/explicit-second"
    absent_source = "/operator/not-explicit"
    request_overlap = "/sink/operator-overlap"
    root_overlap = "/telemetry-api/operator-overlap"
    extra_items = extra_variants + [extra_plain, request_overlap, root_overlap]
    extra_target = {
        "apis": higher_ranked + [absent_source] + extra_items,
        "api_meta": {
            **{
                item: {"confidence": 0.50, "sources": ["extra_wordlist"]}
                for item in extra_items
            },
            request_overlap: {
                "confidence": 0.96,
                "sources": ["js_request", "extra_wordlist"],
            },
        },
    }
    extra_first = scanner.phase3_seed_candidates(extra_target)
    extra_second_run = scanner.phase3_seed_candidates(extra_target)
    assert extra_first == extra_second_run, (extra_first, extra_second_run)
    canonical_extra = [scanner._canonical_seed_path(item) for item in extra_first]
    assert canonical_extra.count("/operator/explicit-late") == 1, canonical_extra
    assert {extra_plain, request_overlap, root_overlap} <= set(canonical_extra), canonical_extra
    assert absent_source not in canonical_extra, canonical_extra
    request_index = canonical_extra.index(request_overlap)
    extra_index = canonical_extra.index("/operator/explicit-late")
    root_index = canonical_extra.index(root_overlap)
    generic_index = canonical_extra.index(higher_ranked[0])
    assert request_index < extra_index < generic_index, canonical_extra
    assert request_index < root_index < generic_index, canonical_extra
    scheduled = scanner.scheduled_bypass_tests(
        "/operator/explicit-late", scanner.FAST_BYPASS, scanner.empty_param_profile()
    )
    assert scheduled and {item[1] for item in scheduled} == {"GET"}, scheduled

    probe = r'''
import json, sys
sys.argv = ["deep_scanner.py", "--no-proxy"]
import pipeline.deep_scanner as scanner
ordinary = ["/admin/user/quota-padding-%02d" % i for i in range(40)]
variants = ["/sink/shared?variant=%02d" % i for i in range(20)]
distinct = ["/sink/distinct-%02d" % i for i in range(20)]
items = variants + distinct
target = {"apis": ordinary + items, "api_meta": {item:{"confidence":0.96,"sources":["js_request"]} for item in items}}
roots = {item.split("?",1)[0] for item in items}
root_variants = ["/iot-api/shared?variant=%02d" % i for i in range(20)]
root_distinct = ["/root%02d-api/item" % i for i in range(20)]
root_items = root_variants + root_distinct
root_target = {"apis": ordinary + root_items, "api_meta": {item:{"confidence":0.8,"sources":["js-graph"]} for item in root_items}}
root_paths = {item.split("?",1)[0] for item in root_items}
print(json.dumps({
  "request": [item.split("?",1)[0] for item in scanner.phase3_seed_candidates(target) if item.split("?",1)[0] in roots],
  "api_root": [item.split("?",1)[0] for item in scanner.phase3_seed_candidates(root_target) if item.split("?",1)[0] in root_paths],
}, sort_keys=True))
'''
    outputs = []
    for seed in ("1", "77", "999"):
        env = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH=str(ROOT))
        proc = subprocess.run([sys.executable, "-c", probe], cwd=str(ROOT), env=env, text=True, capture_output=True, timeout=30)
        assert proc.returncode == 0, proc.returncode
        outputs.append(proc.stdout.strip())
    assert len(set(outputs)) == 1, outputs


def assert_extra_wordlist_boundaries(scanner):
    assert scanner.normalize_wordlist_api("api/operator/status") == "/api/operator/status"
    safe_unicode_path = "/api/%E4%B8%AD%E6%96%87/status"
    assert scanner.validate_root_relative_path(safe_unicode_path) == safe_unicode_path
    assert scanner.normalize_wordlist_api(safe_unicode_path) == safe_unicode_path
    assert scanner.normalize_wordlist_api(
        "HTTP://example.test/api/operator/status?discarded=value#fragment"
    ) == "/api/operator/status"
    encoded_unsafe = (
        "/api/%2e%2e/operator/status",
        "/api/%252e%252e/operator/status",
        "/api/%2f/operator/status",
        "/api/%252f/operator/status",
        "/api/%25252f/operator/status",
        "/api/%5c/operator/status",
        "/api/%255c/operator/status",
        "/api/%25255c/operator/status",
        "/api/%00/operator/status",
        "/api/%2500/operator/status",
        "/api/%252500/operator/status",
        "/api/%3b../operator/status",
        "/api/%253b../operator/status",
        "/api/%3fquery/operator/status",
        "/api/%2523fragment/operator/status",
        "/api/%2540authority/operator/status",
        "/api/%EF%BC%8F/operator/status",
        "/api/%25EF%25BC%258F/operator/status",
        "/api/%EF%BC%BC/operator/status",
        "/api/%EF%BC%8E%EF%BC%8E/operator/status",
        "/api/%EF%BF%BD/operator/status",
        "/api/%25252525252f/operator/status",
    )
    unicode_unsafe = (
        "/api/\uff0f/operator/status",
        "/api/\uff3c/operator/status",
        "/api/\uff0e\uff0e/operator/status",
        "/api/\u2215/operator/status",
        "/api/\u2024\u2024/operator/status",
        "/api/\ufffd/operator/status",
    )
    unsafe_inputs = (
        "//example.test/api/operator/status",
        "http://example.test//api/operator/status",
        "HTTP://user:pass@example.test/api/operator/status",
        "ftp://example.test/api/operator/status",
        "/api//operator/status",
        "/api/../operator/status",
        "/api/./operator/status",
        "/api/..;matrix/operator/status",
        "/api/.;matrix/operator/status",
        r"/api\operator\status",
        "/api/operator/status\x00tail",
        "\t/api/operator/status",
    ) + encoded_unsafe + unicode_unsafe
    for unsafe in unsafe_inputs:
        assert scanner.normalize_wordlist_api(unsafe) == "", unsafe

    padding = ["/admin/user/meta-padding-%02d" % index for index in range(48)]
    late = "/operator/meta-late"
    malformed_sources = (
        "extra_wordlist",
        {"extra_wordlist": True},
        7,
        None,
        ["extra_wordlist", 7],
    )
    for sources in malformed_sources:
        target = {
            "base": "http://example.test",
            "apis": padding + [late],
            "api_meta": {late: {"confidence": 0.5, "sources": sources}},
        }
        assert scanner.phase3_seed_candidates(target).count(late) == 1, sources
        persisted = scanner.phase2_inventory_record(target, include_param_profile=False)
        assert persisted["api_sources"].get(late) == ["prefix_inventory"], persisted["api_sources"]
    malformed_item_target = {"base": "http://example.test", "apis": padding + [late], "api_meta": {late: "extra_wordlist"}}
    assert scanner.phase3_seed_candidates(malformed_item_target).count(late) == 1
    assert scanner.phase2_inventory_record(malformed_item_target, include_param_profile=False)["api_sources"][late] == ["prefix_inventory"]
    valid_target = {
        "apis": padding + [late],
        "api_meta": {late: {"confidence": 0.5, "sources": {"extra_wordlist"}}},
    }
    assert late in scanner.phase3_seed_candidates(valid_target), valid_target

    old_extra = list(scanner.EXTRA_API_WORDLIST_PATHS)
    old_backend = scanner.args.enable_backend_baseline
    try:
        scanner.EXTRA_API_WORDLIST_PATHS = ["/list"]
        scanner.args.enable_backend_baseline = True
        meta = {}
        apis = scanner.add_configured_backend_paths(set(), meta)
        apis, _prefix_order = scanner.apply_prefix_inventory(apis, meta, {"/tenant"})
        assert "/list" in apis and "/tenant/list" in apis, apis
        assert "extra_wordlist" in meta["/list"]["sources"], meta
        assert meta["/tenant/list"]["sources"] == ["prefix_inventory"], meta
        for backend_path in ("/api/v1/users", "/tenant/api/v1/users"):
            expected = "backend_baseline" if backend_path == "/api/v1/users" else "prefix_inventory"
            assert meta[backend_path]["sources"] == [expected], (backend_path, meta)
    finally:
        scanner.EXTRA_API_WORDLIST_PATHS = old_extra
        scanner.args.enable_backend_baseline = old_backend

    class BoundaryHandler(BaseHTTPRequestHandler):
        def log_message(self, _fmt, *_args):
            return

        def do_GET(self):
            self.server.hits.append((self.command, self.path))
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    first = ThreadingHTTPServer(("127.0.0.1", 0), BoundaryHandler)
    second = ThreadingHTTPServer(("127.0.0.1", 0), BoundaryHandler)
    first.hits = []
    second.hits = []
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True)
        for server in (first, second)
    ]
    for thread in threads:
        thread.start()
    try:
        first_base = "http://127.0.0.1:%d" % first.server_address[1]
        second_base = "http://127.0.0.1:%d" % second.server_address[1]
        unsafe_paths = (
            "//127.0.0.1:%d/cross-origin" % second.server_address[1],
            second_base + "/cross-origin",
            second_base + "//cross-origin",
        ) + encoded_unsafe + unicode_unsafe + (
            "/api/../cross-origin",
            "/api/./cross-origin",
            "/api/..;matrix/cross-origin",
            r"/api\cross-origin",
            "/api/cross-origin\x00tail",
        )
        for unsafe_path in unsafe_paths:
            assert scanner.test_api(
                first_base, unsafe_path, scanner.FAST_BYPASS,
                param_profile=scanner.empty_param_profile(),
            ) == [], unsafe_path
        assert first.hits == [] and second.hits == [], (first.hits, second.hits)
    finally:
        for server in (first, second):
            server.shutdown()
            server.server_close()


def assert_scope_aware_forwarded_wrapper_params(scanner):
    trusted_path = "/alpha-api/catalog/search"
    source = r'''
const copy = (target, source) => { for (const key in source) target[key] = source[key]; return target; };
const merge = (left, right) => copy(copy({}, left), right);
const reactive = value => value;
const state = reactive({filter_a:"", filter_b:"", filter_c:""});
const load = formal => http.get("/alpha-api/catalog/search", {params: formal});
const passthrough = value => value;
load(passthrough(merge(state, {offset:0, limit:10})));
function shadowed(load) { load({shadow_noise:1}); }
const routeConfig = { loader: load({route_config_noise:1}) };
const routeArray = [load({route_array_noise:1})];
register(load({nested_call_noise:1}));
{
  const load = formal => router.get("/route/config", {params: formal});
  load({route_noise:1});
}
const dynamic = formal => client.get(`/iot-api/${segment}`, {params: formal});
dynamic({dynamic_noise:1});
const computed = formal => client["get"]("/computed/client", {params: formal});
computed({computed_noise:1});
const untrusted = formal => domainService.get("/untrusted/client", {params: formal});
untrusted({untrusted_noise:1});
const wrongCase = formal => HTTP.get("/wrong-case/client", {params: formal});
wrongCase({wrong_case_noise:1});
'''
    snapshots = []
    for _ in range(2):
        graph = build_inline_graph(scanner, source, ast_mode="required")
        profile = graph.param_profile
        expected = {"filter_a", "filter_b", "filter_c", "offset", "limit"}
        assert profile["api_params"][trusted_path] == expected, profile["api_params"]
        assert profile["api_param_sources"][trusted_path]["query"] == expected, profile
        assert profile["api_methods"][trusted_path] == {"get"}, profile
        endpoints = {item.path: item for item in graph.apis}
        assert endpoints[trusted_path].source == "js_request", endpoints
        for path in ("/route/config", "/computed/client", "/untrusted/client", "/wrong-case/client"):
            assert path not in profile.get("api_params", {}), (path, profile.get("api_params"))
        polluted = set().union(*(profile.get("api_params") or {}).values())
        assert not {
            "shadow_noise", "route_config_noise", "route_array_noise", "route_noise",
            "nested_call_noise", "dynamic_noise", "computed_noise", "untrusted_noise", "wrong_case_noise",
        } & polluted, polluted
        assert graph.stats["ast_param_bindings"] == 1, graph.stats
        snapshots.append(json.dumps(scanner.serialize_param_profile(profile), sort_keys=True))
    assert snapshots[0] == snapshots[1], snapshots

    imported = 'import {opaqueTransform} from "./runtime.js";\n' + source.replace(
        "const reactive = value => value;", ""
    ).replace("reactive({", "opaqueTransform({")
    analysis = analyze_javascript_ast(
        imported, "http://example.test/chunk.js", "http://example.test/",
        mode="required", limits={"max_bytes": 100000, "max_nodes": 20000, "max_expressions": 4000},
    )
    assert not [item for item in analysis["param_bindings"] if item["path"] == trusted_path], analysis
    opaque_apis = {
        (item.get("path"), str(item.get("method") or "").lower())
        for item in analysis.get("apis") or []
    }
    assert (trusted_path, "get") in opaque_apis, opaque_apis
    opaque_graph_source = source.replace(
        "const reactive = value => value;",
        "const reactive = value => externalTransform(value);",
    )
    opaque_graph = build_inline_graph(scanner, opaque_graph_source, ast_mode="required")
    opaque_endpoints = {item.path: item for item in opaque_graph.apis}
    assert opaque_endpoints[trusted_path].source == "js_request", opaque_endpoints
    assert opaque_graph.param_profile["api_methods"][trusted_path] == {"get"}
    assert trusted_path not in opaque_graph.param_profile.get("api_params", {})
    assert trusted_path in opaque_graph.param_profile.get("api_param_blocked", set())
    opaque_variants = scanner.request_variants(
        trusted_path, "GET", "", None, param_profile=opaque_graph.param_profile,
    )
    assert opaque_variants == [("", None)], opaque_variants
    opaque_round_trip = scanner.deserialize_param_profile(json.loads(json.dumps(
        scanner.serialize_param_profile(opaque_graph.param_profile)
    )))
    assert scanner.request_variants(
        trusted_path, "GET", "", None, param_profile=opaque_round_trip,
    ) == [("", None)], opaque_round_trip
    opaque_seed = scanner.phase3_seed_candidates({
        "apis": list(opaque_endpoints),
        "api_meta": {trusted_path: {"sources": ["js_request"], "confidence": 0.96}},
    })
    assert trusted_path in opaque_seed, opaque_seed
    opaque_schedule = scanner.scheduled_bypass_tests(
        trusted_path, scanner.FAST_BYPASS, opaque_graph.param_profile,
    )
    assert opaque_schedule and {item[1] for item in opaque_schedule} == {"GET"}, opaque_schedule

    absolute_source = (
        'const wrap=formal=>http.get("HTTPS://APP.SYNTHETIC.TEST:443/omega-api/absolute/search",{params:formal});'
        'wrap({absolute_key:1});'
    )
    absolute_analysis = analyze_javascript_ast(
        absolute_source, "https://cdn.synthetic.test/assets/chunk.js", "https://app.synthetic.test/",
        mode="required", limits={"max_bytes": 100000, "max_nodes": 20000, "max_expressions": 4000},
    )
    absolute_bindings = absolute_analysis.get("param_bindings") or []
    assert absolute_bindings == [{
        "path": "/omega-api/absolute/search", "method": "GET",
        "source": "query", "names": ["absolute_key"],
    }], absolute_bindings
    assert any(
        item.get("path") == "/omega-api/absolute/search" and item.get("method") == "GET"
        for item in absolute_analysis.get("apis") or []
    ), absolute_analysis.get("apis")
    def build_external_graph(source):
        asset_url = "https://cdn.synthetic.test/assets/chunk.js"
        def fetch(url, max_size=500000):
            assert url == asset_url, url
            return 200, url, source, "application/javascript"
        return build_js_graph(
            page_url="https://app.synthetic.test/",
            html='<script src="%s"></script>' % asset_url,
            fetch_text=fetch,
            extract_js_from_html=scanner.extract_js_from_html,
            extract_links_from_html=lambda _html, _base: set(),
            extract_apis=scanner.extract_apis,
            extract_module_urls_from_content=scanner.extract_module_urls_from_content,
            extract_prefixes_from_content=scanner.extract_prefixes_from_content,
            extract_param_profile=scanner.extract_param_profile,
            empty_param_profile=scanner.empty_param_profile,
            merge_param_profiles=scanner.merge_param_profiles,
            common_libs=scanner.COMMON_LIBS,
            valid_sensitive_value=scanner.valid_sensitive_value,
            ast_mode="required", import_maps=False, manifest_inventory=False,
            source_map_mode="off",
        )

    absolute_graph = build_external_graph(absolute_source)
    absolute_endpoint = {item.path: item for item in absolute_graph.apis}["/omega-api/absolute/search"]
    assert absolute_endpoint.source == "js_request", absolute_endpoint
    assert absolute_graph.param_profile["api_methods"][absolute_endpoint.path] == {"get"}
    assert absolute_graph.param_profile["api_params"][absolute_endpoint.path] == {"absolute_key"}

    absolute_negatives = (
        "https://cdn.synthetic.test/omega-api/asset-origin",
        "hTtPs://foreign.synthetic.test/omega-api/cross-host",
        "https://user@app.synthetic.test/omega-api/userinfo",
        "https://app.synthetic.test:444/omega-api/cross-port",
        "http://app.synthetic.test/omega-api/cross-scheme",
        "//app.synthetic.test/omega-api/network-path",
        "https://app.synthetic.test/omega-api/query?name=value",
        "https://app.synthetic.test/omega-api/empty-query?",
        "https://app.synthetic.test/omega-api/fragment#section",
        "https://app.synthetic.test/omega-api/empty-fragment#",
    )
    for index, absolute_url in enumerate(absolute_negatives):
        negative = (
            'const wrap=formal=>http.get(%s,{params:formal});wrap({forged:1});'
            % json.dumps(absolute_url)
        )
        negative_analysis = analyze_javascript_ast(
            negative, "https://cdn.synthetic.test/assets/chunk.js", "https://app.synthetic.test/",
            mode="required", limits={"max_bytes": 100000, "max_nodes": 20000, "max_expressions": 4000},
        )
        assert negative_analysis.get("param_bindings") == [], (index, negative_analysis)
        assert not any(item.get("path") for item in negative_analysis.get("apis") or []), (index, negative_analysis)

    idna_source = (
        'const wrap=formal=>http.get("HTTPS://XN--BCHER-KVA.EXAMPLE:443/idna-api/catalog",{params:formal});'
        'wrap({idna_key:1});'
    )
    idna_analysis = analyze_javascript_ast(
        idna_source, "https://cdn.synthetic.test/chunk.js", "https://b\u00fccher.example/",
        mode="required", limits={"max_bytes": 100000, "max_nodes": 20000, "max_expressions": 4000},
    )
    assert (idna_analysis.get("param_bindings") or [])[0]["path"] == "/idna-api/catalog", idna_analysis
    assert canonical_http_origin("HTTPS://APP.SYNTHETIC.TEST.") == "https://app.synthetic.test"
    assert canonical_page_api_path(
        "https://app.synthetic.test./root-api/read", "https://app.synthetic.test/",
    ) == "/root-api/read"
    root_dot_analysis = analyze_javascript_ast(
        'const wrap=formal=>http.get("https://app.synthetic.test./root-api/read",{params:formal});wrap({root_key:1});',
        "https://cdn.synthetic.test/chunk.js", "https://app.synthetic.test/",
        mode="required", limits={"max_bytes": 100000, "max_nodes": 20000, "max_expressions": 4000},
    )
    assert (root_dot_analysis.get("param_bindings") or [])[0]["path"] == "/root-api/read"
    for invalid_origin in (
        "https://app.synthetic.test../", "https://app..synthetic.test/",
        "http://exa%6dple.test/", "http://[fe80::1%eth0]/",
        "http://[fe80::1%25eth0]/",
    ):
        assert canonical_http_origin(invalid_origin) == "", invalid_origin
    for invalid_literal in ("/empty?", "/empty#", "/nonempty?x=1", "/nonempty#part"):
        assert canonical_page_api_path(invalid_literal, "https://app.synthetic.test/") == ""
    ipv6_source = (
        'const wrap=formal=>http.get("HTTP://[2001:DB8::1]:80/ipv6-api/read",{params:formal});'
        'wrap({ipv6_key:1});'
    )
    ipv6_analysis = analyze_javascript_ast(
        ipv6_source, "https://cdn.synthetic.test/chunk.js", "http://[2001:db8::1]/",
        mode="required", limits={"max_bytes": 100000, "max_nodes": 20000, "max_expressions": 4000},
    )
    assert (ipv6_analysis.get("param_bindings") or [])[0]["path"] == "/ipv6-api/read", ipv6_analysis
    for zone_literal in (
        "http://[fe80::1%eth0]/zone-api/read",
        "http://[fe80::1%25eth0]/zone-api/read",
    ):
        zone_source = (
            'const wrap=formal=>http.get(%s,{params:formal});wrap({forged:1});'
            % json.dumps(zone_literal)
        )
        zone_analysis = analyze_javascript_ast(
            zone_source, "https://cdn.synthetic.test/chunk.js", "http://[fe80::1]/",
            mode="required", limits={"max_bytes": 100000, "max_nodes": 20000, "max_expressions": 4000},
        )
        assert zone_analysis.get("param_bindings") == [], zone_analysis
        assert zone_analysis.get("apis") == [], zone_analysis

    # Active profile identity is exact. Suffix-related paths cannot exchange
    # blocked, method, query/body or replay facts.
    collision = scanner.empty_param_profile()
    scanner.add_api_method(collision, "/short", "get")
    scanner.add_api_method(collision, "/prefix/short", "post")
    scanner.add_param_name(collision, "prefix_body", api_path="/prefix/short", source="json")
    scanner.add_api_content_type(collision, "/prefix/short", "application/json")
    scanner.add_api_method(collision, "/write", "post")
    scanner.add_param_name(collision, "write_body", api_path="/write", source="json")
    collision["api_param_blocked"].add("/short")
    assert scanner.api_methods_for(collision, "/short") == {"get"}
    assert scanner.api_methods_for(collision, "/prefix/short") == {"post"}
    assert scanner.bound_param_names_by_source(collision, "/short", "query") == []
    assert scanner.bound_param_names_by_source(collision, "/prefix/short", "query") == []
    assert scanner.bound_param_names_by_source(collision, "/prefix/short", "json") == ["prefix_body"]
    assert scanner.bound_param_names_by_source(collision, "/short", "json") == []
    assert scanner.query_suffixes("/short", collision) == [""]
    assert all("short" not in suffix for suffix in scanner.query_suffixes("/prefix/short", collision))
    generated = set(scanner.generate_prefix_inventory(
        {"/short", "/write"}, {"/one", "/one/two", "/cross"},
    )["generated"])
    assert {
        "/one/short", "/one/two/short", "/cross/short",
        "/one/write", "/one/two/write", "/cross/write",
    }.issubset(generated), generated
    generated_target = {
        "apis": sorted(generated | {"/short", "/write"}),
        "param_profile": collision,
        "api_meta": {
            path: {"sources": ["prefix_inventory"], "confidence": 0.25}
            for path in generated
        },
    }
    for generated_path in sorted(generated):
        generated_profile, single_variant = scanner.api_probe_policy(generated_target, generated_path)
        assert single_variant is True
        assert generated_profile == scanner.empty_param_profile(), generated_profile
        assert scanner.api_methods_for(generated_profile, generated_path) == set()
        assert scanner.bound_param_names(generated_profile, generated_path) == []
        assert scanner.scheduled_bypass_tests(
            generated_path, scanner.FAST_BYPASS, generated_profile,
        ) and {item[1] for item in scanner.scheduled_bypass_tests(
            generated_path, scanner.FAST_BYPASS, generated_profile,
        )} == {"GET"}
        active_variants = [("", None)] if single_variant else scanner.request_variants(
            generated_path, "GET", "", None, param_profile=generated_profile,
        )
        assert active_variants == [("", None)]
        replay_target = {"param_profile": scanner.empty_param_profile()}
        assert not scanner.carry_replay_param_profile(
            replay_target, {"param_profile": collision}, generated_path,
        )
        assert replay_target["param_profile"] == scanner.empty_param_profile()

    exact_target = {
        "api_meta": {"/prefix/short": {"sources": ["js_request"], "confidence": 0.96}},
        "param_profile": collision,
    }
    exact_profile, exact_single = scanner.api_probe_policy(exact_target, "/prefix/short")
    assert exact_single is False and exact_profile is collision
    assert scanner.api_methods_for(exact_profile, "/prefix/short") == {"post"}
    assert scanner.bound_param_names_by_source(exact_profile, "/prefix/short", "json") == ["prefix_body"]
    source_target = {"param_profile": collision}
    prefix_target = {"param_profile": scanner.empty_param_profile()}
    assert scanner.carry_replay_param_profile(prefix_target, source_target, "/prefix/short")
    prefix_profile = prefix_target["param_profile"]
    assert "/short" not in prefix_profile["api_methods"]
    assert prefix_profile["api_methods"]["/prefix/short"] == {"post"}
    assert prefix_profile["api_params"]["/prefix/short"] == {"prefix_body"}
    assert "/short" not in prefix_profile["api_param_blocked"]
    short_target = {"param_profile": scanner.empty_param_profile()}
    assert scanner.carry_replay_param_profile(short_target, source_target, "/short")
    short_profile = short_target["param_profile"]
    assert "/prefix/short" not in short_profile["api_methods"]
    assert short_profile["api_methods"]["/short"] == {"get"}
    assert short_profile["api_params"].get("/short", set()) == set()
    assert "/short" in short_profile["api_param_blocked"]
    assert "/prefix/short" not in short_profile["api_params"]

    reverse = scanner.empty_param_profile()
    scanner.add_api_method(reverse, "/short", "get")
    scanner.add_param_name(reverse, "exact_query", api_path="/short", source="query")
    reverse["api_param_blocked"].add("/prefix/short")
    assert any("exact_query" in suffix for suffix in scanner.query_suffixes("/short", reverse))
    assert scanner.query_suffixes("/prefix/short", reverse) == [""]

    def assert_blocked(case_source, path, no_request=False):
        graph = build_inline_graph(scanner, case_source, ast_mode="required")
        assert path not in graph.param_profile.get("api_params", {}), (path, graph.param_profile)
        if no_request:
            endpoints = {item.path: item for item in graph.apis}
            if path in endpoints:
                assert endpoints[path].source != "js_request", (path, endpoints[path])
            assert path not in graph.param_profile.get("api_methods", {}), (path, graph.param_profile)

    for spelling in ("Get", "GET"):
        path = "/case/%s" % spelling
        assert_blocked(
            'const wrap = formal => http.%s("%s", {params:formal}); wrap({forged:1});' % (spelling, path),
            path,
            no_request=True,
        )

    shadow_cases = {
        "/formal/reassigned": 'const wrap=formal=>{formal={forged:1};return http.get("/formal/reassigned",{params:formal})};wrap({safe:1});',
        "/formal/member-mutated": 'const wrap=formal=>{formal.forged=1;return http.get("/formal/member-mutated",{params:formal})};wrap({safe:1});',
        "/formal/block-shadow": 'const wrap=formal=>{{let formal={forged:1};http.get("/formal/block-shadow",{params:formal})}};wrap({safe:1});',
        "/formal/function-shadow": 'const wrap=formal=>{function inner(formal){return http.get("/formal/function-shadow",{params:formal})}return inner(formal)};wrap({safe:1});',
        "/formal/catch-shadow": 'const wrap=formal=>{try{work()}catch(formal){http.get("/formal/catch-shadow",{params:formal})}};wrap({safe:1});',
        "/formal/loop-shadow": 'const wrap=formal=>{for(const formal of items){http.get("/formal/loop-shadow",{params:formal})}};wrap({safe:1});',
        "/formal/var-redeclare": 'const wrap=formal=>{var formal;return http.get("/formal/var-redeclare",{params:formal})};wrap({safe:1});',
        "/formal/bare-for-in": 'const wrap=formal=>{for(formal in items){}return http.get("/formal/bare-for-in",{params:formal})};wrap({safe:1});',
        "/formal/bare-for-of": 'const wrap=formal=>{for(formal of items){}return http.get("/formal/bare-for-of",{params:formal})};wrap({safe:1});',
        "/receiver/block-shadow": 'const wrap=formal=>{{let http=fake;}return http.get("/receiver/block-shadow",{params:formal})};wrap({safe:1});',
        "/receiver/function-shadow": 'const wrap=formal=>{function inner(http){}return http.get("/receiver/function-shadow",{params:formal})};wrap({safe:1});',
        "/receiver/catch-shadow": 'const wrap=formal=>{try{work()}catch(http){}return http.get("/receiver/catch-shadow",{params:formal})};wrap({safe:1});',
        "/receiver/loop-shadow": 'const wrap=formal=>{for(const http of items){}return http.get("/receiver/loop-shadow",{params:formal})};wrap({safe:1});',
        "/receiver/switch-shadow": 'const wrap=formal=>{switch(flag){case 1: let http=fake;break;}return http.get("/receiver/switch-shadow",{params:formal})};wrap({safe:1});',
    }
    for path, case_source in shadow_cases.items():
        assert_blocked(case_source, path, no_request=path.startswith("/receiver/"))

    mutation_cases = {
        "/member/assign": 'http.get=fake;const wrap=formal=>http.get("/member/assign",{params:formal});wrap({forged:1});',
        "/member/update": 'http.get++;const wrap=formal=>http.get("/member/update",{params:formal});wrap({forged:1});',
        "/member/delete": 'delete http.get;const wrap=formal=>http.get("/member/delete",{params:formal});wrap({forged:1});',
        "/member/define": 'Object.defineProperty(http,"get",{value:fake});const wrap=formal=>http.get("/member/define",{params:formal});wrap({forged:1});',
        "/member/defines": 'Object.defineProperties(http,{get:{value:fake}});const wrap=formal=>http.get("/member/defines",{params:formal});wrap({forged:1});',
        "/member/object-assign": 'Object.assign(http,{get:fake});const wrap=formal=>http.get("/member/object-assign",{params:formal});wrap({forged:1});',
        "/member/dynamic-define": 'Object.defineProperty(http,key,{value:fake});const wrap=formal=>http.get("/member/dynamic-define",{params:formal});wrap({forged:1});',
        "/member/dynamic-assign": 'Object.assign(http,descriptor);const wrap=formal=>http.get("/member/dynamic-assign",{params:formal});wrap({forged:1});',
        "/member/computed-write": 'http[key]=fake;const wrap=formal=>http.get("/member/computed-write",{params:formal});wrap({forged:1});',
        "/member/computed-update": 'http[key]++;const wrap=formal=>http.get("/member/computed-update",{params:formal});wrap({forged:1});',
        "/member/reflect-set": 'Reflect.set(http,key,fake);const wrap=formal=>http.get("/member/reflect-set",{params:formal});wrap({forged:1});',
        "/member/reflect-delete": 'Reflect.deleteProperty(http,key);const wrap=formal=>http.get("/member/reflect-delete",{params:formal});wrap({forged:1});',
        "/member/assign-spread": 'Object.assign(http,{...descriptor});const wrap=formal=>http.get("/member/assign-spread",{params:formal});wrap({forged:1});',
        "/member/assign-computed": 'Object.assign(http,{[key]:fake});const wrap=formal=>http.get("/member/assign-computed",{params:formal});wrap({forged:1});',
    }
    for path, case_source in mutation_cases.items():
        assert_blocked(case_source, path, no_request=True)

    assert_blocked(
        'const opaque=value=>({forged:1});const wrap=formal=>http.get("/shape/opaque",{params:formal});wrap(opaque({safe:1}));',
        "/shape/opaque",
    )
    assert_blocked(
        'const weak=(target,source)=>{for(const key in source){source[key]=target[key]}return source};'
        'const wrap=formal=>http.get("/shape/weak",{params:formal});wrap(weak({}, {forged:1}));',
        "/shape/weak",
    )
    for path, helper in {
        "/shape/partial": 'const copy=(target,source)=>{if(flag)for(const key in source)target[key]=source[key];return target};',
        "/shape/alternate": 'const copy=(target,source)=>{for(const key in source)target[key]=source[key];if(flag)return source;return target};',
        "/shape/early": 'const copy=(target,source)=>{if(flag)return target;for(const key in source)target[key]=source[key];return target};',
    }.items():
        assert_blocked(
            helper + 'const wrap=formal=>http.get("%s",{params:formal});wrap(copy({}, {forged:1}));' % path,
            path,
        )

    # Rejected wrapper facts remain inventory-only and cannot influence active
    # variants for an unrelated read endpoint.
    pollution_source = (
        'const opaque=value=>({poison_name:1});'
        'const wrap=formal=>http.get("/gamma-api/rejected",{params:formal});'
        'wrap(opaque({poison_name:1}));'
        'http.get("/gamma-api/items/list",{params:{trusted_direct:1}});'
    )
    pollution_graph = build_inline_graph(scanner, pollution_source, ast_mode="required")
    assert pollution_graph.param_profile["api_params"]["/gamma-api/items/list"] == {"trusted_direct"}
    variants = scanner.request_variants(
        "/gamma-api/items/list", "GET", "", None,
        param_profile=pollution_graph.param_profile,
    )
    assert all("poison_name" not in suffix for suffix, _body in variants), variants

    # A rejected same-path wrapper must not erase an independent trusted fact.
    same_path = "/delta-api/resources/search"
    same_source = (
        'const opaque=value=>({rejected_fact:1});'
        'const wrap=formal=>http.get("%s",{params:formal});'
        'wrap(opaque({rejected_fact:1}));'
        'http.get("%s",{params:{kept_fact:1}});' % (same_path, same_path)
    )
    same_graph = build_inline_graph(scanner, same_source, ast_mode="required")
    assert same_graph.param_profile["api_params"][same_path] == {"kept_fact"}, same_graph.param_profile

    # Independent lexical wrapper bindings with the same spelling remain
    # deterministic and do not cross-contaminate one another.
    independent = (
        '{const wrap=formal=>http.get("/epsilon-api/one",{params:formal});wrap({first_key:1});}'
        '{const wrap=formal=>http.get("/epsilon-api/two",{params:formal});wrap({second_key:1});}'
    )
    independent_graph = build_inline_graph(scanner, independent, ast_mode="required")
    assert independent_graph.param_profile["api_params"]["/epsilon-api/one"] == {"first_key"}
    assert independent_graph.param_profile["api_params"]["/epsilon-api/two"] == {"second_key"}

    malformed_paths = (
        "/api/../admin", "/api/..;matrix/admin", "/api/%252e%252e/admin",
        "/api/%252fadmin", "/api/%255cadmin", "/api/\uff0fadmin", "/api/\ufffd",
    )
    for index, path in enumerate(malformed_paths):
        bad_source = 'const wrap=formal=>http.get(%s,{params:formal});wrap({forged:1});' % json.dumps(path)
        analysis = analyze_javascript_ast(
            bad_source, "http://example.test/chunk.js", "http://example.test/",
            mode="required", limits={"max_bytes": 100000, "max_nodes": 20000, "max_expressions": 4000},
        )
        assert analysis["param_bindings"] == [], (index, analysis["param_bindings"])
        assert analysis["apis"] == [], (index, analysis["apis"])
        assert scanner.extract_apis('const route=%s;' % json.dumps(path)) == set(), (index, path)
        bad_graph = build_inline_graph(scanner, bad_source, ast_mode="required")
        assert path not in {item.path for item in bad_graph.apis}, (index, bad_graph.apis)
        for field in ("api_params", "api_param_sources", "api_methods"):
            assert path not in bad_graph.param_profile.get(field, {}), (index, field, bad_graph.param_profile)

    valid_profile_path = "/zeta-api/profile/search"
    malformed_profile = scanner.empty_param_profile()
    malformed_profile.update({
        "names": {"inventory_name"},
        "api_params": {valid_profile_path: {"kept_name"}, malformed_paths[0]: {"bad_name"}},
        "api_param_sources": {
            valid_profile_path: {"query": {"kept_name"}},
            malformed_paths[1]: {"query": {"bad_name"}},
        },
        "api_param_shapes": {
            valid_profile_path: {"json": {"parent": {"kept_child"}}},
            malformed_paths[2]: {"json": {"parent": {"bad_child"}}},
        },
        "api_param_specs": {
            valid_profile_path: {"query": {"kept_name": {"name": "kept_name", "type": "string"}}},
            malformed_paths[3]: {"query": {"bad_name": {"name": "bad_name", "type": "string"}}},
        },
        "api_methods": {valid_profile_path: {"get"}, malformed_paths[4]: {"post"}},
        "api_content_types": {valid_profile_path: {"application/json"}, malformed_paths[5]: {"text/plain"}},
        "api_path_templates": {
            valid_profile_path: {valid_profile_path + "/{item}", malformed_paths[0]},
            malformed_paths[6]: {valid_profile_path},
        },
        "_apis_from_params": {valid_profile_path, malformed_paths[1]},
        "api_param_blocked": {"/zeta-api/opaque/search", malformed_paths[2]},
    })
    malformed_destination = scanner.empty_param_profile()
    malformed_destination["api_params"] = "not-a-map"
    scanner.merge_param_profiles(malformed_destination, malformed_profile)
    wire = scanner.serialize_param_profile(malformed_destination)
    round_trip = scanner.deserialize_param_profile(json.loads(json.dumps(wire)))
    for profile in (malformed_destination, round_trip):
        assert set(profile["api_params"]) == {valid_profile_path}, profile
        assert set(profile["api_param_sources"]) == {valid_profile_path}, profile
        assert set(profile["api_param_shapes"]) == {valid_profile_path}, profile
        assert set(profile["api_param_specs"]) == {valid_profile_path}, profile
        assert set(profile["api_methods"]) == {valid_profile_path}, profile
        assert set(profile["api_content_types"]) == {valid_profile_path}, profile
        assert set(profile["api_path_templates"]) == {valid_profile_path}, profile
        assert profile["api_path_templates"][valid_profile_path] == {valid_profile_path + "/{item}"}
        assert profile["_apis_from_params"] == {valid_profile_path}
        assert profile["api_param_blocked"] == {"/zeta-api/opaque/search"}


def assert_prefix_inventory_state_and_bounds(scanner):
    page = "https://prefix.synthetic.test/one/two/index.html"
    for fallback_name in ("request_failure", "phase2_timeout"):
        record = scanner.baseline_api_result(page, fallback=fallback_name)
        assert record["fallback"] == fallback_name, record
        generated = [api for api in record["apis"] if scanner.is_prefix_inventory_api(record, api)]
        assert generated and len(generated) <= scanner.MAX_PREFIX_INVENTORY_PATHS, record
        assert all(scanner.validate_root_relative_path(api) == api for api in generated), generated
        assert all(record["api_meta"][api]["sources"] == ["prefix_inventory"] for api in generated)
        for api in generated:
            profile, single_variant = scanner.api_probe_policy(record, api)
            assert single_variant is True and profile == scanner.empty_param_profile()
            assert {item[1] for item in scanner.scheduled_bypass_tests(api, scanner.FAST_BYPASS, profile)} == {"GET"}

    prefixes = {"/p%03d" % index for index in range(128)}
    apis = {"/endpoint-%03d/read" % index for index in range(128)}
    bounded = scanner.generate_prefix_inventory(apis, prefixes)
    assert len(bounded["prefixes"]) == scanner.MAX_PREFIX_INVENTORY_PREFIXES, bounded["prefixes"]
    assert len(bounded["generated"]) == scanner.MAX_PREFIX_INVENTORY_PATHS, len(bounded["generated"])
    assert bounded == scanner.generate_prefix_inventory(reversed(sorted(apis)), reversed(sorted(prefixes)))
    assert all(scanner.validate_root_relative_path(path) == path for path in bounded["generated"])

    invalid_prefixes = {
        "//foreign.synthetic.test", "/bad//", "/bad/../prefix", "/bad%252fescape", "/bad;matrix",
        "/bad\\slash", "/bad\ufffd", "/bad\u2215slash",
    }
    assert scanner.generate_prefix_inventory({"/safe/read"}, invalid_prefixes)["generated"] == ()
    no_compound = scanner.generate_prefix_inventory(
        {"/p000/already", "/fresh"}, {"/p000", "/p001"},
    )["generated"]
    assert "/p000/fresh" in no_compound and "/p001/fresh" in no_compound, no_compound
    assert not any(path.endswith("/p000/already") for path in no_compound), no_compound

    path = "/tenant-api/items/search"

    def exact_profile():
        profile = scanner.empty_param_profile()
        scanner.add_api_method(profile, path, "post")
        scanner.add_param_name(profile, "filter", api_path=path, source="json")
        scanner.add_api_content_type(profile, path, "application/json")
        return profile

    pure_source = {
        "base": "http://prefix-replay.synthetic.test:8101", "apis": [path],
        "api_meta": {path: {"confidence": 0.25, "sources": ["prefix_inventory"]}},
        "param_profile": exact_profile(),
    }
    empty_peer = {
        "base": "http://prefix-replay.synthetic.test:8102", "apis": [],
        "api_meta": {}, "param_profile": scanner.empty_param_profile(),
    }
    pure_records = [scanner.deserialize_scan_record(scanner.serialize_scan_record(item)) for item in (pure_source, empty_peer)]
    assert scanner.apply_cross_base_replay(pure_records, "host", 0) == (0, 0), pure_records
    assert pure_records[1].get("replay_apis", []) == []
    assert scanner.bound_body_tasks([pure_source], max_per_target=0) == []
    assert scanner.bound_param_tasks([pure_source], max_per_target=0) == []
    assert not scanner.carry_replay_param_profile(empty_peer, pure_source, path)

    def replay_records(reverse=False):
        local = {
            "base": "http://exact-replay.synthetic.test:8201", "apis": [path],
            "api_meta": {path: {"confidence": 0.25, "sources": ["prefix_inventory"]}},
            "param_profile": scanner.empty_param_profile(),
        }
        exact = {
            "base": "http://exact-replay.synthetic.test:8202", "apis": [path],
            "api_meta": {path: {"confidence": 0.96, "sources": ["js_request"]}},
            "param_profile": exact_profile(),
        }
        values = [local, exact]
        if reverse:
            values.reverse()
        values = [scanner.deserialize_scan_record(scanner.serialize_scan_record(item)) for item in values]
        scanner.apply_cross_base_replay(values, "host", 0)
        return {item["base"]: item for item in values}

    forward = replay_records(False)
    reverse = replay_records(True)
    local_base = "http://exact-replay.synthetic.test:8201"
    exact_base = "http://exact-replay.synthetic.test:8202"
    for records in (forward, reverse):
        local = records[local_base]
        assert path not in local.get("replay_apis", []), local
        assert local["api_meta"][path]["sources"] == ["js_request"], local["api_meta"]
        assert scanner.api_methods_for(local["param_profile"], path) == {"post"}
        assert scanner.bound_param_names_by_source(local["param_profile"], path, "json") == ["filter"]
        active_profile, single_variant = scanner.api_probe_policy(local, path)
        assert active_profile is local["param_profile"] and single_variant is False
        assert records[exact_base].get("replay_apis", []) == []
        assert records[exact_base]["api_meta"][path]["sources"] == ["js_request"]
    assert scanner.serialize_scan_record(forward[local_base]) == scanner.serialize_scan_record(reverse[local_base])

    mixed_a = scanner._merge_api_meta_items([
        {"confidence": 0.25, "sources": ["prefix_inventory"]},
        {"confidence": 0.80, "sources": ["js-graph"]},
    ])
    mixed_b = scanner._merge_api_meta_items([
        {"confidence": 0.80, "sources": ["js-graph"]},
        {"confidence": 0.25, "sources": ["prefix_inventory"]},
    ])
    assert mixed_a == mixed_b == {"confidence": 0.8, "sources": ["js-graph"]}

    exact = ["/ordinary/read-%02d" % index for index in range(40)]
    proven = "/service-api/proven/read"
    prefix_paths = list(bounded["generated"])
    quota_target = {
        "apis": prefix_paths + exact + [proven],
        "api_meta": {
            **{item: {"confidence": 0.25, "sources": ["prefix_inventory"]} for item in prefix_paths},
            **{item: {"confidence": 0.8, "sources": ["js-graph"]} for item in exact},
            proven: {"confidence": 0.96, "sources": ["js_request"]},
        },
    }
    seeds = scanner.phase3_seed_candidates(quota_target)
    assert proven in seeds and seeds.index(proven) < next(
        (index for index, api in enumerate(seeds) if scanner.is_prefix_inventory_api(quota_target, api)),
        len(seeds),
    ), seeds
    assert sum(scanner.is_prefix_inventory_api(quota_target, api) for api in seeds) <= scanner.MAX_PREFIX_INVENTORY_PHASE3_SEEDS

    exact_business = "/exact-api/business/query"
    exact_file = "/exact-api/files/export"
    high_prefix = ["/pref-%03d/priority/admin/read" % index for index in range(96)]
    candidate = {
        "base": "http://phase3-prefix.synthetic.test",
        "apis": high_prefix + [exact_business, exact_file],
        "api_meta": {
            **{item: {"confidence": 0.99, "sources": ["prefix_inventory"]} for item in high_prefix},
            exact_business: {"confidence": 0.80, "sources": ["js-graph"]},
            exact_file: {"confidence": 0.80, "sources": ["js-graph"]},
        },
        "param_profile": scanner.empty_param_profile(),
    }
    assert scanner.business_layer_apis(candidate) == [], scanner.business_layer_apis(candidate)
    assert scanner.file_layer_apis(candidate) == [], scanner.file_layer_apis(candidate)
    business_tasks = scanner.layer_tasks_for_candidates([candidate], lambda _target: high_prefix + [exact_business], "business")
    file_tasks = scanner.layer_tasks_for_candidates([candidate], lambda _target: high_prefix + [exact_file], "file")
    assert business_tasks == [], business_tasks
    assert file_tasks == [], file_tasks
    future_tasks = scanner.round_robin_tasks([candidate], lambda _target: high_prefix + [exact_business])
    assert future_tasks == [], future_tasks
    initial_tasks = scanner.round_robin_tasks(
        [candidate], lambda _target: high_prefix + [exact_business], allow_prefix_inventory=True,
    )
    assert exact_business not in [task[1] for task in initial_tasks]
    assert sum(scanner.is_prefix_inventory_api(candidate, task[1]) for task in initial_tasks) == len(high_prefix)
    old_allow_active = scanner.args.allow_active_post
    try:
        scanner.args.allow_active_post = True
        prefix_profile, prefix_single = scanner.api_probe_policy(candidate, high_prefix[0])
        assert prefix_single and {item[1] for item in scanner.scheduled_bypass_tests(
            high_prefix[0], scanner.FAST_BYPASS, prefix_profile,
        )} == {"GET"}
    finally:
        scanner.args.allow_active_post = old_allow_active

    producer_sources = set(scanner.API_META_SOURCES)
    assert producer_sources == {
        "api_fuzz", "backend_baseline", "baseline", "business_pattern", "extra_wordlist",
        "html", "js", "js-graph", "js_literal", "js_request", "legacy_baseline",
        "legacy_recovery", "openapi", "param_binding", "prefix_inventory", "react_route",
        "swagger", "vue_router",
    }, producer_sources
    for source in sorted(producer_sources):
        item = scanner._canonical_api_meta_item({"confidence": 0.5, "sources": [source]})
        assert item["sources"] == [source], (source, item)
    unknown = scanner._canonical_api_meta_item({"confidence": 0.99, "sources": ["forged_source"]})
    assert unknown == {"confidence": 0.25, "sources": ["prefix_inventory"]}, unknown
    prefix_unknown = scanner._merge_api_meta_items([
        {"confidence": 0.25, "sources": ["prefix_inventory"]},
        {"confidence": 0.99, "sources": ["forged_source"]},
    ])
    assert prefix_unknown == {"confidence": 0.25, "sources": ["prefix_inventory"]}, prefix_unknown
    live_meta = {}
    scanner.add_api_meta(live_meta, "/live-api/read", "forged_source", 0.99)
    assert live_meta == {"/live-api/read": {"confidence": 0.25, "sources": ["prefix_inventory"]}}, live_meta
    for exact_source in sorted(scanner.API_META_EXACT_SOURCES):
        forward_meta = scanner._merge_api_meta_items([
            {"confidence": 0.25, "sources": ["prefix_inventory"]},
            {"confidence": 0.8, "sources": [exact_source]},
        ])
        reverse_meta = scanner._merge_api_meta_items(list(reversed([
            {"confidence": 0.25, "sources": ["prefix_inventory"]},
            {"confidence": 0.8, "sources": [exact_source]},
        ])))
        assert forward_meta == reverse_meta and forward_meta["sources"] == [exact_source], (exact_source, forward_meta)
        wire_target = scanner.deserialize_scan_record(scanner.serialize_scan_record({
            "apis": ["/wire-api/read"],
            "api_meta": {"/wire-api/read": {"confidence": 0.8, "sources": ["prefix_inventory", "forged_source", exact_source]}},
        }))
        assert exact_source in wire_target["api_meta"]["/wire-api/read"]["sources"]
        assert "prefix_inventory" not in wire_target["api_meta"]["/wire-api/read"]["sources"]

    unknown_path = "/unknown-api/only"
    unknown_profile = scanner.empty_param_profile()
    scanner.add_api_method(unknown_profile, unknown_path, "post")
    scanner.add_param_name(unknown_profile, "forged_body", api_path=unknown_path, source="json")
    unknown_target = {
        "apis": [unknown_path],
        "api_meta": {unknown_path: {"confidence": 0.99, "sources": ["forged_source"]}},
        "param_profile": unknown_profile,
    }
    unknown_profile_for_probe, unknown_single = scanner.api_probe_policy(unknown_target, unknown_path)
    assert unknown_single and unknown_profile_for_probe == scanner.empty_param_profile()
    assert unknown_path in scanner.phase3_seed_candidates(unknown_target)
    assert scanner.phase3_seed_candidates(unknown_target).count(unknown_path) == 1
    assert scanner.bound_body_tasks([unknown_target], max_per_target=0) == []
    assert scanner.layer_tasks_for_candidates([unknown_target], lambda target: target["apis"], "business") == []
    unknown_wire = scanner.serialize_scan_record(unknown_target)
    unknown_round = scanner.deserialize_scan_record(unknown_wire)
    assert unknown_round["api_meta"] == {unknown_path: {"confidence": 0.25, "sources": ["prefix_inventory"]}}, unknown_round
    round_profile, round_single = scanner.api_probe_policy(unknown_round, unknown_path)
    assert round_single and round_profile == scanner.empty_param_profile()
    assert scanner.layer_tasks_for_candidates([unknown_round], lambda target: target["apis"], "business") == []

    malformed_path = "/malformed-api/query"
    malformed_profiles = (
        {"confidence": 0.99, "sources": "js_request"},
        {"confidence": 0.99, "sources": {"js_request": True}},
        {"confidence": 0.99, "sources": 7},
        {"confidence": 0.99, "sources": None},
        {"confidence": 0.99, "sources": ["js_request", 7]},
        "nonmapping-item",
    )
    malformed_records = []
    for index, malformed_meta in enumerate(malformed_profiles):
        forged_profile = scanner.empty_param_profile()
        scanner.add_api_method(forged_profile, malformed_path, "post")
        scanner.add_param_name(forged_profile, "body_%d" % index, api_path=malformed_path, source="json")
        scanner.add_api_content_type(forged_profile, malformed_path, "application/json")
        live = {
            "base": "http://malformed-replay.synthetic.test:%d" % (8500 + index),
            "apis": [malformed_path],
            "api_meta": {malformed_path: malformed_meta},
            "param_profile": forged_profile,
        }
        wire = scanner.serialize_scan_record(live)
        encoded = json.dumps(wire, sort_keys=True, allow_nan=False)
        round_record = scanner.deserialize_scan_record(json.loads(encoded))
        assert round_record["api_meta"] == {
            malformed_path: {"confidence": 0.25, "sources": ["prefix_inventory"]},
        }, (index, round_record)
        inert_profile, inert_single = scanner.api_probe_policy(round_record, malformed_path)
        assert inert_single and inert_profile == scanner.empty_param_profile(), (index, inert_profile)
        assert {item[1] for item in scanner.scheduled_bypass_tests(
            malformed_path, scanner.FAST_BYPASS, inert_profile,
        )} == {"GET"}
        assert scanner.bound_body_tasks([round_record], max_per_target=0) == []
        assert scanner.bound_param_tasks([round_record], max_per_target=0) == []
        assert scanner.layer_tasks_for_candidates([round_record], lambda target: target["apis"], "business") == []
        assert scanner.phase3_seed_candidates(round_record).count(malformed_path) == 1
        malformed_records.append(round_record)

    for index, malformed_root in enumerate(("bad-root", 7, None, ["bad-root"])):
        root_record = scanner.deserialize_scan_record(scanner.serialize_scan_record({
            "base": "http://malformed-root.synthetic.test:%d" % (8600 + index),
            "apis": [malformed_path], "api_meta": malformed_root,
            "param_profile": scanner.empty_param_profile(),
        }))
        assert root_record["api_meta"] == {
            malformed_path: {"confidence": 0.25, "sources": ["prefix_inventory"]},
        }, root_record

    absent_record = scanner.deserialize_scan_record(scanner.serialize_scan_record({
        "base": "http://absent-meta.synthetic.test", "apis": [malformed_path],
        "param_profile": scanner.empty_param_profile(),
    }))
    assert "api_meta" not in absent_record and not scanner.is_initial_screen_only_api(absent_record, malformed_path)

    pure_peer = {
        "base": "http://malformed-replay.synthetic.test:8999", "apis": [],
        "api_meta": {}, "param_profile": scanner.empty_param_profile(),
    }
    pure_source = malformed_records[0]
    source_snapshot = scanner.serialize_scan_record(pure_source)
    pure_pair = [copy.deepcopy(pure_source), copy.deepcopy(pure_peer)]
    assert scanner.apply_cross_base_replay(pure_pair, "host", 0) == (0, 0), pure_pair
    assert pure_pair[1].get("replay_apis", []) == []
    assert scanner.serialize_scan_record(pure_pair[0]) == source_snapshot

    exact_profile = scanner.empty_param_profile()
    scanner.add_api_method(exact_profile, malformed_path, "post")
    scanner.add_param_name(exact_profile, "trusted_body", api_path=malformed_path, source="json")
    scanner.add_api_content_type(exact_profile, malformed_path, "application/json")
    exact_template = {
        "base": "http://exact-malformed.synthetic.test:8701", "apis": [malformed_path],
        "api_meta": {malformed_path: {"confidence": 0.96, "sources": ["js_request"]}},
        "param_profile": exact_profile,
    }
    inert_template = {
        "base": "http://exact-malformed.synthetic.test:8702", "apis": [malformed_path],
        "api_meta": {malformed_path: {"confidence": 0.99, "sources": "js_request"}},
        "param_profile": scanner.empty_param_profile(),
    }
    promoted_snapshots = []
    for templates in ((inert_template, exact_template), (exact_template, inert_template)):
        records = [scanner.deserialize_scan_record(scanner.serialize_scan_record(copy.deepcopy(item))) for item in templates]
        exact_before = scanner.serialize_scan_record(next(item for item in records if item["base"].endswith(":8701")))
        scanner.apply_cross_base_replay(records, "host", 0)
        by_base = {item["base"]: item for item in records}
        promoted = by_base["http://exact-malformed.synthetic.test:8702"]
        assert promoted["api_meta"][malformed_path]["sources"] == ["js_request"], promoted
        assert scanner.api_methods_for(promoted["param_profile"], malformed_path) == {"post"}
        assert scanner.bound_param_names_by_source(promoted["param_profile"], malformed_path, "json") == ["trusted_body"]
        assert scanner.serialize_scan_record(by_base["http://exact-malformed.synthetic.test:8701"]) == exact_before
        promoted_snapshots.append(json.dumps(scanner.serialize_scan_record(promoted), sort_keys=True, allow_nan=False))
    assert promoted_snapshots[0] == promoted_snapshots[1], promoted_snapshots

    safe_path = "/stable-api/good"
    invalid_path = "/bad/../escape"
    raw_record = {
        "base": "http://jsonl-path.synthetic.test",
        "apis": [invalid_path, safe_path, "/bad%252fslash", safe_path + "?ignored=1"],
        "api_meta": {
            invalid_path: {"confidence": 0.96, "sources": ["js_request"]},
            safe_path: {"confidence": 0.80, "sources": ["js-graph"]},
        },
        "param_profile": {
            "names": [], "seeds": [], "file_seeds": [],
            "api_params": {invalid_path: ["bad"], safe_path: ["good"]},
            "api_param_sources": {invalid_path: {"query": ["bad"]}, safe_path: {"query": ["good"]}},
            "api_param_shapes": {}, "api_methods": {invalid_path: ["post"], safe_path: ["get"]},
            "api_param_specs": {}, "api_content_types": {}, "api_path_templates": {},
            "apis_from_params": [invalid_path, safe_path], "api_param_blocked": [invalid_path],
        },
        "replay_apis": [invalid_path, safe_path],
        "prefix_inventory_paths": [invalid_path, safe_path],
    }
    self_healed = scanner.deserialize_scan_record(scanner.serialize_scan_record(raw_record))
    assert self_healed["apis"] == [safe_path], self_healed
    assert self_healed["api_meta"] == {safe_path: {"confidence": 0.8, "sources": ["js-graph"]}}, self_healed
    assert set(self_healed["param_profile"]["api_params"]) == {safe_path}, self_healed["param_profile"]
    assert self_healed["replay_apis"] == [safe_path]
    assert self_healed["prefix_inventory_paths"] == [safe_path]
    assert safe_path in scanner.phase3_seed_candidates(self_healed)
    assert scanner.business_layer_apis(self_healed) == []
    assert invalid_path not in scanner.phase3_seed_candidates(raw_record)
    assert invalid_path not in scanner.business_layer_apis(raw_record)
    assert invalid_path not in scanner.file_layer_apis(raw_record)
    inventory = scanner.phase2_inventory_record(raw_record, include_param_profile=True)
    assert inventory["apis"] == [safe_path] and inventory["api_count"] == 1, inventory

    with tempfile.TemporaryDirectory() as tmpdir:
        jsonl = Path(tmpdir) / "mixed.jsonl"
        bad_shape = dict(raw_record)
        bad_shape["param_profile"] = "invalid"
        good = scanner.serialize_scan_record({"base": "http://jsonl-good.synthetic.test", "apis": [safe_path], "api_meta": {safe_path: {"confidence": 0.8, "sources": ["js-graph"]}}})
        jsonl.write_text("\n".join(json.dumps(item) for item in (raw_record, bad_shape, good)) + "\n", encoding="utf-8")
        streamed = list(scanner.StreamedResultSet(str(jsonl), 3))
        assert len(streamed) == 2, streamed
        assert streamed[0]["apis"] == [safe_path] and streamed[1]["base"] == good["base"], streamed


def main():
    scanner = load_scanner()
    server = LabServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            assert_default_large_bundle(scanner, server, tmp)
            assert_truncated_run(scanner, server, tmp)
        assert_http_bounds(scanner, server)
        assert_legacy_fetch_callback(scanner)
        assert_request_sink_matrix(scanner)
        assert_lexically_honest_method_options(scanner)
        assert_callee_proven_method_contract(scanner)
        assert_cross_asset_body_method_isolation(scanner)
        assert_canonical_quota_dedup(scanner)
        assert_extra_wordlist_boundaries(scanner)
        assert_scope_aware_forwarded_wrapper_params(scanner)
        assert_prefix_inventory_state_and_bounds(scanner)
    finally:
        server.shutdown()
        server.server_close()
    print("V37 LARGE VITE BUNDLE PRIORITY LAB PASS")


if __name__ == "__main__":
    main()
