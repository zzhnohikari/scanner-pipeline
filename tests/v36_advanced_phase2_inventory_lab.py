#!/usr/bin/env python3
"""Deterministic local lab for bounded Phase 2 advanced static discovery."""

import base64
import json
import os
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

import pipeline.js_advanced_inventory as advanced_inventory  # noqa: E402
from pipeline.js_advanced_inventory import analyze_javascript_ast  # noqa: E402
from pipeline.js_extractor import build_js_graph, deterministic_subpage_links  # noqa: E402


RAW_MARKER = "RAW_SOURCE_MARKER_MUST_NOT_PERSIST"
QUERY_MARKERS = (
    "QUERY_RESOURCE_SECRET", "IMPORT_QUERY_SECRET", "MANIFEST_QUERY_SECRET",
    "MAP_QUERY_SECRET", "SOURCE_EMAIL_MARKER@example.test", "SOURCE_TOKEN_MARKER",
    "98765432109876543210", "source-private-file.pdf",
)


class RecordingServer(ThreadingHTTPServer):
    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.hits = []


class BaseHandler(BaseHTTPRequestHandler):
    def log_message(self, _fmt, *_args):
        return

    def send_body(self, body, content_type="text/plain", status=200):
        data = body if isinstance(body, bytes) else str(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()


class CrossHandler(BaseHandler):
    def do_GET(self):
        self.server.hits.append(self.path)
        self.send_body("cross origin must remain untouched")


def app_handler(cross_port):
    external_map = json.dumps({
        "version": 3,
        "sources": ["src/original.js", "../escape.js"],
        "sourcesContent": [
            (
                "fetch('/api/from-external-map',{params:{accountId:98765432109876543210,"
                "email:'SOURCE_EMAIL_MARKER@example.test',token:'SOURCE_TOKEN_MARKER'}});"
                "const privateFile='source-private-file.pdf';const marker='%s';" % RAW_MARKER
            ),
            "fetch('/api/path-traversal-must-not-appear')",
        ],
        "names": [],
        "mappings": "",
    })
    inline_map = json.dumps({
        "version": 3,
        "sources": ["src/inline.js"],
        "sourcesContent": ["fetch('/api/from-inline-map'); const marker='%s';" % RAW_MARKER],
        "names": [],
        "mappings": "",
    }, separators=(",", ":"))
    inline_uri = "data:application/json;base64," + base64.b64encode(inline_map.encode()).decode()

    class AppHandler(BaseHandler):
        def do_GET(self):
            self.server.hits.append(self.path)
            path = urlparse(self.path).path
            if path == "/":
                anchors = "".join('<a href="/page/%d">p</a>' % value for value in range(9, -1, -1))
                return self.send_body(
                    "<!doctype html><html><head>"
                    '<script type="importmap" src="http://127.0.0.1:%d/cross-first-importmap.json"></script>' % cross_port
                    + '<link rel="manifest" href="http://127.0.0.1:%d/asset-manifest-cross-first.json">' % cross_port
                    + '<link rel="manifest" href="/asset-manifest.json?key=MANIFEST_QUERY_SECRET">'
                    '<link rel="modulepreload" href="/chunks/preload.js">'
                    '<script type="importmap">{"imports":{"inline":"/chunks/im-inline.js",'
                    '"cross":"http://127.0.0.1:%d/cross-import.js"}}</script>' % cross_port
                    + '<script type="importmap" src="/maps/importmap.json?token=IMPORT_QUERY_SECRET"></script>'
                    '<script type="importmap" src="/maps/redirect-importmap.json"></script>'
                    '<script src="/app.js"></script></head><body>' + anchors + "</body></html>",
                    "text/html",
                )
            if path.startswith("/page/"):
                return self.send_body(
                    "<!doctype html><html><head><title>subpage</title></head>"
                    "<body>deterministic subpage content long enough for phase two crawling</body></html>",
                    "text/html",
                )
            if path == "/app.js":
                return self.send_body(
                    'const root="/chunks/";const key="prod";'
                    'const files={prod:"member.js",dev:"dev.js"};'
                    'const selected=true?root+files[key]:root+files.dev;'
                    'function injectOnce(url){const node=document.createElement("script");'
                    'node.src=url;document.head.appendChild(node)}injectOnce(selected);'
                    'injectOnce("/chunks/noextension");'
                    'injectOnce("/chunks/query-required.js?token=QUERY_RESOURCE_SECRET");'
                    'injectOnce("/chunks/redirect.js");injectOnce("/chunks/scheme-redirect.js");'
                    'import(root+"dynamic.js");System.import(root+"system.js");'
                    'require(root+"required.js");fetch("/api/"+(true?"ast-users":"ast-profile"));'
                    'const bad="/asset-manifest-bad.json";'
                    'const huge="/asset-manifest-oversize.json";'
                    'const redirectManifest="/asset-manifest-redirect.json";'
                    'const cross="http://127.0.0.1:%d/asset-manifest-cross.json";' % cross_port
                    + "\n//# sourceMappingURL=http://127.0.0.1:%d/cross-first.map" % cross_port
                    + "\n//# sourceMappingURL=/maps/app.js.map?sig=MAP_QUERY_SECRET"
                    + "\n//# sourceMappingURL=/maps/redirect.map",
                    "application/javascript",
                )
            if path == "/chunks/dynamic.js":
                return self.send_body(
                    "fetch('/api/dynamic-chunk');\n//# sourceMappingURL=" + inline_uri,
                    "application/javascript",
                )
            if path == "/chunks/member.js":
                return self.send_body("fetch('/api/member-chunk');\n//# sourceMappingURL=/maps/malformed.map", "application/javascript")
            if path == "/chunks/system.js":
                return self.send_body("fetch('/api/system-chunk');\n//# sourceMappingURL=/maps/oversize.map", "application/javascript")
            if path == "/chunks/required.js":
                return self.send_body(
                    "fetch('/api/required-chunk');\n//# sourceMappingURL=http://127.0.0.1:%d/cross.map" % cross_port,
                    "application/javascript",
                )
            if path == "/chunks/noextension":
                return self.send_body("<html><script>fetch('/api/should-not-extract')</script></html>", "text/html")
            if path == "/chunks/query-required.js":
                if parse_qs(urlparse(self.path).query).get("token") == ["QUERY_RESOURCE_SECRET"]:
                    return self.send_body("fetch('/api/query-resource-loaded')", "application/javascript")
                return self.send_body("missing query", status=404)
            if path == "/chunks/redirect.js":
                return self.send_redirect("http://127.0.0.1:%d/redirected-asset.js" % cross_port)
            if path == "/chunks/scheme-redirect.js":
                return self.send_redirect("https://localhost:%d/scheme-changed.js" % self.server.server_address[1])
            if path.startswith("/chunks/"):
                return self.send_body("fetch('/api/" + path.rsplit("/", 1)[-1].replace(".js", "") + "')", "application/javascript")
            if path == "/maps/importmap.json":
                if parse_qs(urlparse(self.path).query).get("token") != ["IMPORT_QUERY_SECRET"]:
                    return self.send_body("missing query", status=404)
                return self.send_body(json.dumps({
                    "imports": {"external": "/chunks/im-external.js"},
                    "scopes": {"/scope/": {"scoped": "/chunks/im-scoped.js"}},
                }), "application/importmap+json")
            if path == "/maps/redirect-importmap.json":
                return self.send_redirect("http://127.0.0.1:%d/redirected-importmap.json" % cross_port)
            if path == "/asset-manifest.json":
                if parse_qs(urlparse(self.path).query).get("key") != ["MANIFEST_QUERY_SECRET"]:
                    return self.send_body("missing query", status=404)
                return self.send_body(json.dumps({
                    "files": {"main.js": "/chunks/manifest-main.js", "logo.svg": "/logo.svg"},
                    "entrypoints": ["/chunks/manifest-entry.js", "/styles.css"],
                    "dynamicImports": ["/chunks/manifest-dynamic.js"],
                    "manifest": "/manifest-nested.json",
                    "module": "http://127.0.0.1:%d/cross-from-manifest.js" % cross_port,
                    "icons": [{"src": "/icon.js"}],
                    "screenshots": [{"src": "/screenshot.js"}],
                    "shortcuts": [{"name": "bad", "icons": [{"src": "/shortcut.js"}]}],
                }), "application/json")
            if path == "/manifest-nested.json":
                return self.send_body(json.dumps({
                    "file": "/chunks/nested.js",
                    "manifest": "/asset-manifest.json",
                }), "application/json")
            if path == "/asset-manifest-bad.json":
                return self.send_body("{not-json", "application/json")
            if path == "/asset-manifest-oversize.json":
                return self.send_body('{"entrypoints":["/chunks/' + ("x" * 2048) + '.js"]}', "application/json")
            if path == "/asset-manifest-redirect.json":
                return self.send_redirect("http://127.0.0.1:%d/redirected-manifest.json" % cross_port)
            if path == "/maps/app.js.map":
                if parse_qs(urlparse(self.path).query).get("sig") != ["MAP_QUERY_SECRET"]:
                    return self.send_body("missing query", status=404)
                return self.send_body(external_map, "application/json")
            if path == "/maps/redirect.map":
                return self.send_redirect("http://127.0.0.1:%d/redirected.map" % cross_port)
            if path == "/maps/malformed.map":
                return self.send_body("{broken-map", "application/json")
            if path == "/maps/oversize.map":
                return self.send_body("x" * 2048, "application/json")
            return self.send_body("not found", status=404)

    return AppHandler


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_scanner():
    old_argv = sys.argv
    sys.argv = [str(SCANNER), "--no-proxy"]
    try:
        import pipeline.deep_scanner as scanner
        return scanner
    finally:
        sys.argv = old_argv


def build_local_graph(scanner, html, fetch_text, fetch_advanced_text, **overrides):
    options = {
        "page_url": "http://example.test/",
        "html": html,
        "fetch_text": fetch_text,
        "fetch_advanced_text": fetch_advanced_text,
        "extract_js_from_html": scanner.extract_js_from_html,
        "extract_links_from_html": lambda _html, _base: set(),
        "extract_apis": scanner.extract_apis,
        "extract_module_urls_from_content": scanner.extract_module_urls_from_content,
        "extract_prefixes_from_content": scanner.extract_prefixes_from_content,
        "extract_param_profile": scanner.extract_param_profile,
        "empty_param_profile": scanner.empty_param_profile,
        "merge_param_profiles": scanner.merge_param_profiles,
        "common_libs": scanner.COMMON_LIBS,
        "valid_sensitive_value": scanner.valid_sensitive_value,
        "ast_mode": "required",
        "advanced_limits": {
            "max_new_assets": 1,
            "inventory_max_declarations": 8,
            "import_map_max_count": 1,
            "manifest_max_count": 1,
        },
        "source_map_mode": "explicit",
        "source_map_limits": {"max_count": 1, "max_bytes": 4096, "max_sources": 4, "max_ratio": 8},
    }
    options.update(overrides)
    return build_js_graph(**options)


def test_ast_limits_and_real_parser():
    source = (
        'const root="/js/";const key="a";const files={a:"one.js",b:"two.js"};'
        'function load(x){const s=document.createElement("script");s.src=x}'
        'load(true?root+files[key]:root+files.b);import(root+"three.js");'
        'fetch("/api/"+(true?"users":"profile"));'
    )
    result = analyze_javascript_ast(source, "http://example.test/app.js", "http://example.test/", "required", {
        "max_bytes": 10000, "max_nodes": 60, "max_depth": 32,
        "max_expressions": 100, "max_assets": 2,
    })
    assert result["status"] == "parsed" and result["parser"] == "esprima", result
    assert result["truncated"] is True, result
    assert len(result["assets"]) <= 2, result
    oversize = analyze_javascript_ast(source, "http://example.test/app.js", "http://example.test/", "required", {
        "max_bytes": 10,
    })
    assert oversize["status"] == "oversize" and oversize["truncated"], oversize

    parser = advanced_inventory.esprima
    advanced_inventory.esprima = None
    try:
        unavailable = analyze_javascript_ast(source, "http://example.test/app.js", "http://example.test/", "auto", {})
        assert unavailable["status"] == "unavailable", unavailable
        try:
            analyze_javascript_ast(source, "http://example.test/app.js", "http://example.test/", "required", {})
            raise AssertionError("required AST mode accepted a missing parser")
        except RuntimeError as exc:
            assert "requirements-ast.txt" in str(exc), exc
    finally:
        advanced_inventory.esprima = parser


def test_required_cli_fails_before_output_without_parser():
    with tempfile.TemporaryDirectory() as tmp:
        outdir = Path(tmp) / "must-not-exist"
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        proc = subprocess.run(
            [sys.executable, "-S", str(SCANNER), "--js-ast-mode", "required", "--outdir", str(outdir)],
            text=True, capture_output=True, timeout=20, env=env,
        )
        assert proc.returncode == 2, (proc.returncode, proc.stdout, proc.stderr)
        assert "requirements-ast.txt" in proc.stderr, proc.stderr
        assert not outdir.exists(), list(Path(tmp).iterdir())


def test_html_fallback_and_hash_determinism():
    scanner = load_scanner()
    old_bs4 = scanner.HAS_BS4
    scanner.HAS_BS4 = False
    try:
        html = (
            '<script type="module" src="/assets/app.mjs"></script>'
            '<script type="importmap" src="/maps/importmap.json"></script>'
            '<link rel="modulepreload" href="/assets/lazy.js">'
            '<a href="/z">z</a><a href="/a#fragment">a</a>'
            '<a href="https://cross.example.test/no">cross</a>'
        )
        js = scanner.extract_js_from_html(html, "https://example.test/root/")
        links = scanner.extract_links_from_html(html, "https://example.test/root/")
        assert "https://example.test/assets/app.mjs" in js, js
        assert "https://example.test/assets/lazy.js" in js, js
        assert not any("importmap.json" in value for value in js), js
        assert links == {"https://example.test/z", "https://example.test/a"}, links
    finally:
        scanner.HAS_BS4 = old_bs4

    expected = deterministic_subpage_links({"/z", "/b", "/a", "/q", "/c"}, 3)
    assert expected == ["/a", "/b", "/c"], expected
    code = (
        "from pipeline.js_extractor import deterministic_subpage_links;"
        "print('|'.join(deterministic_subpage_links(set(['/z','/b','/a','/q','/c']),3)))"
    )
    outputs = []
    for seed in ("1", "77", "999"):
        env = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH=str(ROOT))
        outputs.append(subprocess.check_output([sys.executable, "-c", code], cwd=str(ROOT), env=env, text=True).strip())
    assert outputs == ["/a|/b|/c"] * 3, outputs


def test_active_limits_duplicate_priority_and_delete_inventory():
    scanner = load_scanner()
    ordinary_calls = []
    advanced_calls = []
    html = (
        '<script type="importmap" src="http://cross.test/cross-map.json"></script>'
        '<script type="importmap" src="/local-map.json"></script>'
        '<link rel="manifest" href="http://cross.test/asset-manifest-cross.json">'
        '<link rel="manifest" href="/asset-manifest.json">'
        '<script src="/existing"></script>'
    )

    def ordinary(url, max_size=500000):
        ordinary_calls.append(url)
        if url == "http://example.test/existing":
            return 200, url, (
                "fetch('/api/existing-ordinary');loadScript('/existing');loadScript('/novel.js');"
                "//# sourceMappingURL=http://cross.test/cross.map\n"
                "//# sourceMappingURL=/local.map"
            ), "text/plain"
        return 404, url, "", "text/plain"

    def advanced(url, max_size=500000):
        advanced_calls.append(url)
        path = urlparse(url).path
        if urlparse(url).hostname == "cross.test":
            raise AssertionError("cross-origin advanced fetch: " + url)
        if path == "/local-map.json":
            return 200, url, '{"imports":{}}', "application/json"
        if path == "/asset-manifest.json":
            return 200, url, json.dumps({"icons": [{"src": "/icon.js"}]}), "application/json"
        if path == "/local.map":
            return 200, url, json.dumps({"version": 3, "sources": [], "sourcesContent": [], "names": [], "mappings": ""}), "application/json"
        return 404, url, "", "text/plain"

    graph = build_local_graph(scanner, html, ordinary, advanced, js_limit=1)
    assert graph.api_paths() >= {"/api/existing-ordinary"}, (graph.api_paths(), ordinary_calls, advanced_calls, graph.stats)
    assert ordinary_calls == ["http://example.test/existing"], ordinary_calls
    assert "http://example.test/novel.js" in graph.discovered_urls, graph.discovered_urls
    assert all("cross.test" not in value for value in advanced_calls), advanced_calls
    assert graph.stats["import_maps_parsed"] == 1, graph.stats
    assert graph.stats["asset_manifest_parsed"] == 1, graph.stats
    assert graph.stats["source_map_parsed"] == 1, graph.stats
    assert not any(item["url"].endswith("/icon.js") for item in graph.js_resource_inventory), graph.js_resource_inventory

    for unlimited in (0, -1):
        unlimited_graph = build_local_graph(
            scanner, html, ordinary, advanced, js_limit=1,
            advanced_limits={
                "max_new_assets": unlimited,
                "inventory_max_declarations": unlimited,
                "import_map_max_count": unlimited,
                "manifest_max_count": unlimited,
            },
            source_map_limits={
                "max_count": unlimited, "max_bytes": 4096, "max_sources": unlimited, "max_ratio": 0,
            },
        )
        assert "http://example.test/novel.js" in unlimited_graph.discovered_urls, (unlimited, unlimited_graph.discovered_urls)
        assert unlimited_graph.stats["import_maps_parsed"] == 1, (unlimited, unlimited_graph.stats)
        assert unlimited_graph.stats["asset_manifest_parsed"] == 1, (unlimited, unlimited_graph.stats)
        assert unlimited_graph.stats["source_map_parsed"] == 1, (unlimited, unlimited_graph.stats)

    rejected_graph = build_local_graph(
        scanner,
        '<script type="importmap" src="/origin-change.json"></script>',
        lambda url, max_size=500000: (404, url, "", "text/plain"),
        lambda url, max_size=500000: (200, "http://cross.test/final.json", '{"imports":{}}', "application/json"),
        source_map_mode="off",
    )
    assert rejected_graph.import_map_inventory[0]["status"] == "origin_rejected", rejected_graph.import_map_inventory
    assert rejected_graph.stats["import_maps_parsed"] == 0, rejected_graph.stats

    dedup_advanced_calls = []
    duplicate_map_html = (
        '<script type="importmap" src="/dedup-map.json"></script>'
        '<a href="/subpage">subpage</a>'
    )

    def dedup_ordinary(url, max_size=500000):
        if url == "http://example.test/subpage":
            return 200, url, (
                '<script type="importmap" src="/dedup-map.json"></script>'
                '<div>subpage padding for deterministic target-global import-map deduplication</div>'
            ), "text/html"
        return 404, url, "", "text/plain"

    def dedup_advanced(url, max_size=500000):
        dedup_advanced_calls.append(url)
        return 200, url, '{"imports":{}}', "application/json"

    dedup_graph = build_local_graph(
        scanner, duplicate_map_html, dedup_ordinary, dedup_advanced,
        extract_links_from_html=lambda _html, _base: {"http://example.test/subpage"},
        source_map_mode="off",
    )
    assert dedup_advanced_calls == ["http://example.test/dedup-map.json"], dedup_advanced_calls
    assert dedup_graph.stats["import_maps_declared"] == 1, dedup_graph.stats

    delete_html = '<script>axios.delete("/api/delete-only");axios.get("/api/read-only")</script>'
    no_fetch = lambda url, max_size=500000: (_ for _ in ()).throw(AssertionError("unexpected fetch " + url))
    default_graph = build_local_graph(
        scanner, delete_html, no_fetch, no_fetch,
        source_map_mode="off", advanced_limits={"max_new_assets": 0}, include_delete_method=False,
    )
    assert "/api/delete-only" not in default_graph.api_paths(), default_graph.api_paths()
    assert "/api/read-only" in default_graph.api_paths(), default_graph.api_paths()
    enabled_graph = build_local_graph(
        scanner, delete_html, no_fetch, no_fetch,
        source_map_mode="off", advanced_limits={"max_new_assets": 0}, include_delete_method=True,
    )
    assert "/api/delete-only" in enabled_graph.api_paths(), enabled_graph.api_paths()
    assert enabled_graph.param_profile["api_methods"]["/api/delete-only"] == {"delete"}, enabled_graph.param_profile


def test_cross_origin_subpage_inline_import_map_inventory_only():
    scanner = load_scanner()

    class RootHandler(BaseHandler):
        def do_GET(self):
            self.server.hits.append(self.path)
            if urlparse(self.path).path == "/must-not-load.js":
                return self.send_body("fetch('/api/must-not-be-admitted')", "application/javascript")
            return self.send_body("not found", status=404)

    root = RecordingServer(("127.0.0.1", 0), RootHandler)
    root_port = root.server_address[1]

    class SubpageHandler(BaseHandler):
        def do_GET(self):
            self.server.hits.append(self.path)
            if urlparse(self.path).path == "/foreign-subpage":
                return self.send_body(
                    "<!doctype html><html><head>"
                    '<script type="importmap">{"imports":{"blocked":'
                    '"http://localhost:%d/must-not-load.js"}}</script>' % root_port
                    + "</head><body>ordinary cross-port subpage padding "
                    + ("x" * 160) + "</body></html>",
                    "text/html",
                )
            return self.send_body("not found", status=404)

    subpage = RecordingServer(("127.0.0.1", 0), SubpageHandler)
    for server in (root, subpage):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        root_url = "http://localhost:%d/" % root_port
        subpage_url = "http://localhost:%d/foreign-subpage" % subpage.server_address[1]
        graph = build_local_graph(
            scanner,
            '<a href="%s">ordinary cross-port subpage</a>' % subpage_url,
            scanner.http_get,
            scanner.exact_origin_http_get,
            page_url=root_url,
            extract_links_from_html=scanner.extract_links_from_html,
            ast_mode="off",
            source_map_mode="off",
            subpage_limit=1,
            advanced_limits={
                "max_new_assets": 4,
                "inventory_max_declarations": 4,
                "import_map_max_count": 1,
                "manifest_max_count": 1,
            },
        )
        assert subpage.hits == ["/foreign-subpage"], subpage.hits
        assert root.hits == [], root.hits
        assert "/api/must-not-be-admitted" not in graph.api_paths(), graph.api_paths()
        assert not any(item["url"].endswith("/must-not-load.js") for item in graph.js_resource_inventory), graph.js_resource_inventory
        assert len(graph.import_map_inventory) == 1, graph.import_map_inventory
        record = graph.import_map_inventory[0]
        assert record["source_page"] == subpage_url, record
        assert record["same_origin"] is False, record
        assert record["active_eligible"] is False, record
        assert record["status"] == "inventory_only", record
        assert graph.stats["import_maps_parsed"] == 0, graph.stats
    finally:
        for server in (subpage, root):
            server.shutdown()
            server.server_close()


def test_manifest_query_variant_source_order_hash_determinism():
    scanner = load_scanner()
    variants = {
        "js-first": "JS_FIRST_VARIANT_MUST_NOT_PERSIST",
        "link-second": "LINK_SECOND_VARIANT_MUST_NOT_PERSIST",
        "link-first": "LINK_FIRST_VARIANT_MUST_NOT_PERSIST",
        "js-second": "JS_SECOND_VARIANT_MUST_NOT_PERSIST",
    }
    cases = [
        (
            "js-first",
            '<script>window.assetManifest="/asset-manifest.json?variant=%s";</script>' % variants["js-first"]
            + '<link rel="manifest" href="/asset-manifest.json?variant=%s">' % variants["link-second"],
        ),
        (
            "link-first",
            '<link rel="manifest" href="/asset-manifest.json?variant=%s">' % variants["link-first"]
            + '<script>window.assetManifest="/asset-manifest.json?variant=%s";</script>' % variants["js-second"],
        ),
    ]

    for expected_label, html in cases:
        expected_variant = variants[expected_label]
        advanced_calls = []

        def advanced(url, max_size=500000):
            advanced_calls.append(url)
            parsed = urlparse(url)
            if parsed.path == "/asset-manifest.json":
                selected = parse_qs(parsed.query).get("variant", [""])[0]
                label = next((name for name, value in variants.items() if value == selected), "unknown")
                return 200, url, json.dumps({"files": {"main.js": "/signed-%s.js" % label}}), "application/json"
            if parsed.path.startswith("/signed-"):
                label = parsed.path[len("/signed-"):-len(".js")]
                return 200, url, "fetch('/api/from-%s-manifest')" % label, "application/javascript"
            return 404, url, "", "text/plain"

        graph = build_local_graph(
            scanner, html,
            lambda url, max_size=500000: (_ for _ in ()).throw(AssertionError("unexpected ordinary fetch " + url)),
            advanced,
            ast_mode="off",
            source_map_mode="off",
            advanced_limits={
                "max_new_assets": 2,
                "inventory_max_declarations": 4,
                "import_map_max_count": 1,
                "manifest_max_count": 1,
            },
        )
        manifest_calls = [call for call in advanced_calls if urlparse(call).path == "/asset-manifest.json"]
        assert len(manifest_calls) == 1, advanced_calls
        assert parse_qs(urlparse(manifest_calls[0]).query).get("variant") == [expected_variant], advanced_calls
        assert "/api/from-%s-manifest" % expected_label in graph.api_paths(), graph.api_paths()
        assert not any(
            "/api/from-%s-manifest" % label in graph.api_paths()
            for label in variants if label != expected_label
        ), graph.api_paths()
        assert graph.asset_manifest_inventory == [{
            "url": "http://example.test/asset-manifest.json",
            "source": "explicit_manifest",
            "declared_from": "http://example.test/",
            "same_origin": True,
            "active_eligible": True,
            "status": "parsed",
            "entry_count": 1,
        }], graph.asset_manifest_inventory
        persisted_inventory = json.dumps({
            "manifests": graph.asset_manifest_inventory,
            "resources": graph.js_resource_inventory,
        }, sort_keys=True)
        assert "?" not in persisted_inventory and "_fetch_url" not in persisted_inventory, persisted_inventory
        assert not any(value in persisted_inventory for value in variants.values()), persisted_inventory

    code = r'''
import json
from urllib.parse import parse_qs, urlparse
from pipeline.js_advanced_inventory import explicit_manifest_references, sanitize_url
values = {"js-first": "A", "link-second": "B", "link-first": "C", "js-second": "D"}
documents = [
    ('<script>const m="/asset-manifest.json?variant=A";</script>'
     '<link rel="manifest" href="/asset-manifest.json?variant=B">'),
    ('<link rel="manifest" href="/asset-manifest.json?variant=C">'
     '<script>const m="/asset-manifest.json?variant=D";</script>'),
]
selected = []
for html in documents:
    seen = set()
    for reference in explicit_manifest_references(html, "http://example.test/", html=True, max_refs=0):
        identity = sanitize_url(reference)
        if identity in seen:
            continue
        seen.add(identity)
        variant = parse_qs(urlparse(reference).query).get("variant", [""])[0]
        selected.append("js" if variant == "A" else "link")
print(json.dumps(selected))
'''
    outputs = []
    for seed in ("1", "77", "999"):
        env = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH=os.environ.get("PYTHONPATH", str(ROOT)))
        outputs.append(subprocess.check_output(
            [sys.executable, "-c", code], cwd=str(ROOT), env=env, text=True,
        ).strip())
    assert outputs == ['["js", "link"]'] * 3, outputs
    assert all("?" not in output and "_fetch_url" not in output for output in outputs), outputs


def test_full_phase2_inventory():
    cross = RecordingServer(("127.0.0.1", 0), CrossHandler)
    app = RecordingServer(("127.0.0.1", 0), app_handler(cross.server_address[1]))
    for server in (cross, app):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target_file = tmp / "targets.json"
            outdir = tmp / "out"
            base = "http://localhost:%d/" % app.server_address[1]
            target_file.write_text(json.dumps([{"url": base, "title": "advanced-phase2", "score": 100}]), encoding="utf-8")
            cmd = [
                sys.executable, str(SCANNER), "--input", str(target_file), "--outdir", str(outdir),
                "--workers", "2", "--phase12-workers", "1", "--timeout", "2", "--phase2-timeout", "60",
                "--no-proxy", "--skip-port-probe", "--dry-run", "--disable-api-fuzz",
                "--js-ast-mode", "required", "--js-advanced-max-assets", "32",
                "--advanced-inventory-max-declarations", "16",
                "--import-map-max-count", "3",
                "--asset-manifest-max-count", "5", "--asset-manifest-max-bytes", "512",
                "--source-map-mode", "explicit", "--source-map-max-count", "5",
                "--source-map-max-bytes", "512", "--source-map-max-sources", "8",
                "--no-capture-finding-evidence",
            ]
            proc = subprocess.run(cmd, text=True, capture_output=True, timeout=90)
            if proc.returncode != 0:
                print(proc.stdout)
                print(proc.stderr)
                raise AssertionError("scanner failed: %s" % proc.returncode)
            records = read_jsonl(outdir / "phase2_inventory.jsonl")
            record = next(item for item in records if item["base"].startswith(base.rstrip("/")))
            apis = set(record["apis"])
            for expected in (
                "/api/ast-users", "/api/ast-profile", "/api/member-chunk",
                "/api/from-external-map", "/api/from-inline-map", "/api/query-resource-loaded",
            ):
                assert expected in apis, (expected, sorted(apis))
            assert "/api/path-traversal-must-not-appear" not in apis, apis
            assert "/api/should-not-extract" not in apis, apis

            stats = record["js_advanced_stats"]
            assert stats["ast_parsed"] >= 1 and stats["ast_assets"] >= 4, stats
            assert stats["import_maps_parsed"] == 2 and stats["import_map_entries"] >= 3, stats
            assert stats["asset_manifest_parsed"] >= 2, stats
            assert stats["source_map_parsed"] >= 2 and stats["source_map_sources_processed"] >= 2, stats
            assert stats["advanced_assets_type_rejected"] >= 1, stats
            assert stats["advanced_origin_rejected"] == 0, stats

            resources = record["js_resource_inventory"]
            assert any(item["source"] == "js_ast" and item["sink"] == "script.src" and item["url"].endswith("/chunks/member.js") for item in resources), resources
            assert any(item["source"] == "import_map" and item["url"].endswith("/chunks/im-external.js") for item in resources), resources
            assert any(item["source"] == "asset_manifest" and item["url"].endswith("/chunks/nested.js") for item in resources), resources
            assert any(item["source"] == "import_map" and not item["active_eligible"] for item in resources), resources
            assert any(item["source"] == "asset_manifest" and not item["active_eligible"] for item in resources), resources
            assert len([item for item in resources if item["active_eligible"]]) <= 32, resources
            assert all("?" not in item["url"] and "#" not in item["url"] for item in resources), resources
            assert not any(item["url"].endswith(ending) for item in resources for ending in ("/icon.js", "/screenshot.js", "/shortcut.js")), resources

            manifests = {Path(urlparse(item["url"]).path).name: item for item in record["asset_manifest_inventory"]}
            assert manifests["asset-manifest.json"]["status"] == "parsed", manifests
            assert manifests["manifest-nested.json"]["status"] == "parsed", manifests
            assert manifests["asset-manifest-bad.json"]["status"] == "malformed", manifests
            assert manifests["asset-manifest-oversize.json"]["status"] == "oversize", manifests
            assert manifests["asset-manifest-cross.json"]["status"] == "inventory_only", manifests
            assert manifests["asset-manifest-redirect.json"]["status"] == "fetch_failed", manifests

            import_maps = {Path(urlparse(item["url"]).path).name: item for item in record["import_map_inventory"]}
            assert import_maps["importmap.json"]["status"] == "parsed", import_maps
            assert import_maps["redirect-importmap.json"]["status"] == "fetch_failed", import_maps
            assert any(item["status"] == "inventory_only" and not item["active_eligible"] for item in record["import_map_inventory"]), record["import_map_inventory"]

            map_statuses = [item["status"] for item in record["source_map_inventory"]]
            assert map_statuses.count("parsed") >= 2, record["source_map_inventory"]
            assert "malformed" in map_statuses and "oversize" in map_statuses and "inventory_only" in map_statuses, map_statuses
            assert any(item["reference"].endswith("/maps/redirect.map") and item["status"] == "fetch_failed" for item in record["source_map_inventory"]), record["source_map_inventory"]
            assert not cross.hits, cross.hits
            assert any(hit.startswith("/chunks/query-required.js?token=QUERY_RESOURCE_SECRET") for hit in app.hits), app.hits
            assert not any(urlparse(hit).path in ("/icon.js", "/screenshot.js", "/shortcut.js") for hit in app.hits), app.hits

            dry_records = json.loads((outdir / "apis.json").read_text(encoding="utf-8"))
            dry_record = next(item for item in dry_records if item["base"] == record["base"])
            assert dry_record["js_resource_inventory_count"] == record["js_resource_inventory_count"], dry_record
            assert dry_record["source_map_count"] == record["source_map_count"], dry_record

            persisted = "\n".join(
                path.read_text(encoding="utf-8", errors="replace")
                for path in outdir.rglob("*") if path.is_file()
            )
            assert RAW_MARKER not in persisted, "raw sourcesContent marker persisted"
            assert "sourcesContent" not in persisted, "raw source map JSON persisted"
            for marker in QUERY_MARKERS:
                assert marker not in persisted, "sensitive internal/source-map value persisted: " + marker
            assert {"accountId", "email", "token"}.issubset(set(record["param_names"])), record["param_names"]
            assert not (outdir / "evidence").exists(), list(outdir.iterdir())
    finally:
        for server in (app, cross):
            server.shutdown()
            server.server_close()


def main():
    tests = [
        test_ast_limits_and_real_parser,
        test_required_cli_fails_before_output_without_parser,
        test_html_fallback_and_hash_determinism,
        test_active_limits_duplicate_priority_and_delete_inventory,
        test_cross_origin_subpage_inline_import_map_inventory_only,
        test_manifest_query_variant_source_order_hash_determinism,
        test_full_phase2_inventory,
    ]
    for test in tests:
        test()
        print("PASS", test.__name__)
    print("V36 ADVANCED PHASE2 INVENTORY LAB PASS")


if __name__ == "__main__":
    main()
