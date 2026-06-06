#!/usr/bin/env python3
"""
Phase 2: JS Download + API Extraction + Unauthorized Access Test (stdlib only)
For each responsive target: download JS -> extract APIs -> test endpoints.
"""

import sys, os, re, json, time, ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
from urllib.request import Request, urlopen, build_opener, HTTPRedirectHandler
from urllib.error import URLError, HTTPError
from collections import defaultdict

TIMEOUT = 8
MAX_WORKERS = 25
JS_WORKERS = 8
API_TEST_WORKERS = 15

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
    http_error_302 = http_error_301 = http_error_303 = http_error_307 = http_error_308 = redirect_request

opener = build_opener(NoRedirect)

def http_get(url, timeout=TIMEOUT, max_size=500000):
    """HTTP GET -> (status, text)."""
    try:
        req = Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; scanner)",
                                     "Accept": "text/html,application/javascript,*/*"})
        resp = opener.open(req, timeout=timeout, context=ssl_ctx)
        body = b""
        while True:
            try:
                chunk = resp.read(65536)
                if not chunk:
                    break
                body += chunk
                if len(body) > max_size:
                    break
            except:
                break
        try:
            text = body.decode('utf-8', errors='replace')
        except:
            text = body.decode('latin-1', errors='replace')
        return resp.getcode(), text
    except HTTPError as e:
        try:
            text = e.read().decode('utf-8', errors='replace')[:100000]
        except:
            text = ""
        return e.code, text
    except:
        return None, ""

# API extraction patterns
API_RE_PATTERNS = [
    r'''url\s*:\s*["']([^"']+)["']''',
    r'''path\s*:\s*["']([^"']+)["']''',
    r'''baseURL\s*:\s*["']([^"']+)["']''',
    r'''\.(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']''',
    r'''axios\s*\(\s*\{[^}]*?url\s*:\s*["']([^"']+)["']''',
    r'''request\s*\(\s*["']([^"']/api/[^"']+)["']''',
    r'''["'](/api/[a-zA-Z0-9_/.-]+)["']''',
]

SENSITIVE_TESTS = [
    "/api/user/users", "/api/user/list", "/api/user/info",
    "/api/server/system/info", "/api/server/system/configInfo",
    "/api/server/info", "/api/server/media_server/list",
    "/api/role/all", "/api/log/list",
    "/api/device/query/devices", "/api/common/channel/list",
    "/api/userApiKey/userApiKeys",
    "/actuator/health", "/actuator/env",
    "/swagger-resources", "/v2/api-docs", "/v3/api-docs",
    "/druid/index.html",
]

JS_LIB_PATS = [
    r'jquery', r'bootstrap', r'vue(\\.min)?\\.js', r'react(\\.min)?\\.js',
    r'axios\\.min', r'lodash', r'moment', r'echarts', r'swiper',
    r'polyfill', r'd3\\.min', r'popper', r'chart(\\.min)?\\.js',
    r'layer', r'layui', r'crypto-js', r'chunk-vendor', r'chunk-common',
    r'vendor\\.', r'vendors\\.', r'h265web', r'ZLMRTC', r'missile',
    r'fontawesome', r'codemirror', r'quill', r'tinymce',
    r'leaflet', r'mapbox', r'socket\\.io', r'pdf\\.js',
    r'highlight', r'markdown', r'webpack\\.runtime',
    r'core-js', r'regenerator',
]

def extract_title(html):
    m = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
    return m.group(1).strip()[:200] if m else ""

def extract_js_urls(html, base_url):
    """Extract JS file URLs from HTML."""
    js_urls = set()
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\\.js[^"\']*)["\']', html, re.IGNORECASE):
        src = m.group(1)
        js_urls.add(urljoin(base_url, src))
    # webpack dynamic imports: "static/js/xxx.js"
    for m in re.finditer(r'''["']([^"']*static/js/[^"']+\\.js)["']''', html):
        js_urls.add(urljoin(base_url, m.group(1)))
    return js_urls

def is_lib(js_url):
    url_l = js_url.lower()
    for p in JS_LIB_PATS:
        if re.search(p, url_l):
            return True
    return False

def extract_apis(js_content):
    """Extract API paths from JS content."""
    apis = set()
    for pat in API_RE_PATTERNS:
        for m in re.finditer(pat, js_content, re.IGNORECASE):
            path = m.group(1).strip()
            if not path or path.startswith("http") or path.startswith("//"):
                continue
            if not path.startswith("/"):
                path = "/" + path
            path = path.split("?")[0]
            if len(path) > 200 or path in ("/", "/#", "/#/"):
                continue
            if path.endswith((".js", ".css", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".woff2")):
                continue
            apis.add(path)
    return apis

def test_api(base_url, path):
    """Test a single API endpoint for unauthenticated access."""
    clean_path = path.split("?")[0].rstrip("/")
    if not clean_path:
        return None

    url = urljoin(base_url, clean_path)
    status, text = http_get(url, timeout=6)

    if status != 200 or len(text) < 20:
        return None

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        # Not JSON, check if it's an interesting HTML page
        if re.search(r'<!DOCTYPE|<html|<title', text, re.IGNORECASE):
            return None
        return {"url": url, "method": "GET", "has_data": True, "raw_preview": text[:300]}

    if not isinstance(data, dict):
        if isinstance(data, list) and len(data) > 0:
            return {"url": url, "method": "GET", "has_data": True, "is_list": True, "count": len(data),
                    "sample": json.dumps(data[:3], ensure_ascii=False)[:500]}
        return None

    code = data.get("code") or data.get("Code") or data.get("status")
    msg = data.get("msg") or data.get("message") or ""
    d = data.get("data")

    has_data = d is not None and d != "" and d != [] and d != {}
    is_success = code in (0, 200, "0", "200") or "成功" in str(msg)

    if has_data or (is_success and "error" not in str(msg).lower() and "失败" not in str(msg)):
        result = {"url": url, "method": "GET", "has_data": has_data, "code": code, "msg": str(msg)[:200]}
        if isinstance(d, dict):
            result["data_keys"] = list(d.keys())[:15]
            if "total" in d or "list" in d:
                size = d.get("total") or len(d.get("list", []))
                result["data_size"] = size
        elif isinstance(d, list) and len(d) > 0:
            result["data_size"] = len(d)
            result["sample"] = json.dumps(d[:2], ensure_ascii=False)[:500]
        return result
    return None

def process_target(info, idx):
    """Process one target: get page -> extract JS -> extract APIs -> test."""
    base_url = info["base_url"]
    title = info.get("title", "")

    result = {
        "base_url": base_url, "title": title,
        "js_count": 0, "api_count": 0,
        "vulnerable": False, "vulnerable_endpoints": [],
    }

    # Get main page
    status, html = http_get(base_url)
    if status is None or status >= 500:
        return result

    # Extract JS URLs
    js_urls = extract_js_urls(html, base_url)
    app_js = [u for u in js_urls if not is_lib(u)]
    if not app_js:
        return result

    result["js_count"] = len(app_js)

    # Download JS and extract APIs (limit to 15 JS files per target)
    all_apis = set()
    with ThreadPoolExecutor(max_workers=JS_WORKERS) as pool:
        futures = {}
        for u in list(app_js)[:15]:
            futures[pool.submit(http_get, u, 8, 300000)] = u

        for f in as_completed(futures):
            try:
                s, content = f.result()
                if s == 200 and content:
                    apis = extract_apis(content)
                    all_apis.update(apis)
            except:
                pass

    if not all_apis:
        return result

    result["api_count"] = len(all_apis)
    # Get top APIs (prefer /api/ paths)
    api_list = sorted(all_apis, key=lambda x: (0 if "/api/" in x else 1, x))[:30]

    # Test APIs + sensitive endpoints
    test_paths = set(api_list + SENSITIVE_TESTS)
    vulns = []
    with ThreadPoolExecutor(max_workers=API_TEST_WORKERS) as pool:
        futures = {pool.submit(test_api, base_url, p): p for p in test_paths}
        for f in as_completed(futures):
            try:
                finding = f.result()
                if finding:
                    vulns.append(finding)
            except:
                pass

    if vulns:
        result["vulnerable"] = True
        result["vulnerable_endpoints"] = vulns

    return result

def deep_probe(info):
    """For confirmed vulnerable targets, probe deeper."""
    base_url = info["base_url"]
    findings = []

    for ep in info.get("vulnerable_endpoints", [])[:5]:
        base_path = ep["url"].split("?")[0].rstrip("/")

        # Try pagination
        for suffix in ["?page=1&count=1000", "?page=1&size=1000", "/all", "/1"]:
            url = f"{base_path}{suffix}"
            status, text = http_get(url, timeout=6)
            if status == 200 and len(text) > 50:
                try:
                    data = json.loads(text)
                    d = data.get("data") if isinstance(data, dict) else data
                    if d and isinstance(d, (list, dict)):
                        preview = str(d)[:800]
                        if len(preview) > 100:
                            findings.append({"url": url, "preview": preview})
                except:
                    pass
    return findings

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 phase2_scan.py <responsive_targets.json> [out.json]")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "/tmp/unauth_scan_results.json"

    with open(input_file) as f:
        targets = json.load(f)

    print(f"[*] Loaded {len(targets)} targets")
    print(f"[*] Workers: {MAX_WORKERS}, Timeout: {TIMEOUT}s")

    # Run
    all_results = []
    vulnerable = []
    done = 0
    start = time.time()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(process_target, t, i): t for i, t in enumerate(targets)}
        for f in as_completed(futures):
            done += 1
            if done % 20 == 0:
                elapsed = time.time() - start
                print(f"  [{done}/{len(targets)}] {elapsed:.0f}s | {len(vulnerable)} vuln")

            try:
                r = f.result()
                all_results.append(r)
                if r["vulnerable"]:
                    vulnerable.append(r)
                    print(f"\n  [!] {r['base_url']} | {r['title'][:60]}")
                    print(f"       JS:{r['js_count']} APIs:{r['api_count']}")
                    for ep in r["vulnerable_endpoints"][:5]:
                        keys = ep.get("data_keys", [])
                        size = ep.get("data_size", "")
                        print(f"       [{ep['method']}] {ep['url']} | keys={keys} | size={size}")
            except:
                pass

    elapsed = time.time() - start
    print(f"\n{'='*60}")
    print(f"[*] DONE in {elapsed:.0f}s ({elapsed/60:.1f}min)")
    print(f"[*] Scanned: {len(all_results)}, Vulnerable: {len(vulnerable)}")
    print(f"{'='*60}")

    # Deep probe
    if vulnerable:
        print(f"\n[*] Deep probing {len(vulnerable)} vulnerable targets...")
        for v in vulnerable[:20]:  # limit deep probe to first 20
            deep = deep_probe(v)
            if deep:
                v["deep_findings"] = deep
                print(f"\n  [DEEP] {v['base_url']}")
                for d in deep[:3]:
                    print(f"    {d['url']}")
                    print(f"    {d['preview'][:200]}")

    # Save
    report = {
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_scanned": len(all_results),
        "vulnerable_count": len(vulnerable),
        "vulnerable": vulnerable,
    }
    with open(output_file, "w") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\n[*] Report -> {output_file}")

    # Final summary
    if vulnerable:
        print(f"\n{'='*60}")
        print("VULNERABILITY SUMMARY")
        print(f"{'='*60}")
        for i, v in enumerate(vulnerable):
            print(f"\n  [{i+1}] {v['base_url']} - {v['title'][:60]}")
            for ep in v["vulnerable_endpoints"][:5]:
                print(f"      {ep['method']} {ep['url']}")
                if "data_size" in ep:
                    print(f"      -> data_size={ep['data_size']}, keys={ep.get('data_keys', [])}")
                if "sample" in ep:
                    print(f"      -> sample: {str(ep['sample'])[:200]}")

if __name__ == "__main__":
    main()
