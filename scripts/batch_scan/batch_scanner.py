#!/usr/bin/env python3
"""
Batch JS/API Unauthorized Access Scanner
Scans IPs/URLs for web servers, downloads JS, extracts APIs, tests for unauthorized access.
Uses only stdlib. Writes results incrementally.
"""

import sys, os, re, json, time, ssl, socket
from concurrent.futures import ThreadPoolExecutor, as_completed, ProcessPoolExecutor
from urllib.parse import urlparse, urljoin
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from collections import defaultdict

# Config
TIMEOUT = 4
TCP_TIMEOUT = 1.5
MAX_WORKERS = 60
INPUT = "/tmp/targets_filtered.txt"
OUTDIR = "/tmp/scan_results"
WEB_PORTS = [443, 8443, 80, 8080, 8001]

os.makedirs(OUTDIR, exist_ok=True)

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

JS_LIB_RE = re.compile(
    r'jquery|bootstrap|vue(\.min)?\.js|react(\.min)?\.js|axios\.min|'
    r'lodash|moment|echarts|swiper|polyfill|chunk-vendor|chunk-common|'
    r'vendor\.|vendors\.|h265web|ZLMRTC|missile|fontawesome|codemirror|'
    r'quill|tinymce|leaflet|mapbox|socket\.io|pdf\.js|highlight|markdown|'
    r'webpack\.runtime|core-js|regenerator', re.I
)

def http_get(url, timeout=TIMEOUT, max_size=300000):
    try:
        req = Request(url, headers={
            "User-Agent": "Mozilla/5.0 (compatible; scan)",
            "Accept": "text/html,application/javascript,application/json,*/*"
        })
        resp = urlopen(req, timeout=timeout, context=ssl_ctx)
        body = b""
        while True:
            try:
                chunk = resp.read(65536)
                if not chunk: break
                body += chunk
                if len(body) > max_size: break
            except: break
        return resp.getcode(), body.decode('utf-8', errors='replace')
    except HTTPError as e:
        try: return e.code, e.read().decode('utf-8', errors='replace')[:50000]
        except: return e.code, ""
    except: return None, ""

def tcp_check(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TCP_TIMEOUT)
        r = s.connect_ex((host, port))
        s.close()
        return r == 0
    except: return False

def scan_target(target):
    """Phase 1+2 combined: probe, extract JS, test APIs."""
    target = target.strip()
    if not target: return None

    # Parse target
    if target.startswith("http://") or target.startswith("https://"):
        p = urlparse(target)
        host, port = p.hostname, p.port or (80 if p.scheme == "http" else 443)
        scheme = p.scheme
        base_url = f"{scheme}://{host}:{port}"
        urls_to_try = [base_url + "/"]
    else:
        host = target
        # Find web port
        urls_to_try = []
        for port in WEB_PORTS:
            if tcp_check(host, port):
                scheme = "https" if port in (443, 8443) else "http"
                urls_to_try.append(f"{scheme}://{host}:{port}/")
                break

    if not urls_to_try:
        return None

    # Try each URL
    for url in urls_to_try:
        status, html = http_get(url)
        if status is None or status >= 500:
            continue
        if status < 200:
            continue

        title = ""
        m = re.search(r'<title[^>]*>([^<]+)</title>', html, re.I)
        if m: title = m.group(1).strip()[:200]

        if not title and len(html) < 100:
            continue

        result = {
            "url": url, "status": status, "title": title, "size": len(html),
            "vulnerable": False, "findings": []
        }

        # Extract JS URLs
        js_urls = set()
        for m in re.finditer(r'(?:src|href)=["\x27]?([^"\'<> ]+\.js[^"\'<> ]*)["\x27]?', html):
            js = m.group(1)
            if not js.startswith("http"):
                js = urljoin(url, js)
            js_urls.add(js)

        if not js_urls:
            return result

        # Filter app JS
        app_js = [j for j in js_urls if not JS_LIB_RE.search(j)]

        if not app_js:
            return result

        # Download JS and extract APIs (limit 10 JS files, 200KB each)
        all_apis = set()
        for js_url in list(app_js)[:10]:
            s, content = http_get(js_url, max_size=200000)
            if s != 200 or not content:
                continue

            # Extract API paths
            for m in re.finditer(r'''["\x27](/[a-zA-Z][a-zA-Z0-9_/\-.]{3,200})["\x27]''', content):
                path = m.group(1)
                if re.search(r'/api/|/user|/admin|/login|/auth|/server|/device|/channel|/record|/platform|/role|/log|/data|/info|/config|/push|/proxy', path, re.I):
                    all_apis.add(path)

            # Extract url/path definitions
            for m in re.finditer(r'''(?:url|path|baseURL)\s*:\s*["']([^"']+)["']''', content):
                path = m.group(1).strip()
                if path.startswith("/") and len(path) > 2 and not path.startswith("//"):
                    all_apis.add(path.split("?")[0])

        if not all_apis:
            return result

        # Test APIs (limit 20)
        api_list = sorted(all_apis, key=lambda x: (0 if "/api/" in x else 1, len(x)))[:20]

        # Add common sensitive paths
        api_list.extend([
            "/api/user/users", "/api/server/info", "/api/role/all",
            "/api/log/list", "/api/device/query/devices",
            "/api/server/system/info", "/api/userApiKey/userApiKeys",
        ])

        findings = []
        for path in set(api_list):
            if not path.startswith("/"):
                path = "/" + path
            api_url = urljoin(url, path)

            s, content = http_get(api_url)
            if s != 200 or len(content) < 30:
                continue

            # Must be JSON
            content = content.strip()
            if not (content.startswith("{") or content.startswith("[")):
                continue

            try:
                data = json.loads(content)
            except:
                continue

            if not isinstance(data, dict):
                if isinstance(data, list) and len(data) > 0:
                    findings.append({
                        "url": api_url, "type": "list", "count": len(data),
                        "sample": json.dumps(data[:2], ensure_ascii=False)[:300]
                    })
                continue

            code = data.get("code") or data.get("Code") or data.get("status")
            msg = data.get("msg") or data.get("message") or ""
            d = data.get("data")

            # Check for unauthorized access (data returned without auth)
            has_data = d is not None and d != "" and d != [] and d != {} and d is not False
            is_success = code in (0, 200, "0", "200")

            # Skip auth-required responses
            if "缺少请求授权令牌" in str(msg) or "Unauthorized" in str(msg) or "未登录" in str(msg):
                continue
            if str(code) == "10031" or str(code) == "401":
                continue

            if has_data or is_success:
                finding = {
                    "url": api_url, "code": code, "msg": str(msg)[:200],
                    "has_data": has_data
                }
                if isinstance(d, dict):
                    finding["keys"] = list(d.keys())[:15]
                    if "total" in d:
                        finding["total"] = d["total"]
                    if "list" in d:
                        finding["items"] = len(d["list"])
                elif isinstance(d, list):
                    finding["count"] = len(d)
                    finding["sample"] = json.dumps(d[:2], ensure_ascii=False)[:500]
                findings.append(finding)

        if findings:
            result["vulnerable"] = True
            result["findings"] = findings

        return result

    return None

def main():
    print(f"[*] Loading targets from {INPUT}")
    with open(INPUT) as f:
        targets = [l.strip() for l in f if l.strip()]

    # Deduplicate
    seen = set()
    unique = []
    for t in targets:
        host = t.split("//")[-1].split("/")[0].split(":")[0].strip()
        if host not in seen:
            seen.add(host)
            unique.append(t)

    print(f"[*] {len(unique)} unique targets, {MAX_WORKERS} workers")

    results = []
    vulnerable = []
    done = 0
    start = time.time()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(scan_target, t): t for t in unique}
        for f in as_completed(futures):
            done += 1
            if done % 200 == 0:
                elapsed = time.time() - start
                print(f"  [{done}/{len(unique)}] {elapsed:.0f}s | {len(vulnerable)} vuln")

            try:
                r = f.result()
                if r:
                    results.append(r)
                    if r.get("vulnerable"):
                        vulnerable.append(r)
                        print(f"\n  [!] {r['url']} | {r['title'][:70]}")
                        for fi in r["findings"][:3]:
                            print(f"      {fi['url']}")
                            if "keys" in fi: print(f"      keys={fi['keys']}")
                            if "total" in fi: print(f"      total={fi['total']}")
                            if "sample" in fi: print(f"      sample={fi['sample'][:200]}")

                        # Save immediately
                        fname = re.sub(r'[^a-zA-Z0-9]', '_', r['url']) + ".json"
                        with open(os.path.join(OUTDIR, fname), "w") as fout:
                            json.dump(r, fout, ensure_ascii=False, indent=2)
            except Exception as e:
                pass

    elapsed = time.time() - start
    print(f"\n{'='*70}")
    print(f"[*] DONE in {elapsed:.0f}s ({elapsed/60:.1f} min)")
    print(f"[*] Scanned: {len(results)}, Web servers: {sum(1 for r in results if r)}, Vulnerable: {len(vulnerable)}")
    print(f"{'='*70}")

    # Save summary
    summary = {
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_scanned": len(unique),
        "web_servers": len(results),
        "vulnerable": len(vulnerable),
        "vulnerable_targets": vulnerable
    }
    with open(os.path.join(OUTDIR, "summary.json"), "w") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    # Print vulnerability report
    if vulnerable:
        print(f"\n{'='*70}")
        print("VULNERABILITY REPORT")
        print(f"{'='*70}")
        for i, v in enumerate(vulnerable):
            print(f"\n  [{i+1}] {v['url']} - {v['title'][:80]}")
            for fi in v["findings"]:
                print(f"      {fi['url']}")
                for key in ["total", "count", "keys", "msg", "sample"]:
                    if key in fi:
                        val = str(fi[key])
                        print(f"        {key}: {val[:200]}")
    else:
        print("\n[!] No unauthorized access vulnerabilities found in this batch.")

    print(f"\n[*] Detailed results saved to {OUTDIR}/")

if __name__ == "__main__":
    main()
