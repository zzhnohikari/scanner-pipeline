#!/usr/bin/env python3
"""
Complete JS/API Unauthorized Access Scanner v2
- 100+ web ports scanned per IP
- TCP probe -> HTTP fetch -> JS extract -> API test -> Report
- All results saved incrementally to /tmp/pipeline_results/
"""

import sys, os, re, json, time, ssl, socket
from concurrent.futures import ThreadPoolExecutor, as_completed, wait
from urllib.parse import urlparse, urljoin
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# ========== CONFIG ==========
TCP_TIMEOUT = 1.2
HTTP_TIMEOUT = 6
API_TIMEOUT = 5
TCP_WORKERS = 300
SCAN_WORKERS = 50
API_TEST_WORKERS = 20

# Top 100+ common web ports (HTTP/HTTPS)
WEB_PORTS = [
    80, 443, 81, 82, 83, 84, 85, 88, 90, 300, 591, 593, 777, 800, 801, 808, 880, 888, 889, 890, 899, 900,
    901, 980, 1080, 1100, 1180, 1241, 1443, 1500, 1521, 1547, 1801, 1935, 2000, 2080, 2095, 2096, 2100, 2222,
    2301, 2381, 2443, 2480, 2500, 2563, 2601, 2628, 2800, 3000, 3001, 3020, 3030, 3040, 3050, 3071, 3080, 3090,
    3100, 3128, 3200, 3260, 3306, 3333, 3389, 3500, 3601, 3689, 3749, 3780, 3800, 3801, 3827, 3837, 3888,
    4000, 4001, 4002, 4040, 4080, 4100, 4143, 4242, 4333, 4433, 4443, 4444, 4500, 4567, 4664, 4712, 4848, 4888,
    4993, 5000, 5001, 5050, 5060, 5080, 5104, 5190, 5222, 5269, 5280, 5353, 5357, 5432, 5443, 5500, 5510, 5540,
    5550, 5555, 5560, 5601, 5631, 5666, 5678, 5683, 5800, 5801, 5810, 5900, 5901, 5984, 5985, 5999,
    6000, 6001, 6060, 6080, 6123, 6379, 6480, 6502, 6543, 6600, 6636, 6666, 6667, 6668, 6669,
    7000, 7001, 7002, 7070, 7071, 7080, 7100, 7171, 7200, 7272, 7396, 7443, 7474, 7510, 7547, 7548,
    7657, 7676, 7700, 7777, 7778, 7800, 7878, 7890, 7900, 7920, 7930, 7980, 7981, 7982,
    8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010, 8020, 8030, 8040, 8042, 8050,
    8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8100, 8112, 8123, 8139, 8140, 8161, 8181,
    8200, 8222, 8300, 8333, 8383, 8400, 8443, 8444, 8445, 8484, 8500, 8530, 8531, 8580, 8600, 8649, 8710,
    8800, 8834, 8848, 8855, 8879, 8880, 8881, 8888, 8899, 8900, 8943, 8983, 8999,
    9000, 9001, 9002, 9003, 9009, 9010, 9020, 9030, 9040, 9050, 9060, 9080, 9081, 9090, 9091, 9100, 9110, 9200,
    9292, 9333, 9393, 9443, 9444, 9494, 9500, 9527, 9595, 9600, 9666, 9696, 9800, 9876, 9898,
    9900, 9988, 9999,
    10000, 10001, 10010, 10051, 10080, 10081, 10082, 10101, 10200, 10443,
    11000, 11111, 11211, 11371, 11501, 12000, 12121, 12345,
    13000, 13333, 13555, 13777, 14000, 14444, 14500, 15000, 15555,
    16000, 16010, 16030, 16379, 17000, 18000, 18080, 18081, 18091, 18181,
    19000, 20000, 20080, 20256, 21000, 22000, 22222, 23000, 23456, 25000,
    27017, 28000, 28017, 30000, 32000, 33333, 35000, 37777, 40000, 44444, 50000, 55555, 60000, 65535,
]

INPUT = "/tmp/targets_filtered.txt"
OUTDIR = "/tmp/pipeline_results"
os.makedirs(OUTDIR, exist_ok=True)

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

# ========== HELPERS ==========
def tcp_check(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TCP_TIMEOUT)
        r = s.connect_ex((str(host), int(port)))
        s.close()
        return r == 0
    except:
        return False

def http_get(url, timeout=HTTP_TIMEOUT, max_size=500000):
    try:
        req = Request(url, headers={
            "User-Agent": "Mozilla/5.0 (compatible)",
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
        return resp.getcode(), resp.url, body.decode('utf-8', errors='replace')
    except HTTPError as e:
        try: return e.code, e.url, e.read().decode('utf-8', errors='replace')[:100000]
        except: return e.code, e.url, ""
    except: return None, None, ""

def is_json(s):
    s = s.strip()
    return s.startswith("{") or s.startswith("[")

def parse_json(s):
    try: return json.loads(s)
    except: return None

# ========== PHASE 1: TCP PROBE ==========
def phase1_probe(targets):
    print(f"[Phase 1] TCP probe: {len(targets)} targets, {len(WEB_PORTS)} ports, {TCP_WORKERS} workers", flush=True)

    # Step 1: Deduplicate hosts, separate known-URL targets
    known_urls = set()  # (host, port, scheme)
    ip_only = set()     # host string

    for t in targets:
        t = t.strip()
        if t.startswith("http://") or t.startswith("https://"):
            p = urlparse(t)
            known_urls.add((p.hostname, p.port or (443 if p.scheme=="https" else 80), p.scheme))
        else:
            ip_only.add(t)

    print(f"  Known-URL targets: {len(known_urls)}, IP-only: {len(ip_only)}", flush=True)

    # Step 2: Check known-URL targets (just the known port)
    live = {}
    done = 0

    def check_known(item):
        host, port, scheme = item
        if tcp_check(host, port):
            return (host, port, scheme)
        return None

    known_list = list(known_urls)
    if known_list:
        with ThreadPoolExecutor(max_workers=TCP_WORKERS) as pool:
            futures = {pool.submit(check_known, k): k for k in known_list}
            for f in as_completed(futures):
                done += 1
                try:
                    r = f.result()
                    if r:
                        host, port, scheme = r
                        live[host] = (port, scheme)
                except: pass
        print(f"  Known-URL live: {len(live)}", flush=True)

    # Step 3: Tiered port scan for IP-only targets
    # Split ports into tiers for efficiency
    port_tiers = [
        ("T1", [80, 443, 8080, 8443, 8001]),
        ("T2", [81, 82, 88, 3000, 4000, 5000, 7000, 8000, 8002, 8003, 8008, 8081, 8088, 8089, 8888, 9000, 9090, 9443, 10000, 10080]),
        # T3: extended scan on remaining hosts (runs after Phase 2 on promising hosts)
    ]

    remaining = ip_only - set(live.keys())

    def scan_one(item):
        host, port = item
        if tcp_check(host, port):
            scheme = "https" if port in (443, 8443, 9443, 10443, 4433, 4443, 8444, 7443, 5443) else "http"
            return (host, port, scheme)
        return None

    for tier_name, tier_ports in port_tiers:
        if not remaining:
            break
        remaining_list = list(remaining)
        print(f"  {tier_name}: {len(remaining_list)} hosts, {len(tier_ports)} ports...", flush=True)

        new_live = 0

        # Submit tasks in batches to avoid memory issues
        BATCH = 5000
        for batch_start in range(0, len(remaining_list), BATCH):
            batch_hosts = remaining_list[batch_start:batch_start + BATCH]
            tasks = []
            for host in batch_hosts:
                for port in tier_ports:
                    tasks.append((host, port))

            batch_found = 0
            with ThreadPoolExecutor(max_workers=TCP_WORKERS) as pool:
                futures = [pool.submit(scan_one, t) for t in tasks]
                for f in as_completed(futures):
                    try:
                        r = f.result()
                        if r:
                            host, port, scheme = r
                            if host not in live:
                                live[host] = (port, scheme)
                                new_live += 1
                                batch_found += 1
                    except: pass

            if batch_found > 0:
                print(f"    batch +{batch_found} live", flush=True)

        print(f"    {tier_name}: +{new_live} live (total: {len(live)})", flush=True)
        remaining = ip_only - set(live.keys())

    # Build result list
    result = []
    for host, (port, scheme) in live.items():
        result.append({
            "host": host, "port": port, "scheme": scheme,
            "url": f"{scheme}://{host}:{port}" if port not in (80,443) or scheme != "http" else
                   f"{scheme}://{host}"
        })

    print(f"  Phase 1 DONE: {len(result)} live hosts", flush=True)

    # Save live hosts for later use
    with open(os.path.join(OUTDIR, "live_hosts.json"), "w") as f:
        json.dump(result, f, ensure_ascii=False)
    print(f"  Live hosts saved to {OUTDIR}/live_hosts.json", flush=True)

    return result

# ========== PHASE 2: HTTP + JS + API EXTRACT ==========
LIB_RE = re.compile(
    r'(?:jquery|bootstrap\.min|vue\.min|vue\.runtime|react\.min\.|react\.production\.|'
    r'angular\.min|axios\.min|lodash\.min|moment\.min|echarts\.min|swiper\.min|'
    r'polyfill\.|chunk-vendors\.|chunk-common\.|vendor\.\w{8}\.|vendors\.\w{8}\.|'
    r'core-js|regenerator|webpack\.runtime)', re.I
)

API_PATTERNS = [
    (re.compile(r'''url\s*:\s*["']([^"']{2,200})["']''', re.I), 1),
    (re.compile(r'''path\s*:\s*["']([^"']{2,200})["']''', re.I), 1),
    (re.compile(r'''baseURL\s*:\s*["']([^"']{2,200})["']''', re.I), 1),
    (re.compile(r'''\.(?:get|post|put|delete|patch)\s*\(\s*["']([^"']{2,200})["']''', re.I), 1),
    (re.compile(r'''axios\s*\(\s*\{[^}]*?url\s*:\s*["']([^"']{2,200})["']''', re.I), 1),
    (re.compile(r'''fetch\s*\(\s*["']([^"']{2,200})["']''', re.I), 1),
    (re.compile(r'''request\s*\(\s*\{[^}]*?url\s*:\s*["']([^"']{2,200})["']''', re.I), 1),
    (re.compile(r'''["'](/api/[a-zA-Z][a-zA-Z0-9_/\-.]{2,200})["']''', re.I), 2),
    (re.compile(r'''["'](/[a-zA-Z][a-zA-Z0-9_/\-.]*/[a-zA-Z][a-zA-Z0-9_/\-.]{2,200})["']''', re.I), 3),
]

API_INTEREST = re.compile(
    r'/api/|/user|/admin|/login|/logout|/auth|/token|/server|/system|'
    r'/device|/channel|/record|/platform|/role|/log|/data|/info|/config|'
    r'/push|/proxy|/group|/region|/upload|/download|/file|/notary|/enterprise|'
    r'/portal|/biz|/nsc|/CmCon|/profile|/account|/setting|/manage|/dashboard|'
    r'/query|/list|/search|/find|/monitor|/stream|/video|/camera|/media', re.I
)

SENSITIVE_TESTS = [
    "/api/user/users", "/api/user/list", "/api/user/info", "/api/user/userInfo",
    "/api/server/info", "/api/server/system/info", "/api/server/system/configInfo",
    "/api/server/media_server/list", "/api/role/all", "/api/log/list",
    "/api/device/query/devices", "/api/common/channel/list", "/api/common/channel/one",
    "/api/userApiKey/userApiKeys",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
    "/swagger-ui.html", "/swagger-resources", "/v2/api-docs", "/v3/api-docs",
    "/api-docs", "/doc.html", "/druid/index.html",
    "/api/admin/user", "/api/admin/config",
]

def extract_js_urls(html, base_url):
    js = set()
    for m in re.finditer(r'<script[^>]+src\s*=\s*["\x27]?([^"\'<>\s]+\.js(?:[^"\'<>\s]*))["\x27]?', html, re.I):
        src = m.group(1)
        js.add(urljoin(base_url, src))
    for m in re.finditer(r'''(?:src|href)\s*=\s*["\x27]?([^"\'<>\s]*?/js/[^"\'<>\s]+\.js)["\x27]?''', html, re.I):
        js.add(urljoin(base_url, m.group(1)))
    for m in re.finditer(r'''["\x27]([^"\x27]*?/static/js/[^"\x27]+\.js)["\x27]''', html):
        js.add(urljoin(base_url, m.group(1)))
    return js

def extract_apis(js_content):
    apis = set()
    for pat, _ in API_PATTERNS:
        for m in pat.finditer(js_content):
            path = m.group(1).strip()
            if not path or path.startswith("http") or path.startswith("//"): continue
            if not path.startswith("/"): path = "/" + path
            path = path.split("?")[0].rstrip("/")
            if len(path) < 2 or len(path) > 200: continue
            if path in ("/", "/#", "/#/"): continue
            ext = os.path.splitext(path)[1].lower()
            if ext in ('.js','.css','.png','.jpg','.gif','.svg','.ico','.woff','.woff2','.ttf','.eot','.map','.json','.xml','.html','.htm','.pdf'): continue
            if API_INTEREST.search(path):
                apis.add(path)
    return apis

def process_host(h):
    url = h["url"] + "/"
    status, final_url, html = http_get(url)
    if status is None or status >= 500 or not html or len(html) < 100:
        return None

    title = ""
    m = re.search(r'<title[^>]*>([^<]+)</title>', html, re.I)
    if m: title = m.group(1).strip()[:200]

    parsed = urlparse(final_url)
    base = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port and parsed.port not in (80, 443):
        base += f":{parsed.port}"

    # Extract JS
    js_urls = extract_js_urls(html, base)
    app_js = [j for j in js_urls if not LIB_RE.search(j)]

    # Download JS and extract APIs
    all_apis = set()
    js_dl = 0
    for js_url in list(app_js)[:15]:
        s, _, content = http_get(js_url, max_size=300000)
        if s != 200 or not content: continue
        js_dl += 1
        apis = extract_apis(content)
        all_apis.update(apis)

    # Add common sensitive tests
    all_apis.update(SENSITIVE_TESTS)

    if all_apis:
        return {
            "base": base, "title": title, "status": status,
            "apis": sorted(all_apis), "js_count": js_dl,
            "host": h["host"], "port": h["port"],
        }
    return None

def phase2_scan(live_hosts):
    print(f"\n[Phase 2] HTTP fetch + JS extract + API scan: {len(live_hosts)} hosts", flush=True)

    targets = []
    done = 0
    with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as pool:
        futures = {pool.submit(process_host, h): h for h in live_hosts}
        for f in as_completed(futures):
            done += 1
            if done % 100 == 0:
                print(f"  [{done}/{len(live_hosts)}] {len(targets)} with APIs", flush=True)
            try:
                r = f.result()
                if r: targets.append(r)
            except: pass

    print(f"  Phase 2 DONE: {len(targets)} targets with API endpoints", flush=True)
    return targets

# ========== PHASE 3: UNAUTHORIZED ACCESS TEST ==========
AUTH_FAIL = [
    "缺少请求授权令牌", "token无效", "token过期", "token失效", "未登录", "请登录",
    "请先登录", "登录已过期", "重新登录", "认证失败", "鉴权失败",
    "Unauthorized", "unauthenticated", "Authentication required",
    "Full authentication is required", "Access Denied",
]

def is_auth_fail(data):
    if not isinstance(data, dict): return False
    code = str(data.get("code") or data.get("statusCode") or data.get("status") or "")
    msg = str(data.get("msg") or data.get("message") or data.get("errorMessage") or "")
    if code in ("10031", "401", "403", "500002", "40001", "4010"): return True
    for p in AUTH_FAIL:
        if p in msg: return True
    return False

def has_data(data):
    if isinstance(data, list): return len(data) > 0
    if isinstance(data, dict):
        # Filter out error pages disguised as JSON
        if set(data.keys()) == {"path", "time"} or set(data.keys()) == {"timestamp", "status", "error", "path"}:
            return False
        if "error" in data and "path" in data and len(data) <= 5:
            return False
        if data.get("status") and data.get("error") and data.get("message"):
            return False

        d = data.get("data")
        if d is not None and d != "" and d != [] and d != {} and d is not False:
            if isinstance(d, dict):
                # Check it's not an error response
                keys = set(d.keys())
                if keys in ({"path", "time"}, {"timestamp", "error", "status", "path"}):
                    return False
            return True
        r = data.get("records")
        if r is not None and r != "" and r != [] and r != {}:
            return True
        # list/items in root
        for k in ["list", "items"]:
            v = data.get(k)
            if isinstance(v, list) and len(v) > 0:
                return True
        # Direct content
        if data.get("content") not in (None, "",):
            return True
        if data.get("flag") is True:
            return True
    return False

def summarize(data):
    s = {}
    if isinstance(data, list):
        s["count"] = len(data)
        s["sample"] = data[:2]
        return s
    if not isinstance(data, dict): return s
    d = data.get("data")
    if isinstance(d, list):
        s["count"] = len(d)
        if d: s["sample"] = d[:2]
    elif isinstance(d, dict):
        s["keys"] = list(d.keys())[:20]
        if "total" in d: s["total"] = d["total"]
        if "list" in d and isinstance(d["list"], list):
            s["items"] = len(d["list"])
            if d["list"]: s["sample"] = d["list"][:2]
        if "records" in d and isinstance(d["records"], list):
            s["items"] = len(d["records"])
            if d["records"]: s["sample"] = d["records"][:2]
    # Direct fields
    for k in ["total", "count"]:
        if k in data and isinstance(data[k], (int, float)):
            s[k] = data[k]
    # Flag-based success
    if data.get("flag") is True:
        s["flag"] = True
    return s

def test_api(base_url, path):
    clean = path.split("?")[0].rstrip("/")
    if not clean: return None
    url = urljoin(base_url, clean)

    for method in ["GET", "POST"]:
        try:
            if method == "GET":
                req = Request(url, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
            else:
                req = Request(url, data=b"{}", headers={
                    "User-Agent": "Mozilla/5.0",
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                })
            resp = urlopen(req, timeout=API_TIMEOUT, context=ssl_ctx)
            body = resp.read().decode('utf-8', errors='replace')
            if len(body) < 30: continue
            data = parse_json(body)
            if data is None: continue
            if is_auth_fail(data): continue
            if not has_data(data): continue

            return {
                "url": url, "method": method, "status": resp.getcode(),
                "summary": summarize(data), "raw": body[:1500]
            }
        except HTTPError as e:
            if e.code not in (404, 403, 405):
                try:
                    body = e.read().decode('utf-8', errors='replace')
                    data = parse_json(body)
                    if data and has_data(data) and not is_auth_fail(data):
                        return {"url": url, "method": method, "status": e.code,
                                "summary": summarize(data), "raw": body[:500]}
                except: pass
        except: pass
    return None

def phase3_test(api_targets):
    print(f"\n[Phase 3] Unauthorized access testing: {len(api_targets)} targets", flush=True)

    vulnerable = []
    done = 0

    def test_one(t):
        findings = []
        paths = t["apis"][:50]  # Test up to 50 APIs per target
        with ThreadPoolExecutor(max_workers=API_TEST_WORKERS) as pool:
            futures = {pool.submit(test_api, t["base"], p): p for p in paths}
            for f in as_completed(futures):
                try:
                    r = f.result()
                    if r: findings.append(r)
                except: pass
        if findings:
            t["findings"] = findings
            t["finding_count"] = len(findings)
            # Save individual result
            fname = re.sub(r'[^a-zA-Z0-9]', '_', t["base"]) + ".json"
            with open(os.path.join(OUTDIR, fname), "w") as f:
                json.dump(t, f, ensure_ascii=False, indent=2, default=str)
            return t
        return None

    with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as pool:
        futures = {pool.submit(test_one, t): t for t in api_targets}
        for f in as_completed(futures):
            done += 1
            if done % 20 == 0:
                print(f"  [{done}/{len(api_targets)}] {len(vulnerable)} vulnerable", flush=True)
            try:
                r = f.result()
                if r:
                    vulnerable.append(r)
                    print(f"\n  [!] {r['base']} | {r['title'][:70]}", flush=True)
                    for fi in r["findings"][:5]:
                        s = fi["summary"]
                        print(f"      [{fi['method']}] {fi['url']}", flush=True)
                        if s.get("keys"): print(f"        keys={s['keys'][:10]}", flush=True)
                        if s.get("total"): print(f"        total={s['total']}", flush=True)
                        if s.get("count"): print(f"        count={s['count']}", flush=True)
                        if s.get("sample"):
                            print(f"        sample={json.dumps(s['sample'], ensure_ascii=False)[:200]}", flush=True)
            except: pass

    print(f"  Phase 3 DONE: {len(vulnerable)} vulnerable targets", flush=True)
    return vulnerable

# ========== PHASE 4: REPORT ==========
def phase4_report(vulnerable, total_scanned):
    print(f"\n[Phase 4] Report generation", flush=True)

    report = {
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_scanned": total_scanned,
        "vulnerable_count": len(vulnerable),
        "vulnerable": [],
    }

    for v in vulnerable:
        entry = {
            "url": v["base"], "title": v.get("title", ""),
            "host": v.get("host", ""), "port": v.get("port", 0),
            "js_count": v.get("js_count", 0), "api_count": len(v.get("apis", [])),
            "finding_count": v.get("finding_count", 0), "findings": [],
        }
        for fi in v.get("findings", []):
            entry["findings"].append({
                "url": fi["url"], "method": fi["method"], "summary": fi["summary"],
            })
        report["vulnerable"].append(entry)

    # JSON
    jp = os.path.join(OUTDIR, "report.json")
    with open(jp, "w") as f:
        json.dump(report, f, ensure_ascii=False, indent=2, default=str)

    # Markdown
    mp = os.path.join(OUTDIR, "report.md")
    with open(mp, "w") as f:
        f.write("# JS/API 未授权访问漏洞扫描报告\n\n")
        f.write(f"- **扫描时间**: {report['scan_time']}\n")
        f.write(f"- **目标总数**: {report['total_scanned']}\n")
        f.write(f"- **漏洞目标**: {report['vulnerable_count']}\n\n")

        if not vulnerable:
            f.write("未发现漏洞。\n")
        else:
            f.write("## 漏洞汇总\n\n")
            f.write("| # | URL | 标题 | 漏洞端点 |\n")
            f.write("|---|-----|------|----------|\n")
            for i, v in enumerate(report["vulnerable"]):
                f.write(f"| {i+1} | {v['url']} | {v['title'][:40]} | {v['finding_count']} |\n")

            f.write("\n## 详细信息\n\n")
            for i, v in enumerate(report["vulnerable"]):
                f.write(f"### [{i+1}] {v['url']}\n\n")
                f.write(f"- **标题**: {v['title']}\n")
                f.write(f"- **主机**: {v['host']}:{v['port']}\n")
                f.write(f"- **JS文件**: {v['js_count']}, **API数**: {v['api_count']}\n\n")
                for fi in v["findings"]:
                    f.write(f"- `{fi['method']}` {fi['url']}\n")
                    s = fi.get("summary", {})
                    for k, val in s.items():
                        if isinstance(val, list):
                            val = json.dumps(val[:3], ensure_ascii=False)
                        f.write(f"  - {k}: {str(val)[:200]}\n")
                    f.write("\n")
                f.write("---\n\n")

    print(f"  JSON: {jp}", flush=True)
    print(f"  MD: {mp}", flush=True)
    return report

# ========== MAIN ==========
def main():
    print("=" * 60, flush=True)
    print("JS/API UNAUTHORIZED ACCESS SCANNER v2", flush=True)
    print(f"Ports: {len(WEB_PORTS)} | Workers: T{TCP_WORKERS}/S{SCAN_WORKERS}/A{API_TEST_WORKERS}", flush=True)
    print("=" * 60, flush=True)

    with open(INPUT) as f:
        raw = [l.strip() for l in f if l.strip()]

    seen_hosts = set()
    targets = []
    for t in raw:
        host = t.split("//")[-1].split("/")[0].split(":")[0].strip()
        if host and host not in seen_hosts:
            seen_hosts.add(host)
            targets.append(t)

    print(f"\n[*] {len(targets)} unique targets loaded", flush=True)
    start = time.time()

    # Phase 1
    live = phase1_probe(targets)
    if not live:
        print("[!] No live hosts. Exiting.", flush=True)
        phase4_report([], len(targets))
        return

    # Phase 2
    api_targets = phase2_scan(live)

    # Phase 3
    vulnerable = []
    if api_targets:
        vulnerable = phase3_test(api_targets)

    # Phase 4
    phase4_report(vulnerable, len(targets))

    elapsed = time.time() - start
    print(f"\n{'='*60}", flush=True)
    print(f"SCAN COMPLETE: {elapsed:.0f}s ({elapsed/60:.1f}min)", flush=True)
    print(f"Targets: {len(targets)} | Live: {len(live)} | APIs: {len(api_targets)} | Vuln: {len(vulnerable)}", flush=True)
    print(f"Results: {OUTDIR}/", flush=True)
    print(f"{'='*60}", flush=True)

if __name__ == "__main__":
    main()
