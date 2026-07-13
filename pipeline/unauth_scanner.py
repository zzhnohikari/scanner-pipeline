#!/usr/bin/env python3
"""
构建于 jjjjjsz 工具之上的未授权访问扫描器
- 使用 extract_api.py 的 API 提取模式
- 使用 spider2.py 的 JS 发现逻辑
- 新增：未授权访问测试 + 漏洞报告
"""

import sys, os, re, json, time, ssl, socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from collections import defaultdict

# ======= 从 jjjjjsz/extract_api.py 继承的配置 =======
# 第三方库过滤（从 extract_api.py 行55-213 继承）
COMMON_LIBS = re.compile(
    r'(?:jquery|bootstrap|vue\.min|vue\.runtime|react\.min|react\.production|'
    r'angular\.min|axios\.min|lodash|moment|echarts|swiper|'
    r'polyfill|fontawesome|materialize|foundation|modernizr|'
    r'd3\.min|three\.min|popper|zepto|hammer|gsap|anime|'
    r'datatable|select2|cropper|sweetalert|tinymce|ckeditor|quill|summernote|'
    r'codemirror|ace-editor|monaco|crypto-js|socket\.io|'
    r'pdf\.js|jspdf|leaflet|mapbox|openlayers|fabric|'
    r'highlight|prism|markdown|marked|showdown|'
    r'velocity|waypoints|fullpage|wow|isotope|parallax|'
    r'slick|owl\.carousel|flickity|masonry|highcharts|raphael|'
    r'snap\.svg|webfont|scrollmagic|scrollreveal|particles|'
    r'vivus|lottie|bodymovin|aos|barba|cleave|dropzone|'
    r'nouislider|plyr|rellax|smooth-scroll|tippy|toastr|'
    r'clipboard|draggable|dragula|sortable|simplebar|autosize|'
    r'flatpickr|intl-tel-input|lazysizes|stickyfill|jarallax|'
    r'photoswipe|lightgallery|fancybox|magnific-popup|'
    r'filepond|uppy|shepherd|driver|intro\.js|tether|headroom|'
    r'chunk-vendors|chunk-common|vendor\.\w{8}\.|vendors\.\w{8}\.|'
    r'core-js|regenerator|webpack\.runtime|babel|polyfill|'
    r'dayjs|luxon|numeral|jszip|pdfmake|xlsx|docxtemplater|'
    r'trumbowyg|pell|trix|prosemirror|draft-js|slate|'
    r'blockly|konva|pixi|phaser|matter-js|box2d|'
    r'cannon|babylon|aframe|medium-editor)', re.I
)

# 从 extract_api.py 继承的 API 提取正则（行329-355区域的核心模式）
API_EXTRACT_PATTERNS = [
    # url: "/api/xxx"
    (re.compile(r'''url\s*:\s*["']([^"']{2,200})["']''', re.I), "url"),
    # path: "/xxx"
    (re.compile(r'''path\s*:\s*["']([^"']{2,200})["']''', re.I), "path"),
    # baseURL: "/xxx"
    (re.compile(r'''baseURL\s*:\s*["']([^"']{2,200})["']''', re.I), "baseURL"),
    # .get("/xxx"), .post("/xxx")
    (re.compile(r'''\.(?:get|post|put|patch)\s*\(\s*["']([^"']{2,200})["']''', re.I), "method"),
    # axios({url: "/xxx"})
    (re.compile(r'''axios\s*\(\s*\{[^}]*?url\s*:\s*["']([^"']{2,200})["']''', re.I), "axios"),
    # fetch("/xxx")
    (re.compile(r'''fetch\s*\(\s*["']([^"']{2,200})["']''', re.I), "fetch"),
    # request({url: "/xxx"})
    (re.compile(r'''request\s*\(\s*\{[^}]*?url\s*:\s*["']([^"']{2,200})["']''', re.I), "request"),
    # Generic API paths in quotes
    (re.compile(r'''["'](/api/[a-zA-Z][a-zA-Z0-9_/\-.]{2,200})["']''', re.I), "direct_api"),
    # 中文API路径
    (re.compile(r'''["'](/[a-zA-Z][a-zA-Z0-9_/\-.]{3,200}/(?:list|query|find|get|add|update|delete|save|info|config|user|admin|login|logout|token|auth|server|device|channel|record|platform|role|log|data|push|proxy|group|region|upload|download|file|notary|enterprise|portal|biz|profile|account|setting|manage|dashboard|monitor|stream|video|camera|media)[a-zA-Z0-9_/\-.]{0,100})["']''', re.I), "business"),
]

# 从 extract_api.py 的行383区域继承：需要 POST 的特殊端点
NEED_POST_FIX = re.compile(r'/(?:add|update|delete|save|remove|create|upload|push|reset|change|enable|disable|start|stop|sync|export|import|login|logout|register|submit)/?(?:\?|$)?', re.I)

# ======= 配置 =======
TCP_TIMEOUT = 1.2
HTTP_TIMEOUT = 8
API_TIMEOUT = 6
WORKERS = 50
WEB_PORTS = [80, 443, 8080, 8443, 8001, 81, 82, 88, 3000, 4000, 5000, 7000, 8000, 8002, 8008, 8081, 8088, 8089, 8888, 9000, 9090, 9443, 10000, 10080]

INPUT = "/tmp/targets_filtered.txt"
OUTDIR = "/tmp/pipeline_results"
os.makedirs(OUTDIR, exist_ok=True)

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

# ======= 核心函数 =======
def http_get(url, timeout=HTTP_TIMEOUT, max_size=500000):
    try:
        req = Request(url, headers={
            "User-Agent": "Mozilla/5.0 (compatible; scanner)",
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

def tcp_check(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TCP_TIMEOUT)
        r = s.connect_ex((str(host), int(port)))
        s.close()
        return r == 0
    except: return False

def extract_js_urls(html, base_url):
    """从 HTML 提取 JS 文件 URL（继承 spider2.py 的提取逻辑）"""
    js = set()
    # <script src="...">
    for m in re.finditer(r'<script[^>]+src\s*=\s*["\x27]?([^"\'<>\s]+\.js(?:[^"\'<>\s]*))["\x27]?', html, re.I):
        js.add(urljoin(base_url, m.group(1)))
    # webpack chunks
    for m in re.finditer(r'''(?:src|href)\s*=\s*["\x27]?([^"\'<>\s]*/js/[^"\'<>\s]+\.js)["\x27]?''', html, re.I):
        js.add(urljoin(base_url, m.group(1)))
    # dynamic imports
    for m in re.finditer(r'''["\x27]([^"\x27]*?/static/js/[^"\x27]+\.js)["\x27]''', html):
        js.add(urljoin(base_url, m.group(1)))
    return js

def extract_apis_from_js(content):
    """从 JS 内容提取 API 路径（继承 extract_api.py 的核心模式）"""
    apis = set()
    for pat, pat_type in API_EXTRACT_PATTERNS:
        for m in pat.finditer(content):
            path = m.group(1).strip()
            if not path or path.startswith("http") or path.startswith("//"): continue
            if not path.startswith("/"): path = "/" + path
            path = path.split("?")[0].rstrip("/")
            if len(path) < 2 or len(path) > 200: continue
            if path in ("/", "/#", "/#/"): continue
            # 过滤静态文件
            ext = os.path.splitext(path)[1].lower()
            if ext in ('.js','.css','.png','.jpg','.gif','.svg','.ico','.woff','.woff2','.ttf','.eot','.map','.json','.xml','.html','.pdf'): continue
            # 只保留 API 相关路径
            if re.search(r'/api/|/user|/admin|/login|/logout|/auth|/token|/server|/system|/device|/channel|/record|/platform|/role|/log|/data|/info|/config|/push|/proxy|/group|/region|/upload|/download|/file|/notary|/enterprise|/portal|/biz|/profile|/account|/setting|/manage|/dashboard|/query|/list|/search|/find|/monitor|/stream|/video|/camera|/media|/back/', path, re.I):
                apis.add(path)
    return apis

AUTH_FAIL_MSGS = [
    "缺少请求授权令牌", "token无效", "token过期", "token失效", "未登录", "请登录",
    "请先登录", "登录已过期", "重新登录", "认证失败", "鉴权失败",
    "Unauthorized", "unauthorized", "unauthenticated", "Authentication required",
    "Full authentication", "Access Denied", "Forbidden",
    "code不存在", "请求类型不支持", "Method not supported",
]

def is_auth_fail(data):
    if not isinstance(data, dict): return False
    code = str(data.get("code") or data.get("statusCode") or data.get("status") or "")
    msg = str(data.get("msg") or data.get("message") or data.get("errorMessage") or "")
    if code in ("10031", "401", "403", "500002", "40001", "4010", "5005"): return True
    return any(p in msg for p in AUTH_FAIL_MSGS)

def has_real_data(data):
    if isinstance(data, list): return len(data) > 0
    if isinstance(data, dict):
        if set(data.keys()).issubset({"path","time","timestamp","status","error","message"}): return False
        d = data.get("data")
        if d not in (None, "", [], {}, False): return True
        for k in ("records", "list", "items", "content"):
            v = data.get(k)
            if v not in (None, "", [], {}): return True
        if data.get("flag") is True: return True
    return False

def test_endpoint(base_url, path):
    """测试单个API端点是否可未授权访问"""
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
            data = None
            try: data = json.loads(body)
            except: continue
            if data is None: continue
            if is_auth_fail(data): continue
            if not has_real_data(data): continue

            result = {
                "url": url, "method": method, "status": resp.getcode(),
                "raw": body[:1500]
            }
            # 数据摘要
            if isinstance(data, dict):
                d = data.get("data")
                if isinstance(d, list):
                    result["count"] = len(d)
                    result["sample"] = json.dumps(d[:2], ensure_ascii=False)[:500]
                elif isinstance(d, dict):
                    result["keys"] = list(d.keys())[:20]
                    if "total" in d: result["total"] = d["total"]
                    if "list" in d: result["items"] = len(d["list"])
                elif isinstance(data, list):
                    result["count"] = len(data)
            return result
        except HTTPError as e:
            if e.code not in (404, 403, 405):
                try:
                    body = e.read().decode('utf-8', errors='replace')
                    data = json.loads(body)
                    if has_real_data(data) and not is_auth_fail(data):
                        return {"url": url, "method": method, "status": e.code, "raw": body[:500]}
                except: pass
        except: pass
    return None

# ======= 主流程 =======
def main():
    print("=" * 60)
    print("基于 jjjjjsz 工具的未授权访问扫描器")
    print("=" * 60)

    with open(INPUT) as f:
        targets = [l.strip() for l in f if l.strip()]

    # 去重
    seen = set()
    unique = []
    for t in targets:
        h = t.split("//")[-1].split("/")[0].split(":")[0].strip()
        if h and h not in seen:
            seen.add(h)
            unique.append(t)

    print(f"\n[*] {len(unique)} targets")
    start = time.time()

    # Phase 1: TCP 探测
    print(f"\n[Phase 1] TCP 探测...")
    live = []
    with ThreadPoolExecutor(max_workers=300) as pool:
        def probe(t):
            t = t.strip()
            if t.startswith("http"):
                p = urlparse(t)
                port = p.port or (443 if p.scheme=="https" else 80)
                if tcp_check(p.hostname, port):
                    return {"url": f"{p.scheme}://{p.hostname}:{port}" if port not in (80,443) else f"{p.scheme}://{p.hostname}"}
            else:
                for port in WEB_PORTS:
                    if tcp_check(t, port):
                        s = "https" if port in (443,8443,9443) else "http"
                        return {"url": f"{s}://{t}:{port}" if port not in (80,443) else f"{s}://{t}"}
            return None

        futures = [pool.submit(probe, t) for t in unique]
        for f in as_completed(futures):
            try:
                r = f.result()
                if r: live.append(r)
            except: pass

    print(f"  {len(live)} live hosts")

    # Phase 2: JS下载 + API提取（使用 jjjjjsz 的提取模式）
    print(f"\n[Phase 2] JS下载 + API提取...")
    api_targets = []

    def process(h):
        url = h["url"] + "/"
        status, final_url, html = http_get(url)
        if not status or status >= 500 or not html or len(html) < 100:
            return None

        title = ""
        m = re.search(r'<title[^>]*>([^<]+)</title>', html, re.I)
        if m: title = m.group(1).strip()[:200]

        parsed = urlparse(final_url)
        base = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port and parsed.port not in (80,443):
            base += f":{parsed.port}"

        # 提取 JS（继承 spider2.py 逻辑）
        js_urls = extract_js_urls(html, base)
        app_js = [j for j in js_urls if not COMMON_LIBS.search(j)]
        if not app_js: return None

        # 下载 JS 并提取 API（继承 extract_api.py 模式）
        all_apis = set()
        js_dl = 0
        for js_url in list(app_js)[:15]:
            s, _, content = http_get(js_url, max_size=300000)
            if s != 200 or not content: continue
            js_dl += 1
            all_apis.update(extract_apis_from_js(content))

        # 添加通用敏感路径
        all_apis.update([
            "/api/user/users", "/api/user/list", "/api/user/info",
            "/api/server/info", "/api/server/system/info", "/api/server/system/configInfo",
            "/api/role/all", "/api/log/list", "/api/device/query/devices",
            "/actuator/health", "/actuator/env",
            "/swagger-resources", "/v3/api-docs", "/v2/api-docs",
            "/druid/index.html",
        ])

        if all_apis:
            return {"base": base, "title": title, "apis": sorted(all_apis), "js_count": js_dl}
        return None

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(process, h): h for h in live}
        for f in as_completed(futures):
            try:
                r = f.result()
                if r: api_targets.append(r)
            except: pass

    print(f"  {len(api_targets)} hosts with APIs")

    # Phase 3: 未授权访问测试
    print(f"\n[Phase 3] 未授权访问测试...")
    vulnerable = []

    def scan_target(t):
        findings = []
        with ThreadPoolExecutor(max_workers=15) as pool:
            futures = {pool.submit(test_endpoint, t["base"], p): p for p in t["apis"][:50]}
            for f in as_completed(futures):
                try:
                    r = f.result()
                    if r: findings.append(r)
                except: pass
        if findings:
            t["findings"] = findings
            # 保存结果文件
            fname = re.sub(r'[^a-zA-Z0-9]', '_', t["base"]) + ".json"
            with open(os.path.join(OUTDIR, fname), "w") as f:
                json.dump(t, f, ensure_ascii=False, indent=2, default=str)
            return t
        return None

    done = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(scan_target, t): t for t in api_targets}
        for f in as_completed(futures):
            done += 1
            if done % 50 == 0:
                print(f"  [{done}/{len(api_targets)}] {len(vulnerable)} vuln")
            try:
                r = f.result()
                if r:
                    vulnerable.append(r)
                    print(f"\n  [!] {r['base']} | {r['title'][:60]}")
                    for fi in r["findings"][:5]:
                        print(f"      [{fi['method']}] {fi['url']}")
                        if fi.get("keys"): print(f"        keys={fi['keys'][:10]}")
                        if fi.get("total"): print(f"        total={fi['total']}")
                        if fi.get("count"): print(f"        count={fi['count']}")
            except: pass

    print(f"\n  DONE: {len(vulnerable)} vulnerable")

    # Phase 4: 报告
    print(f"\n[Phase 4] 生成报告...")
    elapsed = time.time() - start
    report = {
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "duration": f"{elapsed:.0f}s",
        "targets": len(unique),
        "live": len(live),
        "with_apis": len(api_targets),
        "vulnerable": len(vulnerable),
        "findings": vulnerable
    }
    with open(os.path.join(OUTDIR, "final_report.json"), "w") as f:
        json.dump(report, f, ensure_ascii=False, indent=2, default=str)

    print(f"  报告: {OUTDIR}/final_report.json")
    print(f"\n{'='*60}")
    print(f"扫描完成: {elapsed:.0f}s | {len(unique)}→{len(live)}→{len(api_targets)}→{len(vulnerable)}")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
