#!/usr/bin/env python3
"""
v13: 文件专项 + HTML/JS静态参数画像 + URL/参数绑定 + POST body/form fuzz
融合 JSFinder/Webpack_extract/VueCrack/Packer-Fuzzer 技术
"""

import os, re, json, time, ssl, socket, argparse, logging
from concurrent.futures import ThreadPoolExecutor, as_completed, wait
from urllib.parse import urlparse, urljoin, urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError

# ===== CLI =====
parser = argparse.ArgumentParser(description='JS/API 未授权访问扫描器 v13')
parser.add_argument('--input', default='/tmp/v7_targets.json', help='目标JSON文件')
parser.add_argument('--outdir', default='/tmp/v13_scan_results', help='输出目录')
parser.add_argument('--workers', type=int, default=50, help='并发数')
parser.add_argument('--timeout', type=int, default=12, help='HTTP超时(秒)')
parser.add_argument('--phase2-timeout', type=int, default=180, help='Phase 2 JS/API提取软超时(秒),超时目标用baseline兜底')
parser.add_argument('--phase3a-timeout', type=int, default=240, help='Phase 3a 快筛软超时(秒),超时后先进入候选/补筛流程')
parser.add_argument('--rescue-timeout', type=int, default=180, help='Phase 3a baseline补筛软超时(秒)')
parser.add_argument('--phase3b-layer-timeout', type=int, default=300, help='Phase 3b 每个分层软超时(秒)')
parser.add_argument('--limit', type=int, default=0, help='限制目标数量,0=全部')
parser.add_argument('--dry-run', action='store_true', help='只提取API,不测试')
parser.add_argument('--full-bypass', action='store_true', help='收集所有绕过方法(默认命中断路)')
parser.add_argument('--debug', action='store_true', help='调试日志')
parser.add_argument('--no-proxy', action='store_true', help='绕过系统代理(ClashX等)')
parser.add_argument('--fresh', action='store_true', help='扫描前清理输出目录中的旧JSON报告/checkpoint')
parser.add_argument('--resume', action='store_true', help='报告阶段合并输出目录中的历史checkpoint(默认只统计本轮结果)')
parser.add_argument('--disable-file-hunter', action='store_true', help='关闭下载/预览/导出接口专项检测')
parser.add_argument('--enable-file-baseline', action='store_true', help='启用硬编码文件下载baseline路径(默认关闭)')
parser.add_argument('--file-max-probes', type=int, default=36, help='每个疑似文件接口最多探测次数')
parser.add_argument('--disable-param-harvest', action='store_true', help='关闭HTML/JS静态参数画像')
parser.add_argument('--param-max-probes', type=int, default=12, help='每个接口最多静态参数模板探测次数')
parser.add_argument('--param-probe-mode', choices=['targeted','broad'], default='targeted', help='静态参数探测模式: targeted仅高价值接口,broad全部接口')
args = parser.parse_args()

log = logging.getLogger('scanner')
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG if args.debug else logging.WARNING)

TCP_TIMEOUT = 1.5; HTTP_TIMEOUT = args.timeout; API_TIMEOUT = max(6, args.timeout//2)
WORKERS = args.workers; SSL_RETRIES = 2; OUTDIR = args.outdir
os.makedirs(OUTDIR, exist_ok=True)
if args.fresh:
    for name in os.listdir(OUTDIR):
        if name.endswith((".json", ".md")):
            try:
                os.remove(os.path.join(OUTDIR, name))
            except Exception as e:
                log.debug(f"Remove old output {name} failed: {e}")

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

# 绕过系统代理 (ClashX 等 macOS 系统级代理)
if args.no_proxy:
    import urllib.request as _ur
    _proxy_handler = _ur.ProxyHandler({})
    _no_proxy_opener = _ur.build_opener(_proxy_handler)
    _ur.install_opener(_no_proxy_opener)

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
API_PREFIX_RE = re.compile(
    r'''["']?(?:baseURL|baseUrl|baseApi|apiBase|apiPrefix|apiUrl|apiURL|api_url|apiHost|api_host|'''
    r'''contextPath|serverBase|serverUrl|serverURL|proxyPrefix|VUE_APP_BASE_API|'''
    r'''VUE_APP_API_BASE|VUE_APP_API_URL|REACT_APP_API_URL|REACT_APP_BASE_API|'''
    r'''NEXT_PUBLIC_API_URL|API_BASE_URL|API_BASE|API_URL|BASE_API)["']?\s*[:=]\s*["']((?:https?:)?//[^"']{1,220}|/[^"']{1,160})["']''',
    re.I)
PUBLIC_PATH_RE = re.compile(r'''["']?(?:publicPath|assetsPublicPath)["']?\s*[:=]\s*["']((?:https?:)?//[^"']{1,220}|/[^"']{1,160})["']''', re.I)
QUERY_PARAM_RE = re.compile(r'''[?&]([a-zA-Z_][a-zA-Z0-9_\-]{1,40})=''')
OBJECT_PARAM_RE = re.compile(r'''["']?([a-zA-Z_][a-zA-Z0-9_]{1,40})["']?\s*:\s*["']?([a-zA-Z0-9_\-./:@]{1,120})["']?''')
FORM_FIELD_RE = re.compile(r'''(?:name|v-model|prop|field)\s*=\s*["']([a-zA-Z_][a-zA-Z0-9_.\-\[\]]{1,60})["']''', re.I)
REQUEST_BODY_RE = re.compile(r'''(?:params|data|body)\s*:\s*\{([^{}]{1,2000})\}''', re.I)

def _param_source_from_prop(prop, method=""):
    prop = (prop or "").lower()
    method = (method or "").lower()
    if prop == "params":
        return "query"
    if prop in ("form", "formdata"):
        return "form"
    if method == "get":
        return "query"
    if prop in ("data", "body"):
        return "json"
    return "json"

def _extract_url_body_sources(text):
    """Extract (url, body_text, source) from common JS request styles."""
    pairs = []
    obj = r'''\{(?:[^{}]|\{[^{}]*\})*\}'''
    # Pattern 1: request({url:"/api/x", ..., data:{...}})
    for m in re.finditer(r'''request\s*\(\s*\{\s*url\s*:\s*["']([^"']{2,200})["'].*?(data|params|body)\s*:\s*(''' + obj + r''')''', text, re.I):
        pairs.append((m.group(1), m.group(3), _param_source_from_prop(m.group(2))))
    # Pattern 2: fetch("/api/x", {body:JSON.stringify({...})})
    for m in re.finditer(r'''fetch\s*\(\s*["']([^"']{2,200})["'].*?body\s*:\s*JSON\.stringify\s*\((''' + obj + r''')''', text, re.I):
        pairs.append((m.group(1), m.group(2), "json"))
    # Pattern 3: fetch("/api/x?"+new URLSearchParams({...}))
    for m in re.finditer(r'''fetch\s*\(\s*["']([^"']{2,200})["']\s*\+\s*new\s+URLSearchParams\s*\((''' + obj + r''')''', text, re.I):
        pairs.append((m.group(1), m.group(2), "query"))
    # Pattern 4: fetch("/api/x", {body:qs.stringify({...})})
    for m in re.finditer(r'''fetch\s*\(\s*["']([^"']{2,200})["'].*?body\s*:\s*(?:qs\.)?stringify\s*\((''' + obj + r''')''', text, re.I):
        pairs.append((m.group(1), m.group(2), "form"))
    # Pattern 4b: fetch("/api/x", {body:new URLSearchParams({...})})
    for m in re.finditer(r'''fetch\s*\(\s*["']([^"']{2,200})["'].*?body\s*:\s*new\s+URLSearchParams\s*\((''' + obj + r''')''', text, re.I):
        pairs.append((m.group(1), m.group(2), "form"))
    # Pattern 5: http.post("/api/x", {...}) / axios.post("/api/x", {...}) / request.get(...)
    for m in re.finditer(r'''(?:this\.)?(?:http|axios|request|service|api)\.(get|post|put|patch|delete)\s*\(\s*["']([^"']{2,200})["']\s*,\s*(''' + obj + r''')''', text, re.I):
        body = m.group(3)
        source = "query" if re.search(r'''params\s*:''', body, re.I) or m.group(1).lower() == "get" else "json"
        pairs.append((m.group(2), body, source))
    # Pattern 6: request("/api/x", {params:{...}}) / axios("/api/x", {data:{...}})
    for m in re.finditer(r'''(?:request|axios)\s*\(\s*["']([^"']{2,200})["']\s*,\s*\{.*?(data|params|body)\s*:\s*(''' + obj + r''')''', text, re.I):
        pairs.append((m.group(1), m.group(3), _param_source_from_prop(m.group(2))))
    # Pattern 7: axios({url:"/api/x", params:{...}}) / uni.request({url:"/api/x", data:{...}})
    for m in re.finditer(r'''(?:axios|request|uni\.request|wx\.request|\w+\.request)\s*\(\s*\{.*?url\s*:\s*["']([^"']{2,200})["'].*?(data|params|body)\s*:\s*(''' + obj + r''')''', text, re.I):
        pairs.append((m.group(1), m.group(3), _param_source_from_prop(m.group(2))))
    # Pattern 8: $.ajax({url:"/api/x", data:{...}}) / $.getJSON({url:"/api/x", data:{...}})
    for m in re.finditer(r'''\$\.(?:ajax|post|get|getJSON)\s*\(\s*\{[^}]*?url\s*:\s*["']([^"']{2,200})["'].*?data\s*:\s*(''' + obj + r''')''', text, re.I):
        source = "query" if re.search(r'''(?:type|method)\s*:\s*["']?GET["']?''', m.group(0), re.I) else "form"
        pairs.append((m.group(1), m.group(2), source))
    # Pattern 9: $.get("/api/x", {...}) / $.post("/api/x", {...}) / $.getJSON("/api/x", {...})
    for m in re.finditer(r'''\$\.(get|post|getJSON)\s*\(\s*["']([^"']{2,200})["']\s*,\s*(''' + obj + r''')''', text, re.I):
        source = "form" if m.group(1).lower() == "post" else "query"
        pairs.append((m.group(2), m.group(3), source))
    # Pattern 10: const fd = new FormData(); fd.append("docId", ...); axios.post("/api/x", fd)
    for m in re.finditer(r'''(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*=\s*new\s+FormData\s*\(\s*\)\s*;([\s\S]{0,1500}?)(?:axios|request|http|service)\.post\s*\(\s*["']([^"']{2,200})["']\s*,\s*\1''', text, re.I):
        fd_name, middle, url_path = m.group(1), m.group(2), m.group(3)
        keys = re.findall(r'''%s\.append\s*\(\s*["']([a-zA-Z_][a-zA-Z0-9_]{1,40})["']''' % re.escape(fd_name), middle)
        if keys:
            pairs.append((url_path, "{" + ",".join(f"{k}:1" for k in keys) + "}", "form"))
    # Pattern 11: window.open("/api/x?param="+value) / location.href="/api/x?id="+id
    for m in re.finditer(r'''(?:window\.open|location\.href)\s*\(\s*["']([^"']{2,200}\?(?:[a-zA-Z_][a-zA-Z0-9_]*=)["']\s*\+)''', text, re.I):
        url_part = m.group(1).rstrip('"+ ')
        pairs.append((url_part.split("?")[0], "", "query"))
    return pairs

def _extract_url_body_pairs(text):
    return [(url, body) for url, body, _source in _extract_url_body_sources(text)]
FILE_SEED_RE = re.compile(r'''["']([a-zA-Z0-9_\-./]{1,120}\.(?:pdf|doc|docx|xls|xlsx|csv|zip|rar|7z|jpg|jpeg|png|gif|txt))["']''', re.I)
NUMERIC_ID_RE = re.compile(r'''(?:id|Id|ID|fileId|docId|recordId|userId|deptId|orgId|attachId)\s*[:=]\s*["']?(\d{1,12})["']?''')
COMMON_PARAM_HINTS = {
    "id","ids","page","pageNum","pageNo","current","size","pageSize","limit","count",
    "keyword","keywords","query","search","name","username","userId","deptId","orgId",
    "tenantId","type","status","startTime","endTime","beginTime","endDate","startDate",
    "fileId","fileName","filePath","path","url","key","objectKey","ossKey","downloadUrl",
    "recordId","docId","documentId","attachId","attachmentId","templateId"
}
PARAM_PROBE_KEYWORDS = (
    "download","export","preview","file","attach","attachment","document","template",
    "list","query","search","page","detail","info","get","find","select",
    "user","person","people","device","camera","record","report","log","alarm"
)

WEB_PORTS = [80,443,8080,8443,8001,81,82,88,3000,4000,5000,7000,8000,8002,8003,8008,8081,8088,8089,8888,9000,9090,9443,10000,10080,10443,4433,4443]
HTTPS_PORTS = {443, 8443, 9443, 10443, 4433, 4443}

FAST_BYPASS = [
    ("GET_no_auth","GET",None,None,{}),
    ("POST_JSON_no_auth","POST","application/json",lambda p: json.dumps(p).encode(),{}),
]
FULL_BYPASS = FAST_BYPASS + [
    ("GET_empty_bearer","GET",None,None,{"Authorization":"Bearer "}),
    ("GET_admin_token","GET",None,None,{"Authorization":"Bearer admin-token"}),
    ("POST_FORM_no_auth","POST","application/x-www-form-urlencoded",lambda p: urlencode(p).encode(),{}),
    ("POST_JWT_none","POST","application/json",lambda p: json.dumps(p).encode(),{"Authorization":"Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9."}),
]

BASELINE_PATHS = [
    "/api/server/media_server/list","/api/device/query/devices?page=1&count=10",
    "/api/server/media_server/online/list",
    "/api/user/users?page=1&count=10","/api/server/system/configInfo",
    "/api/server/resource/info","/api/role/all","/api/log/list",
    "/swagger-ui.html","/swagger/index.html","/swagger-ui/index.html",
    "/v2/api-docs","/v3/api-docs","/druid/index.html","/druid/datasource.json",
    "/druid/sql.json","/druid/websession.json","/druid/wall.json","/druid/basic.json",
    "/druid/stat.json","/actuator","/actuator/env",
    "/general/login_code_check.php","/e/port/tongji.php",
    "/seeyon/druid/wall.json","/system/admin/user/official/login",
]
SWAGGER_DOC_PATHS = ["/v2/api-docs", "/v3/api-docs", "/openapi.json", "/swagger.json"]
AUTH_FAIL_MSGS = ["缺少请求授权令牌","token无效","未登录","请登录","Unauthorized","Forbidden"]
CAPTCHA_RE = re.compile(
    r"captcha|verifycode|verify_code|verificationcode|validcode|validatecode|"
    r"checkcode|check_code|checknum|randcode|vcode|codeimg|login_code|"
    r"kaptcha|authcode|auth_code|securitycode|seccode",
    re.I,
)
PUBLIC_DOWNLOAD_RE = re.compile(
    r"downloadca|cert|certificate|ca\.|rootca|client|plugin|setup|installer|"
    r"authenticator|webplugin|控件|客户端|证书|插件",
    re.I,
)

FILE_ENDPOINT_KEYWORDS = [
    "download","downLoad","file","files","export","preview","view","read",
    "attachment","attach","upload","resource","document","doc","image",
    "photo","avatar","template","import","excel","word","pdf"
]
FILE_ENDPOINT_WORDS = {k.lower() for k in FILE_ENDPOINT_KEYWORDS}
FILE_ENDPOINT_PREFIXES = ("download", "export", "preview", "upload", "attach", "attachment", "import")
FILE_PARAM_NAMES = [
    "id","ids","fileId","file_id","attachId","attachmentId","docId","documentId",
    "templateId","recordId","path","filePath","url","fileUrl","name","fileName",
    "key","objectKey","ossKey","downloadUrl","resourceId","avatar","src"
]
FILE_SEED_VALUES = [
    "1","2","3","10","100","1000","test","demo","default",
    "1.pdf","test.pdf","demo.pdf","1.xlsx","test.xlsx","1.docx","test.docx",
    "1.jpg","test.jpg","1.png","test.png","template.xlsx","template.docx"
]
FILE_BASELINE_PATHS = [
    "/api/file/download","/api/file/preview","/api/file/view","/api/file/get",
    "/api/common/download","/api/common/download/resource","/api/system/file/download",
    "/api/attachment/download","/api/attach/download","/api/document/download",
    "/api/export","/api/user/export","/api/template/download","/prod-api/common/download",
    "/admin-api/infra/file/download","/admin-api/system/file/download",
]
if args.enable_file_baseline and not args.disable_file_hunter:
    BASELINE_PATHS = BASELINE_PATHS + FILE_BASELINE_PATHS
FILE_CT_HINTS = [
    "application/octet-stream","application/pdf","application/zip","application/x-zip",
    "application/msword","application/vnd.ms-excel","application/vnd.openxmlformats",
    "image/jpeg","image/png","image/gif","application/x-msdownload"
]

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

def http_get(url, timeout=HTTP_TIMEOUT, max_size=1_000_000, retries=SSL_RETRIES):
    for attempt in range(retries + 1):
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
                if attempt < retries:
                    log.debug(f"SSL retry {attempt+1} for {url}")
                    time.sleep(1)
                    continue
            log.debug(f"HTTP GET {url} failed: {e}")
            if attempt == retries: return None, None, "", ""
    return None, None, "", ""

def read_limited(resp, max_size=1_000_000):
    body = b""
    while True:
        chunk = resp.read(65536)
        if not chunk:
            break
        body += chunk
        if len(body) >= max_size:
            break
    return body

def compact_url(url, max_len=120):
    if len(url) <= max_len:
        return url
    keep_head = max_len // 2
    keep_tail = max_len - keep_head - 3
    return url[:keep_head] + "..." + url[-keep_tail:]

def target_url_with_scheme(raw):
    raw = (raw or "").strip()
    if not raw:
        return "", "", None
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        return raw.rstrip("/"), parsed.hostname or "", parsed.port or (443 if parsed.scheme == "https" else 80)
    if "://" in raw:
        return raw.rstrip("/"), "", None
    host = raw
    port = None
    if raw.count(":") == 1:
        left, right = raw.rsplit(":", 1)
        if left and right.isdigit():
            host, port = left.strip("[]"), int(right)
    if port:
        scheme = "https" if port in HTTPS_PORTS else "http"
        default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        return (f"{scheme}://{host}" if default_port else f"{scheme}://{host}:{port}"), host, port
    return "", raw.strip("[]"), None

def is_file_endpoint(path):
    parts = re.split(r'[^A-Za-z0-9]+', path.split("?", 1)[0])
    for part in parts:
        if not part:
            continue
        lowered = part.lower()
        if lowered in FILE_ENDPOINT_WORDS:
            return True
        if any(lowered.startswith(p) or lowered.endswith(p) for p in FILE_ENDPOINT_PREFIXES):
            return True
        words = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', part).lower().split()
        if any(w in FILE_ENDPOINT_WORDS for w in words):
            return True
    return False

def file_magic(raw):
    if raw.startswith(b"%PDF-"): return "PDF"
    if raw.startswith(b"PK\x03\x04"): return "ZIP/OOXML"
    if raw.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"): return "OLE"
    if raw.startswith(b"\xff\xd8\xff"): return "JPEG"
    if raw.startswith(b"\x89PNG\r\n\x1a\n"): return "PNG"
    if raw.startswith(b"GIF87a") or raw.startswith(b"GIF89a"): return "GIF"
    if raw.startswith(b"Rar!\x1a\x07"): return "RAR"
    if raw.startswith(b"7z\xbc\xaf\x27\x1c"): return "7Z"
    if raw.startswith(b"MZ"): return "PE"
    return ""

def looks_like_login_or_error(raw, content_type):
    head = raw[:4096].decode("utf-8", errors="ignore").lower()
    if "text/html" in content_type.lower() and any(x in head for x in ["login", "登录", "请登录", "unauthorized", "forbidden"]):
        return True
    if any(x in head for x in ["缺少请求授权令牌", "token无效", "未登录", "请登录", "unauthorized", "forbidden"]):
        return True
    return False

def looks_like_captcha(url, content_disp=""):
    return bool(CAPTCHA_RE.search((url or "") + " " + (content_disp or "")))

def is_strong_download_endpoint(url):
    p = urlparse(url).path.lower()
    return any(x in p for x in ("/download", "/export", "/preview", "/attach", "/attachment", "/document", "/template"))

def looks_like_public_download(url, content_disp="", magic="", content_type=""):
    text = " ".join([url or "", content_disp or "", magic or "", content_type or ""])
    path = urlparse(url).path.lower()
    if PUBLIC_DOWNLOAD_RE.search(text):
        return True
    return path.endswith((".apk", ".exe", ".msi", ".dmg", ".pkg", ".crt", ".cer", ".pem"))

def check_file_response(raw, headers, url, method, test_name, status_code=None):
    if not raw or len(raw) < 32:
        return None
    if status_code is not None and not (200 <= int(status_code) < 300):
        return None
    content_type = headers.get("Content-Type", "") if headers else ""
    content_disp = headers.get("Content-Disposition", "") if headers else ""
    if looks_like_captcha(url, content_disp):
        return None
    magic = file_magic(raw)
    file_endpoint = is_file_endpoint(url)
    image_file = magic in ("JPEG", "PNG", "GIF")
    if image_file and not content_disp and not is_strong_download_endpoint(url):
        return None
    if image_file and len(raw) < 2048 and not content_disp:
        return None
    score = 0
    reasons = []
    if content_disp:
        score += 3; reasons.append("content_disposition")
    if magic:
        score += 3; reasons.append(f"magic:{magic}")
    if any(x in content_type.lower() for x in FILE_CT_HINTS):
        score += 2; reasons.append(f"content_type:{content_type[:80]}")
    if len(raw) > 2048:
        score += 1; reasons.append("size>2KB")
    if file_endpoint:
        score += 1; reasons.append("file_endpoint")
    if looks_like_login_or_error(raw, content_type):
        score -= 5; reasons.append("auth_or_login_hint")
    if "text/html" in content_type.lower() and not magic and not content_disp:
        score -= 3; reasons.append("html_without_file_signal")
    if score < 4:
        return None
    public_download = looks_like_public_download(url, content_disp, magic, content_type)
    risk = "LOW" if public_download else "HIGH" if score >= 6 else "MEDIUM"
    return {
        "url": url,
        "method": method,
        "test": test_name,
        "risk": risk,
        "file_leak": True,
        "public_download_intel": public_download,
        "file_score": score,
        "file_reasons": reasons,
        "content_type": content_type[:120],
        "content_disposition": content_disp[:200],
        "file_magic": magic,
        "body_size": len(raw),
        "raw": raw[:160].hex(),
    }

def file_query_suffixes(path):
    suffixes = ["", "?page=1&count=10", "?page=1&size=10"]
    if args.disable_file_hunter:
        return suffixes
    if not is_file_endpoint(path):
        return suffixes
    probes = []
    for name in FILE_PARAM_NAMES:
        for value in FILE_SEED_VALUES:
            probes.append(f"?{name}={value}")
            if len(probes) >= args.file_max_probes:
                return suffixes + probes
    return suffixes + probes

def empty_param_profile():
    return {"names": set(), "seeds": set(), "file_seeds": set(), "api_params": {}, "api_param_sources": {}}

def normalize_param_name(name):
    name = (name or "").strip().strip("[]")
    if "." in name:
        name = name.split(".")[-1]
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]{1,40}$", name):
        return ""
    return name

def add_param_name(profile, name, api_path=None, source="query"):
    name = normalize_param_name(name)
    if not name:
        return
    profile["names"].add(name)
    if api_path:
        api_path = api_path.split("?")[0].split("#")[0].rstrip("/")
        if api_path:
            profile["api_params"].setdefault(api_path, set()).add(name)
            source = source if source in ("query", "json", "form") else "query"
            profile.setdefault("api_param_sources", {}).setdefault(api_path, {}).setdefault(source, set()).add(name)

def add_seed(profile, value, file_hint=False):
    value = str(value or "").strip().strip('"\'')
    if not value or len(value) > 120:
        return
    if value.lower() in ("null", "true", "false", "undefined"):
        return
    if not file_hint and (value.startswith("/") or "://" in value):
        return
    if file_hint or re.search(r"\.(?:pdf|doc|docx|xls|xlsx|csv|zip|rar|7z|jpg|jpeg|png|gif|txt)$", value, re.I):
        profile["file_seeds"].add(value)
    elif re.match(r"^[a-zA-Z0-9_\-./:@]{1,120}$", value):
        profile["seeds"].add(value)

def merge_param_profiles(dst, src):
    dst["names"].update(src.get("names", set()))
    dst["seeds"].update(src.get("seeds", set()))
    dst["file_seeds"].update(src.get("file_seeds", set()))
    for path, names in src.get("api_params", {}).items():
        dst["api_params"].setdefault(path, set()).update(names)
    for path, sources in src.get("api_param_sources", {}).items():
        dst_sources = dst.setdefault("api_param_sources", {}).setdefault(path, {})
        for source, names in sources.items():
            dst_sources.setdefault(source, set()).update(names)
    for api in src.get("_apis_from_params", set()):
        dst.setdefault("_apis_from_params", set()).add(api)
    return dst

def extract_param_profile(content):
    profile = empty_param_profile()
    if not content or args.disable_param_harvest:
        return profile
    sample = content[:1_500_000]
    # 从URL-body配对中提取的路径也加入API集合
    for url_path, body_text in _extract_url_body_pairs(sample):
        if url_path and url_path.startswith("/"):
            profile.setdefault("_apis_from_params", set()).add(url_path)
    for m in QUERY_PARAM_RE.finditer(sample):
        add_param_name(profile, m.group(1))
    for m in FORM_FIELD_RE.finditer(sample):
        add_param_name(profile, m.group(1))
    for m in FILE_SEED_RE.finditer(sample):
        add_seed(profile, m.group(1), file_hint=True)
    for m in NUMERIC_ID_RE.finditer(sample):
        add_seed(profile, m.group(1))
    # URL+body 配对提取: 将参数绑定到具体URL
    for url_path, body_text, source in _extract_url_body_sources(sample):
        if url_path and body_text:
            for key, value in OBJECT_PARAM_RE.findall(body_text):
                add_param_name(profile, key, api_path=url_path, source=source)
                add_seed(profile, value)
    # 全局 body 提取 (无URL上下文)
    for m in REQUEST_BODY_RE.finditer(sample):
        for key, value in OBJECT_PARAM_RE.findall(m.group(1)):
            add_param_name(profile, key)
            add_seed(profile, value)
    # 从表达式提取字面种子值: pageNum: p.pageNum||1 → "1", pageSize: 20 → "20"
    for m in re.finditer(r'''(?:[|?&]|\|\||&&|,\s*)\s*(\d{1,6})\s*(?:[,\s\)\}\]])''', sample):
        add_seed(profile, m.group(1))
    for m in re.finditer(r'''["']([a-zA-Z0-9_\-]{1,40})["']\s*[:=]\s*(\d{1,6})''', sample):
        add_seed(profile, m.group(2))
    for m in OBJECT_PARAM_RE.finditer(sample):
        key, value = m.group(1), m.group(2)
        if key in COMMON_PARAM_HINTS or key.endswith(("Id", "ID", "Name", "Path", "Key")):
            add_param_name(profile, key)
            add_seed(profile, value)
    for api in extract_apis(sample):
        for q in QUERY_PARAM_RE.finditer(api):
            add_param_name(profile, q.group(1), api)
    return profile

def path_param_candidates(path):
    clean = path.split("?")[0].rstrip("/")
    candidates = [clean, "/" + clean.strip("/")]
    parts = clean.strip("/").split("/")
    for i in range(1, len(parts)):
        candidates.append("/" + "/".join(parts[i:]))
    return list(dict.fromkeys(c for c in candidates if c and c != "/"))

def bound_param_names(profile, path):
    names = []
    for candidate in path_param_candidates(path):
        bound = profile.get("api_params", {}).get(candidate, set())
        for name in sorted(bound):
            if name not in names:
                names.append(name)
    return names

def bound_param_names_by_source(profile, path, source):
    names = []
    for candidate in path_param_candidates(path):
        sources = profile.get("api_param_sources", {}).get(candidate, {})
        for name in sorted(sources.get(source, set())):
            if name not in names:
                names.append(name)
    return names

def prioritized_param_names(profile, path):
    names = bound_param_names(profile, path)
    clean = path.split("?")[0].rstrip("/")
    p = clean.lower()
    harvested = sorted(profile.get("names", set()))
    hinted = [n for n in harvested if n in COMMON_PARAM_HINTS or n.endswith(("Id", "ID", "Name", "Path", "Key", "Code"))]
    for name in hinted + [n for n in harvested if n not in hinted]:
        if name not in names:
            names.append(name)
    if is_file_endpoint(clean):
        for name in FILE_PARAM_NAMES:
            if name not in names:
                names.append(name)
    if any(x in p for x in ("list", "query", "search", "page")):
        for name in ("pageNum", "pageNo", "page", "current", "pageSize", "size", "limit", "keyword", "name"):
            if name not in names:
                names.append(name)
    return names[:40]

def should_param_probe(path, profile):
    if args.disable_param_harvest or not profile:
        return False
    clean = path.split("?")[0].rstrip("/")
    if args.disable_file_hunter and is_file_endpoint(clean):
        return False
    if args.param_probe_mode == "broad":
        return True
    p = clean.lower()
    if is_file_endpoint(clean) or any(k in p for k in PARAM_PROBE_KEYWORDS):
        return True
    for candidate in path_param_candidates(clean):
        if profile.get("api_params", {}).get(candidate):
            return True
    return False

def param_seed_value(name, seeds):
    lname = name.lower()
    if lname in ("pagenum", "pageno", "page", "current"):
        return "1"
    if lname in ("pagesize", "size", "limit", "count"):
        return "10"
    if lname in ("keyword", "keywords", "query", "search", "name", "username"):
        return "test"
    if lname in ("format",):
        return "xlsx"
    if lname in ("filetype", "doctype", "documenttype"):
        return "pdf"
    if lname in ("status",):
        return "1"
    if lname in ("type", "devicetype"):
        return "camera"
    if lname in ("protocol", "stream"):
        return "rtsp"
    if lname.endswith(("id", "ids")) or lname in ("id", "deptid", "orgid", "userid", "deviceid", "channelid", "fileid"):
        return "1"
    for seed in seeds:
        if seed and not seed.startswith("/") and "://" not in seed:
            return seed
    return "1"

def param_seed_pool(profile, path):
    seeds = ["1", "2", "10", "100", "test"]
    dynamic = [s for s in sorted(profile.get("seeds", set())) if not s.startswith("/") and "://" not in s][:20]
    file_dynamic = sorted(profile.get("file_seeds", set()))[:20]
    if is_file_endpoint(path):
        return list(dict.fromkeys(file_dynamic + FILE_SEED_VALUES + dynamic + seeds))
    return list(dict.fromkeys(dynamic + seeds))

def build_param_payload(names, seeds, max_names=6):
    payload = {}
    for name in names[:max_names]:
        payload[name] = param_seed_value(name, seeds)
    return payload

def param_query_suffixes(path, profile):
    if not should_param_probe(path, profile):
        return []
    names = prioritized_param_names(profile, path)
    if not names:
        return []
    seeds = param_seed_pool(profile, path)
    probes = []
    # 组合fuzz只使用URL绑定参数, 避免全局参数池污染真实前端流量形态。
    bound_names = bound_param_names(profile, path)
    if bound_names and len(bound_names) >= 2:
        combo_parts = []
        for bn in bound_names[:5]:
            sv = param_seed_value(bn, seeds)
            combo_parts.append(f"{bn}={sv}")
        if combo_parts:
            probes.append("?" + "&".join(combo_parts))
    for name in names:
        for value in seeds:
            probes.append(f"?{name}={value}")
            if len(probes) >= args.param_max_probes:
                return probes
    return probes

def query_suffixes(path, profile=None, allow_param_probe=True):
    suffixes = file_query_suffixes(path)
    if allow_param_probe:
        for qs in param_query_suffixes(path, profile or {}):
            if qs not in suffixes:
                suffixes.append(qs)
    return suffixes

def body_param_payloads(path, profile, body_type, allow_param_probe=True):
    if not allow_param_probe or not should_param_probe(path, profile or {}):
        return []
    profile = profile or {}
    seeds = param_seed_pool(profile, path)
    names = bound_param_names_by_source(profile, path, body_type)
    if not names and body_type == "form":
        names = bound_param_names_by_source(profile, path, "json")
    if not names and body_type == "json":
        names = bound_param_names_by_source(profile, path, "form")
    if not names:
        return []
    payloads = []
    combo = build_param_payload(names, seeds)
    if combo:
        payloads.append(combo)
    for name in names:
        payloads.append({name: param_seed_value(name, seeds)})
        if len(payloads) >= max(2, min(args.param_max_probes, 8)):
            break
    return payloads

def request_variants(path, method, content_type, body_func, param_profile=None, allow_param_probe=True):
    if method in ("POST", "PUT", "PATCH") and body_func:
        body_type = "form" if content_type == "application/x-www-form-urlencoded" else "json"
        variants = [("", {"page": "1", "size": "10"})]
        for payload in body_param_payloads(path, param_profile or {}, body_type, allow_param_probe):
            item = ("", payload)
            if item not in variants:
                variants.append(item)
        return variants
    return [(qs, None) for qs in query_suffixes(path, param_profile, allow_param_probe=allow_param_probe)]

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

def origin_from_url(raw_url):
    p = urlparse(raw_url)
    origin = f"{p.scheme}://{p.hostname}"
    if p.port and p.port not in (80,443): origin += f":{p.port}"
    return origin

def path_prefixes_from_url(raw_url):
    """Infer deployment prefixes such as /abcabc from target/final URLs."""
    path = urlparse(raw_url).path or ""
    if not path or path == "/": return set()
    path = path.rstrip("/")
    if not path: return set()
    parts = [p for p in path.strip("/").split("/") if p]
    if parts and "." in parts[-1]:
        parts = parts[:-1]
    return {'/' + '/'.join(parts[:i]) for i in range(1, len(parts)+1)}

def expand_with_prefixes(apis, prefixes):
    expanded = set(apis)
    clean_prefixes = {p.rstrip("/") for p in prefixes if p and p != "/"}
    for api in list(apis):
        if not api.startswith("/"): continue
        for prefix in clean_prefixes:
            if api == prefix or api.startswith(prefix + "/"):
                if api.startswith(prefix + "/"):
                    stripped = api[len(prefix):]
                    if stripped: expanded.add(stripped)
                continue
            expanded.add(prefix + api)
    return expanded

def normalize_api_prefixes(path):
    if path.startswith("//"):
        path = urlparse("http:" + path).path
    elif path.startswith(("http://", "https://")):
        path = urlparse(path).path
    path = path.split("?")[0].split("#")[0].rstrip("/")
    if not path.startswith("/") or path == "/": return set()
    parts = [p for p in path.strip("/").split("/") if p]
    if not parts: return set()
    prefixes = {"/" + "/".join(parts)}
    if len(parts) > 1:
        prefixes.add("/" + "/".join(parts[:-1]))
    for idx, part in enumerate(parts):
        lowered = part.lower()
        if idx > 0 and (lowered == "api" or lowered.endswith("-api") or lowered in ("gateway", "openapi", "rest")):
            prefixes.add("/" + "/".join(parts[:idx]))
    return prefixes

def extract_prefixes_from_content(content):
    prefixes = set()
    for m in API_PREFIX_RE.finditer(content):
        prefixes.update(normalize_api_prefixes(m.group(1).strip()))
    for m in PUBLIC_PATH_RE.finditer(content):
        path = m.group(1).strip()
        lowered = path.lower()
        if any(marker in lowered for marker in ("/api", "api-", "-api", "gateway", "openapi")):
            prefixes.update(normalize_api_prefixes(path))
    return prefixes

def extract_swagger_apis(doc_text):
    apis = set()
    try:
        doc = json.loads(doc_text)
    except Exception:
        return apis
    if not isinstance(doc, dict):
        return apis
    paths = doc.get("paths")
    if isinstance(paths, dict):
        for path in paths.keys():
            if isinstance(path, str) and path.startswith("/") and len(path) < 250:
                apis.add(re.sub(r"\{[^}/]+\}", "1", path))
    for key in ("basePath", "servers"):
        value = doc.get(key)
        if isinstance(value, str):
            prefix = normalize_api_prefixes(value)
            for p in prefix:
                for api in list(apis):
                    if not api.startswith(p + "/"):
                        apis.add(p + api)
        elif isinstance(value, list):
            for item in value:
                url = item.get("url") if isinstance(item, dict) else item
                if isinstance(url, str):
                    for p in normalize_api_prefixes(url):
                        for api in list(apis):
                            if not api.startswith(p + "/"):
                                apis.add(p + api)
    return apis

def api_priority(path):
    p = path.lower()
    score = 0
    weighted = [
        (120, ["media_server","gb28181","rtsp","streamurl","playurl","wvp"]),
        (100, ["camera","video","stream","media","play","live","channel","device"]),
        (95, ["phone","mobile","idcard","identity","realname","citizen","resident"]),
        (85, ["user","person","people","email","address"]),
        (75, ["config","system","admin","role","permission","auth","token","password","secret"]),
        (50, ["file","upload","download","export","import","backup"]),
        (40, ["alarm","alert","record","log","history","trace"]),
        (35, ["swagger","api-docs","druid","actuator","openapi"]),
        (25, ["list","query","search","page","all"]),
    ]
    for weight, words in weighted:
        if any(w in p for w in words):
            score += weight
    if p.startswith(("/api/", "/prod-api/", "/dev-api/", "/gateway/")):
        score += 15
    if re.search(r"/(?:get|list|query|search|page|all)(?:/|$)", p):
        score += 10
    if "delete" in p or "remove" in p:
        score -= 30
    return (-score, len(path), path)

def collect_swagger_apis(base):
    apis = set()
    for doc_path in SWAGGER_DOC_PATHS:
        s, _, doc, _ = http_get(urljoin(base, doc_path), max_size=1_000_000, retries=0)
        if s == 200 and doc:
            apis.update(extract_swagger_apis(doc))
    return apis

# ===== 响应检测 =====
def risk_level(fi):
    url = fi.get('url','').lower()
    # API文档是攻击路径情报 — 不算直接分但价值高
    attack_path = any(kw in url for kw in ['swagger','api-docs','druid','/v2/api','/v3/api','openapi','/actuator'])
    if attack_path:
        fi['attack_path_intel'] = True
    if fi.get('file_leak'):
        score = int(fi.get('file_score') or 0)
        return 'CRITICAL' if score >= 8 else 'HIGH' if score >= 6 else 'MEDIUM'
    score = 0
    if fi.get('credential_leak'): score += 3
    if fi.get('data_count', 0) > 10: score += 2
    if fi.get('data_keys'):
        keys_str = ' '.join(fi['data_keys']).lower()
        if any(k in keys_str for k in ['secret','password','token','key']): score += 3
        if any(k in keys_str for k in ['phone','email','address','idcard','身份证']): score += 3
        if any(k in keys_str for k in ['camera','cameraid','deviceid','stream','streamurl','rtsp','playurl','channel','gb28181']):
            score += 3
        if any(k in keys_str for k in ['plate','plateno','latitude','longitude','lng','lat','gps']):
            score += 2
    if score >= 5: return 'CRITICAL'
    if score >= 3: return 'HIGH'
    if score >= 1 or attack_path: return 'MEDIUM'
    return 'LOW'

def check_response(body, url, method, test_name, status_code=None):
    if len(body) < 20: return None
    url_lower = url.lower()
    attack_path = any(kw in url_lower for kw in ['swagger','api-docs','druid','/v2/api','/v3/api','openapi','/actuator'])
    attack_path_ok = attack_path and (status_code is None or 200 <= int(status_code) < 300)
    parsed = None
    try: parsed = json.loads(body)
    except: pass
    if parsed and isinstance(parsed, dict):
        code_val = next((parsed[k] for k in ("code","statusCode","status") if k in parsed and parsed[k] is not None), "")
        code = str(code_val)
        msg = str(parsed.get("msg","") or parsed.get("message",""))
        if code in ("10031","401","403","500002","40001"): return None
        if any(p in msg for p in AUTH_FAIL_MSGS): return None
        d = parsed.get("data")
        has_data = (isinstance(d, list) and len(d)>0) or (isinstance(d, dict) and d and set(d.keys())-{"path","time","timestamp","error","status"}) or bool(parsed.get("records")) or bool(parsed.get("list")) or bool(parsed.get("items"))
        if has_data or code in ("0","200","20000") or attack_path_ok:
            f = {"url":url,"method":method,"test":test_name,"code":code,"msg":msg[:200]}
            if isinstance(d, list):
                f["data_count"]=len(d)
                if d and isinstance(d[0], dict): f["data_keys"] = list(d[0].keys())[:15]
            elif isinstance(d, dict): f["data_keys"]=list(d.keys())[:15]
            if "secret" in body.lower() or "password" in body.lower(): f["credential_leak"]=True
            f["risk"] = risk_level(f)
            f["raw"] = body[:500]
            return f
    elif parsed and isinstance(parsed, list) and len(parsed)>0:
        f = {"url":url,"method":method,"test":test_name,"data_count":len(parsed),"risk":"MEDIUM","raw":body[:500]}
        if isinstance(parsed[0], dict): f["data_keys"] = list(parsed[0].keys())[:15]; f["risk"] = risk_level(f)
        return f
    elif attack_path_ok:
        f = {"url":url,"method":method,"test":test_name,"attack_path_intel":True,"risk":"MEDIUM","raw":body[:500]}
        return f
    return None

# ===== API 测试（双模式） =====
def test_api(base_url, path, bypass_tests, short_circuit=True, param_profile=None, allow_param_probe=True):
    clean = path.split("?")[0].rstrip("/")
    if not clean: return []
    url_base = urljoin(base_url, clean)
    findings = []
    for name, method, ct, bf, headers in bypass_tests:
        for qs, payload in request_variants(clean, method, ct, bf, param_profile, allow_param_probe=allow_param_probe):
            url = url_base + qs
            try:
                data = None
                if method in ("POST","PUT","PATCH") and bf:
                    data = bf(payload or {"page":"1","size":"10"})
                h = {"User-Agent":"Mozilla/5.0","Accept":"application/json"}
                h.update(headers)
                if data and ct: h["Content-Type"] = ct
                req = Request(url, data=data, headers=h, method=method)
                resp = urlopen(req, timeout=API_TIMEOUT, context=ssl_ctx)
                raw = read_limited(resp)
                if not args.disable_file_hunter:
                    ff = check_file_response(raw, resp.headers, url, method, name, resp.getcode())
                    if ff:
                        findings.append(ff)
                        if short_circuit: return findings
                body = raw.decode('utf-8', errors='replace')
                f = check_response(body, url, method, name, resp.getcode())
                if f:
                    findings.append(f)
                    if short_circuit: return findings
            except HTTPError as e:
                if e.code not in (404,403,405):
                    try:
                        raw = e.read()
                        if not args.disable_file_hunter:
                            ff = check_file_response(raw, e.headers, url, method, name, e.code)
                            if ff:
                                findings.append(ff)
                                if short_circuit: return findings
                        b = raw.decode('utf-8', errors='replace')
                        f = check_response(b, url, method, name, e.code)
                        if f:
                            findings.append(f)
                            if short_circuit: return findings
                    except: pass
            except Exception as e:
                log.debug(f"API {url} {method} failed: {e}")
    return findings

def normalized_endpoint(url):
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}{p.path.rstrip('/')}"

def file_entity_key(fi):
    return "|".join([
        normalized_endpoint(fi.get("url", "")),
        str(fi.get("content_disposition", "")),
        str(fi.get("file_magic", "")),
        str(fi.get("body_size", "")),
    ])

def normalize_finding(fi):
    if fi.get("file_leak") and "public_download_intel" not in fi:
        public_download = looks_like_public_download(
            fi.get("url", ""),
            fi.get("content_disposition", ""),
            fi.get("file_magic", ""),
            fi.get("content_type", ""),
        )
        fi["public_download_intel"] = public_download
        if public_download:
            fi["risk"] = "LOW"
    return fi

def finding_key(fi):
    fi = normalize_finding(fi)
    if fi.get("file_leak"):
        return "FILE|" + file_entity_key(fi)
    return fi.get("url", "") + fi.get("test", "")

def merge_findings(existing, new_items):
    seen = {finding_key(fi) for fi in existing}
    for fi in new_items or []:
        fi = normalize_finding(fi)
        key = finding_key(fi)
        if key and key not in seen:
            seen.add(key)
            existing.append(fi)
    return existing

def useful_findings(findings):
    return [f for f in findings if f.get("data_count") or f.get("data_keys") or f.get("credential_leak") or f.get("attack_path_intel") or f.get("file_leak")]

def high_value_finding(fi):
    if fi.get("public_download_intel"):
        return False
    if fi.get("credential_leak"):
        return True
    keys = " ".join(fi.get("data_keys", [])).lower()
    url = fi.get("url", "").lower()
    text = keys + " " + url
    return any(k in text for k in [
        "phone","mobile","idcard","身份证","email","address",
        "camera","stream","rtsp","gb28181","deviceid","playurl",
        "password","secret","token","apikey","accesskey","config",
    ])

def report_stats(vulnerable):
    all_findings = [fi for v in vulnerable for fi in v.get("findings", [])]
    unique_endpoint_keys = {normalized_endpoint(fi.get("url", "")) for fi in all_findings}
    data_findings = [fi for fi in all_findings if fi.get("data_count") or fi.get("data_keys")]
    file_findings = [fi for fi in all_findings if fi.get("file_leak")]
    public_downloads = [fi for fi in file_findings if fi.get("public_download_intel")]
    return {
        "raw_findings": len(all_findings),
        "unique_endpoints": len(unique_endpoint_keys),
        "data_findings": len(data_findings),
        "unique_data_endpoints": len({normalized_endpoint(fi.get("url", "")) for fi in data_findings}),
        "file_leaks": len(file_findings),
        "public_download_intel": len(public_downloads),
        "high_value_findings": sum(1 for fi in all_findings if high_value_finding(fi)),
    }

def target_filename(base):
    return re.sub(r'[^a-zA-Z0-9]', '_', base) + ".json"

def write_target_result(t):
    findings = t.get("findings", [])
    if not findings:
        return
    t["finding_count"] = len(findings)
    out = {k: v for k, v in t.items() if k not in ("_f", "_f3a_real", "_deep", "_seen_tasks")}
    with open(os.path.join(OUTDIR, target_filename(t["base"])), "w") as f:
        json.dump(out, f, ensure_ascii=False, indent=2, default=str)

def load_checkpoint_results():
    items = []
    for name in os.listdir(OUTDIR):
        if not name.endswith(".json") or name in ("report.json", "apis.json"):
            continue
        path = os.path.join(OUTDIR, name)
        try:
            with open(path) as f:
                item = json.load(f)
            if item.get("base") and item.get("findings"):
                item["finding_count"] = len(item.get("findings", []))
                items.append(item)
        except Exception as e:
            log.debug(f"Load checkpoint {path} failed: {e}")
    return items

def baseline_api_result(url):
    base = origin_from_url(url)
    page_url = url if url.endswith("/") else url + "/"
    prefixes = path_prefixes_from_url(page_url)
    apis = expand_with_prefixes(set(BASELINE_PATHS), prefixes)
    return {"base":base,"title":"","apis":sorted(apis, key=api_priority),"sensitive":[],"js_count":0,"param_profile":empty_param_profile(),"fallback":"phase2_timeout"}

def add_task(tasks, seen, t, api, layer):
    key = (t["base"], api, layer)
    if key in seen:
        return
    seen.add(key)
    tasks.append((t, api, layer))

def run_task_pool(tasks, worker_count, timeout, label, fn, on_result, progress_every=500):
    if not tasks:
        return 0, 0
    pool = ThreadPoolExecutor(max_workers=worker_count)
    completed = 0
    pending = set()
    started = time.time()
    try:
        futures = {pool.submit(fn, task): task for task in tasks}
        pending = set(futures)
        while pending:
            remaining = max(0, timeout - (time.time() - started)) if timeout else None
            if timeout and remaining <= 0:
                break
            wait_time = 5 if remaining is None else min(5, remaining)
            done_set, pending = wait(pending, timeout=wait_time)
            if not done_set:
                continue
            for f in done_set:
                completed += 1
                try:
                    on_result(f.result())
                except Exception as e:
                    log.debug(f"{label} failed: {e}")
                if progress_every and completed % progress_every == 0:
                    print(f"    [{completed}/{len(tasks)}] {label}")
        if pending:
            print(f"  {label} soft-timeout: {len(pending)} unfinished tasks skipped")
            for f in pending:
                f.cancel()
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return completed, len(pending)

# ===== 主流程 =====
def main():
    print("="*60)
    print(f"v13: URL参数绑定+POST body/form增强 | {'全量绕过' if args.full_bypass else '命中断路'} | 风险分级 | Markdown报告")
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
        normalized, host, port = target_url_with_scheme(t_url)
        if normalized and host and port:
            if tcp_check(host, port):
                return normalized
        elif host:
            for port in WEB_PORTS:
                if tcp_check(host, port):
                    s = "https" if port in HTTPS_PORTS else "http"
                    return f"{s}://{host}" if port in (80,443) else f"{s}://{host}:{port}"
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
    print(f"  绕过: {'FULL(6种)' if args.full_bypass else 'FAST(2种,短路)'} | dry-run={args.dry_run} | file-hunter={not args.disable_file_hunter} | file-baseline={args.enable_file_baseline and not args.disable_file_hunter} | param-harvest={not args.disable_param_harvest}")

    api_results, done = [], 0
    def crawl(url):
        base = origin_from_url(url)
        page_url = url if url.endswith("/") else url + "/"
        path_prefixes = path_prefixes_from_url(page_url)
        param_profile = empty_param_profile()
        status, final_url, html, ct = http_get(page_url, retries=0)
        swagger_apis = collect_swagger_apis(base)
        if not status or not html or len(html) < 50:
            apis = set(BASELINE_PATHS) | swagger_apis
            apis = expand_with_prefixes(apis, path_prefixes)
            return {"base":base,"title":"","apis":sorted(apis, key=api_priority),"sensitive":[],"js_count":0,"param_profile":param_profile}
        merge_param_profiles(param_profile, extract_param_profile(html))
        title = ""
        m = re.search(r'<title[^>]*>([^<]+)</title>', html, re.I)
        if m: title = m.group(1)[:200]
        if final_url:
            page_url = final_url
            base = origin_from_url(final_url)
            path_prefixes.update(path_prefixes_from_url(final_url))
        js_urls = extract_js_from_html(html, page_url)
        links = extract_links_from_html(html, page_url)
        inline_scripts = re.findall(r'<script[^>]*>([\s\S]*?)</script>', html, re.I)
        all_apis = set()
        for s in inline_scripts:
            if s.strip():
                all_apis.update(extract_apis(s))
                path_prefixes.update(extract_prefixes_from_content(s))
                merge_param_profiles(param_profile, extract_param_profile(s))
        if VUE_INSTANCE_RE.search(html):
            for m in VUE_ROUTER_RE.finditer(html): all_apis.add(m.group(1))
        for m in REACT_ROUTE_RE.finditer(html): all_apis.add(m.group(1))
        app_js = [j for j in js_urls if not COMMON_LIBS.search(j)]
        for js_url in list(app_js)[:30]:
            s, _, content, _ = http_get(js_url, max_size=500_000, retries=0)
            if s != 200 or not content: continue
            all_apis.update(extract_apis(content))
            path_prefixes.update(extract_prefixes_from_content(content))
            merge_param_profiles(param_profile, extract_param_profile(content))
            for m in SENSITIVE_FIELD_RE.finditer(content): all_apis.add(f"SENSITIVE:{m.group(1)[:100]}")
            for m in INTERNAL_IP_RE.finditer(content): all_apis.add(f"INTERNAL_IP:{m.group(0)}")
            for m in JDBC_RE.finditer(content): all_apis.add(f"JDBC:{m.group(0)}")
        crawled = set()
        for link in list(links)[:5]:
            if link in crawled: continue
            crawled.add(link)
            s, _, page, _ = http_get(link, retries=0)
            if s != 200 or not page or len(page) < 100: continue
            sub_js = extract_js_from_html(page, link)
            for js in sub_js:
                if not COMMON_LIBS.search(js): js_urls.add(js)
            for s in re.findall(r'<script[^>]*>([\s\S]*?)</script>', page, re.I):
                if s.strip():
                    all_apis.update(extract_apis(s))
                    path_prefixes.update(extract_prefixes_from_content(s))
                    merge_param_profiles(param_profile, extract_param_profile(s))
        # 将参数画像提取到的URL补充进API集合
        for extra_api in param_profile.get("_apis_from_params", set()):
            if extra_api.startswith("/"):
                all_apis.add(extra_api)
        all_apis.update(swagger_apis)
        all_apis = expand_paths(base, all_apis)
        all_apis.update(BASELINE_PATHS)
        all_apis = expand_with_prefixes(all_apis, path_prefixes)
        clean = sorted((a for a in all_apis if not a.startswith(("SENSITIVE:","INTERNAL_IP:","JDBC:"))), key=api_priority)
        sensitive = [a for a in all_apis if a.startswith(("SENSITIVE:","INTERNAL_IP:","JDBC:"))]
        if not clean: return None
        return {"base":base,"title":title,"apis":clean,"sensitive":sensitive,"js_count":len(app_js),"param_profile":param_profile}

    pool = ThreadPoolExecutor(max_workers=WORKERS)
    try:
        futures = {pool.submit(crawl, u): u for u in live}
        pending = set(futures)
        phase2_start = time.time()
        while pending:
            remaining = max(0, args.phase2_timeout - (time.time() - phase2_start))
            if remaining <= 0:
                break
            done_set, pending = wait(pending, timeout=min(5, remaining))
            if not done_set:
                continue
            for f in done_set:
                done += 1
                try:
                    r = f.result()
                    if r: api_results.append(r)
                except Exception as e:
                    log.debug(f"Crawl failed: {e}")
                if done % 10 == 0 or done == len(live): print(f"  [{done}/{len(live)}] {len(api_results)} with APIs")
        if pending:
            print(f"  Phase 2 soft-timeout: {len(pending)} hosts fallback to baseline")
            for f in pending:
                url = futures[f]
                f.cancel()
                done += 1
                api_results.append(baseline_api_result(url))
            print(f"  [{done}/{len(live)}] {len(api_results)} with APIs")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    print(f"  Phase 2 DONE: {len(api_results)} hosts")

    if args.dry_run:
        print(f"\n[Dry-run] 跳过测试, 输出API列表")
        with open(os.path.join(OUTDIR, "apis.json"), "w") as f:
            json.dump([{
                "base": t["base"],
                "title": t["title"],
                "apis": t["apis"][:50],
                "param_names": sorted(t.get("param_profile", {}).get("names", set()))[:80],
                "seed_values": sorted(t.get("param_profile", {}).get("seeds", set()))[:40],
                "file_seed_values": sorted(t.get("param_profile", {}).get("file_seeds", set()))[:40],
            } for t in api_results], f, ensure_ascii=False, indent=2)
        print(f"  API列表: {OUTDIR}/apis.json")
        return

    # Phase 3: 两阶段测试
    print(f"\n[Phase 3] 未授权测试 ({'全量绕过' if args.full_bypass else '命中断路'})...")
    flat_tasks, target_map = [], {}
    for t in api_results:
        target_map[t["base"]] = t; t["_f"] = []
        seen_apis = set()
        for api in list(t["apis"][:30]) + BASELINE_PATHS:
            if api in seen_apis:
                continue
            seen_apis.add(api)
            flat_tasks.append((t, api))
    print(f"  3a/fast: {len(flat_tasks)} tasks on {len(target_map)} hosts")
    t_start = time.time()
    pool = ThreadPoolExecutor(max_workers=WORKERS*2)
    try:
        def test_flat(task):
            t, api = task
            return t["base"], test_api(t["base"], api, FAST_BYPASS, short_circuit=True, param_profile=t.get("param_profile"), allow_param_probe=False)
        futures = {pool.submit(test_flat, ft): ft for ft in flat_tasks}
        pending = set(futures)
        completed = 0
        while pending:
            remaining = max(0, args.phase3a_timeout - (time.time() - t_start))
            if remaining <= 0:
                break
            done_set, pending = wait(pending, timeout=min(5, remaining))
            if not done_set:
                continue
            for f in done_set:
                completed += 1
                try:
                    base_url, findings = f.result()
                    if findings: target_map[base_url]["_f"].extend(findings)
                except Exception as e:
                    log.debug(f"Test failed: {e}")
                if completed % 500 == 0:
                    print(f"    [{completed}/{len(flat_tasks)}] 3a/fast")
        if pending:
            print(f"  3a/fast soft-timeout: {len(pending)} unfinished tasks skipped")
            for f in pending:
                f.cancel()
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    print(f"  3a/fast 耗时: {time.time()-t_start:.0f}s")

    candidates = []
    for base, t in target_map.items():
        real = useful_findings(t["_f"])
        t.pop("_f", None)
        if real:
            t["_f3a_real"] = real
            t["findings"] = merge_findings(t.get("findings", []), real)
            write_target_result(t)
            candidates.append(t)
    if args.full_bypass:
        candidate_bases = {t["base"] for t in candidates}
        rescue_tasks = []
        for t in api_results:
            if t["base"] in candidate_bases:
                continue
            for api in BASELINE_PATHS:
                rescue_tasks.append((t, api))
        if rescue_tasks:
            print(f"  3a/rescue-baseline: {len(rescue_tasks)} FULL tasks for {len(api_results)-len(candidate_bases)} non-candidates")
            t_start = time.time()
            def test_rescue(task):
                t, api = task
                return t["base"], test_api(t["base"], api, FULL_BYPASS, short_circuit=True, param_profile=t.get("param_profile"), allow_param_probe=False)
            def handle_rescue(result):
                base_url, findings = result
                real = useful_findings(findings)
                if real and base_url not in candidate_bases:
                    t = target_map[base_url]
                    t["_f3a_real"] = real
                    t["findings"] = merge_findings(t.get("findings", []), real)
                    write_target_result(t)
                    candidates.append(t)
                    candidate_bases.add(base_url)
            run_task_pool(rescue_tasks, WORKERS, args.rescue_timeout, "3a/rescue-baseline", test_rescue, handle_rescue)
            print(f"  3a/rescue-baseline 耗时: {time.time()-t_start:.0f}s")
    print(f"  3a: {len(candidates)} candidates")

    vulnerable = []
    if candidates:
        cand_map = {}
        for t in candidates:
            cand_map[t["base"]] = t

        layers = [
            ("baseline", lambda t: BASELINE_PATHS),
            ("business", lambda t: [api for api in t["apis"][:80] if not is_file_endpoint(api)]),
            ("file", lambda t: [api for api in t["apis"][:80] if is_file_endpoint(api)] if not args.disable_file_hunter else []),
        ]
        print("  3b: 分层 deep test (baseline -> business -> file)")
        for layer_name, api_provider in layers:
            layer_tasks, seen_tasks = [], set()
            for t in candidates:
                for api in api_provider(t):
                    add_task(layer_tasks, seen_tasks, t, api, layer_name)
            if not layer_tasks:
                continue
            print(f"  3b/{layer_name}: {len(layer_tasks)} tasks")
            t_start = time.time()
            def test_deep_flat(task):
                t, api, layer = task
                return t["base"], test_api(t["base"], api, bypass_used, short_circuit=not args.full_bypass, param_profile=t.get("param_profile"))
            def handle_deep(result):
                base_url, findings = result
                if findings:
                    t = cand_map[base_url]
                    merge_findings(t.setdefault("findings", []), useful_findings(findings))
                    write_target_result(t)
            run_task_pool(layer_tasks, WORKERS, args.phase3b_layer_timeout, f"3b/{layer_name}", test_deep_flat, handle_deep)
            print(f"  3b/{layer_name} 耗时: {time.time()-t_start:.0f}s")

        for t in candidates:
            all_f = t.get("findings", [])
            if all_f:
                unique = merge_findings([], all_f)
                t["findings"] = unique; t["finding_count"] = len(unique)
                write_target_result(t)
                vulnerable.append(t)
                print(f"\n  [!] {t['base']} | {t['title'][:50]}")
                for fi in unique[:4]:
                    risk = fi.get('risk','?')
                    print(f"      [{risk}] {fi.get('method','')} {compact_url(fi.get('url',''))}")
                    for k in ["data_count","data_keys","credential_leak","file_leak","file_score","file_magic","content_type","content_disposition","body_size"]:
                        if k in fi: print(f"        {k}: {str(fi[k])[:100]}")
    print(f"\n  Phase 3 DONE: {len(vulnerable)} vulnerable")

    # Phase 4: 报告 (JSON + Markdown)
    print(f"\n[Phase 4] 报告生成")
    by_base = {}
    if args.resume:
        by_base.update({v["base"]: v for v in load_checkpoint_results()})
    for v in vulnerable:
        by_base[v["base"]] = v
    vulnerable = sorted(by_base.values(), key=lambda x: x.get("base", ""))
    stats = report_stats(vulnerable)
    report = {"scan_time":time.strftime("%Y-%m-%d %H:%M:%S"),"targets":len(targets),"live":len(live),
              "apis":len(api_results),"vulnerable":len(vulnerable),"stats":stats,"findings":[]}
    for v in vulnerable:
        report["findings"].append({"url":v["base"],"title":v.get("title",""),"findings":v.get("findings",[])})
    with open(os.path.join(OUTDIR,"report.json"),"w") as f:
        json.dump(report, f, ensure_ascii=False, indent=2, default=str)

    # Markdown
    file_leak_count = stats["file_leaks"]
    md = [f"# 扫描报告 v13\n\n**时间**: {report['scan_time']} | **目标**: {report['targets']} | **存活**: {report['live']} | **API**: {report['apis']} | **漏洞**: {report['vulnerable']} | **文件类发现**: {file_leak_count}\n"]
    md.append(
        "\n## 统计口径\n\n"
        f"- 原始发现: {stats['raw_findings']}\n"
        f"- 去重端点: {stats['unique_endpoints']}\n"
        f"- 数据类发现: {stats['data_findings']} / 去重数据端点: {stats['unique_data_endpoints']}\n"
        f"- 高价值发现: {stats['high_value_findings']}\n"
        f"- 文件类发现: {stats['file_leaks']} / 公开下载情报: {stats['public_download_intel']}\n"
    )
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
                if fi.get('file_leak'):
                    label = "公开下载情报" if fi.get("public_download_intel") else "文件泄露"
                    md.append(f"  - {label}: 评分 {fi.get('file_score')} | 类型: {fi.get('content_type','')[:80]} | 魔数: {fi.get('file_magic','') or '-'} | 大小: {fi.get('body_size')}")
                    if fi.get('content_disposition'): md.append(f"  - 文件名/下载头: {fi.get('content_disposition')[:160]}")
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
