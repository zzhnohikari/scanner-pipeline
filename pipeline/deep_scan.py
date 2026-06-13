#!/usr/bin/env python3
"""Deep scan phase: tests all live hosts against common API paths more aggressively."""
import urllib.request, ssl, json, re, os, sys
from concurrent.futures import ThreadPoolExecutor, as_completed

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
TIMEOUT = 6
WORKERS = 30

# Common unauthorized API paths to test on EVERY live host
TEST_PATHS = [
    "/api/user/users", "/api/user/list", "/api/user/info", "/api/user/userInfo",
    "/api/server/info", "/api/server/system/info", "/api/server/system/configInfo",
    "/api/server/media_server/list", "/api/server/resource/info",
    "/api/role/all", "/api/log/list",
    "/api/device/query/devices", "/api/common/channel/list", "/api/common/channel/one",
    "/api/userApiKey/userApiKeys",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
    "/actuator/info", "/actuator/beans", "/actuator/configprops",
    "/swagger-resources", "/swagger-ui.html", "/swagger-ui/index.html",
    "/v2/api-docs", "/v3/api-docs", "/api-docs", "/doc.html",
    "/druid/index.html", "/druid/login.html",
    "/api/admin/user", "/api/admin/config", "/api/system/info",
    "/api/nsc/user/users", "/api/platform/list",
    "/back/findParam/list", "/back/findParam/all",
    "/back/user/list", "/back/admin/info",
    "/e/port/tongji.php",
    "/api/p/toiletsList", "/api/p/parksList", "/api/p/bicyclesList",
    "/api/portal/enterprise/list",
    "/api/notary/name", "/api/notary/list",
    "/api/tags/all", "/api/articles/all", "/api/talks",
    "/prod-api/system/config", "/prod-api/user/list",
]

AUTH_FAIL = [
    "缺少请求授权令牌", "token无效", "token过期", "token失效", "未登录", "请登录",
    "请先登录", "登录已过期", "重新登录", "认证失败", "鉴权失败",
    "Unauthorized", "unauthenticated", "Authentication required",
    "Full authentication is required", "Access Denied", "Forbidden",
]

def get(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
        resp = urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx)
        return resp.getcode(), resp.read().decode('utf-8', errors='replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', errors='replace')
    except: return None, ""

def is_auth_fail(data):
    if not isinstance(data, dict): return False
    code = str(data.get("code") or data.get("statusCode") or data.get("status") or "")
    msg = str(data.get("msg") or data.get("message") or data.get("errorMessage") or "")
    if code in ("10031", "401", "403", "500002", "40001", "4010"): return True
    for p in AUTH_FAIL:
        if p in msg: return True
    return False

def has_real_data(data):
    if isinstance(data, list): return len(data) > 0
    if isinstance(data, dict):
        # Filter error pages
        if set(data.keys()) in ({"path","time"}, {"timestamp","status","error","path"}):
            return False
        if "error" in data and "path" in data and len(data) <= 5: return False
        d = data.get("data")
        if isinstance(d, list) and len(d) > 0: return True
        if isinstance(d, dict):
            if set(d.keys()) in ({"path","time"},): return False
            if d.get("list") and len(d["list"]) > 0: return True
            if d.get("records") and len(d["records"]) > 0: return True
            if d.keys() - {"path","time","timestamp","error","status"}:
                return True
        for k in ("list","records","items","content"):
            v = data.get(k)
            if v and not isinstance(v, str): return True
        if data.get("flag") is True: return True
    return False

def test_host(entry):
    host, port, scheme = entry
    base = f"{scheme}://{host}" if port in (80,443) else f"{scheme}://{host}:{port}"
    findings = []

    for path in TEST_PATHS:
        url = base + path
        code, body = get(url)
        if code != 200 or len(body) < 30: continue
        data = None
        try: data = json.loads(body)
        except: continue
        if data is None: continue
        if is_auth_fail(data): continue
        if not has_real_data(data): continue

        finding = {"url": url, "method": "GET", "status": code, "preview": body[:500]}
        # Try POST too
        findings.append(finding)

    if findings:
        return {"base": base, "host": host, "findings": findings}
    return None

def main():
    # Read live hosts from Phase 1 output
    # We need to regenerate from the target list
    # For now, just read the scanner result files
    results_dir = "/tmp/pipeline_results"
    print(f"Deep scanning...", flush=True)

    # Load the report to find live hosts
    # Since we don't have the live list, let's scan from targets
    with open("/tmp/targets_filtered.txt") as f:
        targets = [l.strip() for l in f if l.strip()]

    # Just test a sample of IPs directly
    import socket
    seen = set()
    hosts = []
    for t in targets:
        if t.startswith("http"):
            p = urllib.parse.urlparse(t)
            host, port = p.hostname, p.port or (443 if p.scheme=="https" else 80)
            key = (host, port, p.scheme)
        else:
            host = t
            # Quick check common ports
            key = None
            for port in [80, 443, 8080, 8443, 8001, 88, 81, 82, 8888, 3000]:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    if s.connect_ex((host, port)) == 0:
                        scheme = "https" if port in (443, 8443) else "http"
                        key = (host, port, scheme)
                        s.close()
                        break
                    s.close()
                except: pass
            if key is None: continue
        if key and key not in seen:
            seen.add(key)
            hosts.append(key)
            if len(hosts) >= 5000: break

    print(f"Testing {len(hosts)} hosts", flush=True)
    vulnerable = []
    done = 0

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(test_host, h): h for h in hosts[:1000]}
        for f in as_completed(futures):
            done += 1
            if done % 100 == 0: print(f"  [{done}/1000]", flush=True)
            try:
                r = f.result()
                if r:
                    vulnerable.append(r)
                    print(f"\n  [!] {r['base']}", flush=True)
                    for fi in r["findings"][:3]:
                        print(f"      {fi['url']} -> {fi['preview'][:200]}", flush=True)
            except: pass

    print(f"\nDone: {len(vulnerable)} vulnerable", flush=True)

if __name__ == "__main__":
    main()
