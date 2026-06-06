#!/usr/bin/env python3
"""
Phase 1: Fast HTTP probe using only stdlib (no external deps).
TCP connect first, then HTTP request for responsive hosts.
"""

import sys, os, re, json, time, socket, ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from urllib.request import Request, urlopen, HTTPRedirectHandler, build_opener, install_opener
from urllib.error import URLError, HTTPError
import http.client

INPUT_FILE = "/tmp/targets_filtered.txt"
OUTPUT_FILE = "/tmp/responsive_targets.json"
CONNECT_TIMEOUT = 2
HTTP_TIMEOUT = 5
MAX_WORKERS = 200
WEB_PORTS = [443, 8443, 80, 8080, 8001, 9443, 9090, 3000]

# Disable SSL verification
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
    def http_error_302(self, req, fp, code, msg, headers):
        return fp
    http_error_301 = http_error_303 = http_error_307 = http_error_302

opener = build_opener(NoRedirectHandler)

def tcp_connect(host, port):
    """Fast TCP connect check."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def http_get(url, timeout=HTTP_TIMEOUT):
    """Simple HTTP GET returning (status, headers_dict, body_text)."""
    try:
        req = Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; scanner)",
                                     "Accept": "text/html,application/json,*/*"})
        resp = opener.open(req, timeout=timeout, context=ssl_ctx)
        # Read body
        body = b""
        while True:
            try:
                chunk = resp.read(65536)
                if not chunk:
                    break
                body += chunk
                if len(body) > 500000:  # 500KB limit
                    break
            except Exception:
                break
        status = resp.getcode()
        headers = dict(resp.headers) if hasattr(resp, 'headers') else {}
        content_type = headers.get("Content-Type", headers.get("content-type", ""))
        try:
            text = body.decode('utf-8', errors='replace')
        except Exception:
            text = body.decode('latin-1', errors='replace')
        return status, content_type, text
    except HTTPError as e:
        try:
            body = e.read()
            text = body.decode('utf-8', errors='replace')[:100000]
        except Exception:
            text = ""
        return e.code, "", text
    except URLError as e:
        return None, "", ""
    except Exception:
        return None, "", ""

def check_host(target):
    """Check a single host for open web ports, then probe HTTP."""
    target = target.strip()
    if not target:
        return []

    # Parse target
    if target.startswith("http://") or target.startswith("https://"):
        p = urlparse(target)
        host = p.hostname
        if not host:
            return []
        port = p.port or (443 if p.scheme == "https" else 80)
        scheme = p.scheme
        base_path = p.path or "/"
        ports_to_check = [port]
        schemes_to_try = [scheme]
    else:
        host = target
        # Quick check: try most common ports first
        # Prefer HTTPS on 443/8443, HTTP on 80/8080
        if tcp_connect(host, 443):
            ports_to_check = [443]
            schemes_to_try = ["https"]
        elif tcp_connect(host, 8443):
            ports_to_check = [8443]
            schemes_to_try = ["https"]
        elif tcp_connect(host, 80):
            ports_to_check = [80]
            schemes_to_try = ["http"]
        elif tcp_connect(host, 8080):
            ports_to_check = [8080]
            schemes_to_try = ["http"]
        else:
            # Check remaining ports
            for port in [8001, 9443, 9090, 3000]:
                if tcp_connect(host, port):
                    ports_to_check = [port]
                    schemes_to_try = ["https", "http"]
                    break
            else:
                return []  # No open web ports
        base_path = "/"

    results = []
    for port in ports_to_check:
        for scheme in schemes_to_try:
            url = f"{scheme}://{host}:{port}{base_path}"
            status, content_type, text = http_get(url)
            if status is None:
                continue

            title = ""
            m = re.search(r'<title[^>]*>([^<]+)</title>', text, re.IGNORECASE)
            if m:
                title = m.group(1).strip()[:200]

            results.append({
                "base_url": f"{scheme}://{host}:{port}",
                "url": url,
                "status": status,
                "title": title,
                "content_type": content_type,
                "size": len(text),
            })
            break  # Got a response
        if results:
            break

    return results

def main():
    print(f"[*] Reading targets from {INPUT_FILE}")
    with open(INPUT_FILE) as f:
        targets = [l.strip() for l in f if l.strip()]

    print(f"[*] {len(targets)} targets to probe")
    print(f"[*] TCP: {CONNECT_TIMEOUT}s, HTTP: {HTTP_TIMEOUT}s, Workers: {MAX_WORKERS}")

    responsive = []
    done = 0
    start = time.time()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {}
        for t in targets:
            futures[pool.submit(check_host, t)] = t

        for f in as_completed(futures):
            done += 1
            if done % 1000 == 0:
                elapsed = time.time() - start
                rate = done / elapsed if elapsed > 0 else 0
                print(f"  [{done}/{len(targets)}] {rate:.0f}/s | {len(responsive)} responsive | {elapsed:.0f}s")

            try:
                results = f.result()
                responsive.extend(results)
            except Exception:
                pass

    elapsed = time.time() - start
    print(f"\n[*] Done in {elapsed:.0f}s ({elapsed/60:.1f} min)")
    print(f"[*] Responsive targets: {len(responsive)}")

    # Deduplicate by base_url
    seen = set()
    unique = []
    for r in responsive:
        key = r["base_url"]
        if key not in seen:
            seen.add(key)
            unique.append(r)

    print(f"[*] Unique base URLs: {len(unique)}")

    # Sort: 200 first, then others
    unique.sort(key=lambda x: (0 if x["status"] == 200 else 1 if 300 <= x["status"] < 400 else 2, x["url"]))

    with open(OUTPUT_FILE, "w") as f:
        json.dump(unique, f, ensure_ascii=False, indent=2)

    print(f"[*] Results -> {OUTPUT_FILE}")

    # Show summary
    for r in unique[:25]:
        print(f"  {r['status']:>3} | {r['title'][:50]:<50} | {r['base_url']}")

if __name__ == "__main__":
    main()
