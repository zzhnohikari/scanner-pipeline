#!/usr/bin/env python3
"""Regression for Vite module API extraction and framework error filtering."""

import json
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "pipeline" / "deep_scanner.py"


class LabServer(ThreadingHTTPServer):
    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def send_body(self, body, content_type="text/html", status=200):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, obj, status=200):
        self.send_body(json.dumps(obj, ensure_ascii=False), "application/json", status)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if path == "/admin":
            return self.send_body(
                """<!doctype html>
                <html><head><title>配电监测系统</title></head>
                <body><script type="module" src="/src/main.ts"></script></body></html>"""
            )
        if path == "/src/main.ts":
            return self.send_body(
                'import Device from "/views/device/index.vue";\n'
                'import { stats } from "/src/screen.ts";\n'
                'const loginBase = "/admin/system.Login/";\n'
                'function setting(params){return request({url: loginBase + "setting", method: "get", params});}\n'
                'function captcha(params){return request({url: loginBase + "captcha", method: "get", params});}\n',
                "application/javascript",
            )
        if path == "/src/screen.ts":
            return self.send_body(
                'const largeBase = "/large/Index/";\n'
                'export function message(){return service({url: largeBase + "message", method: "get"});}\n'
                'export function userStatistics(){return service({url: largeBase + "userStatistics", method: "get"});}\n'
                'export function inspectionStatistics(){return service({url: largeBase + "inspectionStatistics", method: "get"});}\n'
                'export function unitStatistics(){return service({url: largeBase + "unitStatistics", method: "get"});}\n',
                "application/javascript",
            )
        if path == "/views/device/index.vue":
            return self.send_json({
                "code": 0,
                "msg": "controller not exists:app\\controller\\Views",
                "data": {
                    "line": 108,
                    "file": "/www/wwwroot/tp8.hzzwhl.com/yylAdmin-master/app/common.php",
                    "trace": [{"file": "/www/wwwroot/tp8.hzzwhl.com/yylAdmin-master/app/admin/controller.php"}],
                },
            })
        if path == "/admin/system.Login/setting":
            return self.send_json({
                "code": 200,
                "msg": "操作成功",
                "data": {
                    "system_name": "配电监测系统",
                    "token_type": "header",
                    "token_name": "AdminToken",
                    "captcha_switch": 0,
                },
            })
        if path == "/large/Index/message":
            return self.send_json({
                "code": 200,
                "msg": "操作成功",
                "data": {
                    "list": {
                        "list": [{
                            "content": "电压 ua超出设置的阈值范围",
                            "unit_name": "设备1",
                            "unit_number": "FE220513B064",
                            "unit_type": "电能表",
                            "user_name": "廿三里分公司",
                        }],
                        "count": 1,
                    },
                    "count": 1,
                },
            })
        if path in {
            "/large/Index/userStatistics",
            "/large/Index/inspectionStatistics",
            "/large/Index/unitStatistics",
        }:
            return self.send_json({"code": 200, "msg": "操作成功", "data": [{"jurisdiction": "北苑", "count": 1}]})
        if path.startswith("/admin/") or path.startswith("/large/"):
            return self.send_json({"code": 401, "msg": "请登录", "data": []})
        return self.send_json({"code": 404, "msg": "not found"}, status=404)

    def do_POST(self):
        return self.do_GET()


def flatten(report):
    return [fi for host in report.get("findings", []) for fi in host.get("findings", [])]


def main():
    server = LabServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target_file = tmp / "targets.json"
            outdir = tmp / "out"
            target_file.write_text(
                json.dumps([{"url": server.url + "/admin/", "title": "thinkphp-yyladmin-lab", "score": 100}]),
                encoding="utf-8",
            )
            cmd = [
                sys.executable,
                str(SCANNER),
                "--input",
                str(target_file),
                "--outdir",
                str(outdir),
                "--workers",
                "8",
                "--timeout",
                "3",
                "--phase3a-timeout",
                "60",
                "--rescue-timeout",
                "30",
                "--phase3b-layer-timeout",
                "60",
                "--no-proxy",
                "--full-bypass",
            ]
            proc = subprocess.run(cmd, text=True, capture_output=True, timeout=160)
            if proc.returncode != 0:
                print(proc.stdout)
                print(proc.stderr)
                raise SystemExit(proc.returncode)

            inventory = [
                json.loads(line)
                for line in (outdir / "phase2_inventory.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ][0]
            assert "/admin/system.Login/setting" in inventory["apis"], inventory["apis"][:30]
            assert "/large/Index/message" in inventory["apis"], inventory["apis"][:30]
            assert inventory["js_count"] >= 1, inventory
            assert inventory["js_discovered"] >= 3, inventory
            assert inventory["js_discovered"] >= inventory["js_attempted"], inventory

            report = json.loads((outdir / "report.json").read_text(encoding="utf-8"))
            findings = flatten(report)
            paths = {urlparse(fi.get("url", "")).path for fi in findings}
            assert "/admin/system.Login/setting" in paths, paths
            assert "/large/Index/message" in paths, paths
            assert "/views/device/index.vue" not in paths, "ThinkPHP controller-not-exists response should be filtered"
            large = next(fi for fi in findings if urlparse(fi.get("url", "")).path == "/large/Index/message")
            keys = set(large.get("data_keys", []))
            assert {"unit_name", "unit_number", "unit_type", "user_name"}.issubset(keys), large
            print("THINKPHP YYLADMIN ROUTES LAB PASS")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
