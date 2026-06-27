#!/usr/bin/env python3
"""Regression for JS graph v2 dataflow endpoint reconstruction."""

import json
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


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
        if path == "/":
            return self.send_body('<script type="module" src="/src/main.js"></script>')
        if path == "/src/main.js":
            return self.send_body(
                'import "./api.js";\n',
                "application/javascript",
            )
        if path == "/src/api.js":
            return self.send_body(
                'const apiBase = "/api";\n'
                'const userBase = apiBase + "/user";\n'
                'const detailPath = userBase + "/detail";\n'
                'const screenBase = "/large/Index/";\n'
                'const msgPath = screenBase + "message";\n'
                'const dynamicPath = screenBase + `detail/${unitId}`;\n'
                'const q = {userId: id, pageNum: 1, pageSize: 10};\n'
                'axios.get(detailPath, {params: q});\n'
                'service.get(msgPath, {params: {unitId: unitId}});\n'
                'request({url: dynamicPath, data: {deviceId: deviceId}});\n',
                "application/javascript",
            )
        if path == "/api/user/detail":
            qs = parse_qs(parsed.query)
            if qs.get("userId"):
                return self.send_json({
                    "code": 0,
                    "data": [{"userId": 1, "phone": "13800000000", "address": "Nanjing"}],
                })
            return self.send_json({"code": 401, "msg": "请登录", "data": []})
        if path == "/large/Index/message":
            qs = parse_qs(parsed.query)
            if qs.get("unitId"):
                return self.send_json({
                    "code": 200,
                    "msg": "操作成功",
                    "data": [{"unit_name": "设备1", "unit_number": "FE220513B064", "user_name": "廿三里分公司"}],
                })
            return self.send_json({"code": 401, "msg": "请登录", "data": []})
        if path == "/large/Index/detail/1":
            return self.send_json({
                "code": 200,
                "msg": "操作成功",
                "data": [{"deviceId": 1, "unit_type": "电能表", "alarm": "over voltage"}],
            })
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
            target_file.write_text(json.dumps([{"url": server.url, "title": "js-graph-dataflow", "score": 100}]), encoding="utf-8")
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
                "--no-proxy",
                "--full-bypass",
                "--param-max-probes",
                "8",
                "--phase3a-timeout",
                "60",
                "--phase3b-layer-timeout",
                "60",
            ]
            proc = subprocess.run(cmd, text=True, capture_output=True, timeout=140)
            if proc.returncode != 0:
                print(proc.stdout)
                print(proc.stderr)
                raise SystemExit(proc.returncode)

            inventory = [
                json.loads(line)
                for line in (outdir / "phase2_inventory.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ][0]
            assert "/api/user/detail" in inventory["apis"], inventory["apis"][:40]
            assert "/large/Index/message" in inventory["apis"], inventory["apis"][:40]
            assert "/large/Index/detail/1" in inventory["apis"], inventory["apis"][:40]
            assert inventory["js_graph_edges"] >= 1, inventory
            params = inventory["param_profile"]["api_params"]
            assert "userId" in params["/api/user/detail"], params
            assert "unitId" in params["/large/Index/message"], params
            assert "deviceId" in params["/large/Index/detail/1"], params

            report = json.loads((outdir / "report.json").read_text(encoding="utf-8"))
            paths = {urlparse(fi.get("url", "")).path for fi in flatten(report)}
            assert "/api/user/detail" in paths, paths
            assert "/large/Index/message" in paths, paths
            assert "/large/Index/detail/1" in paths, paths
            print("JS GRAPH DATAFLOW LAB PASS")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
