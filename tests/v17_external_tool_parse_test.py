#!/usr/bin/env python3
"""Regression checks for external masscan/naabu/httpx integration helpers."""

import importlib.util
import json
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "pipeline" / "deep_scanner.py"


def load_scanner(extra_args=None):
    old_argv = sys.argv[:]
    sys.argv = [str(SCANNER)] + (extra_args or [])
    try:
        spec = importlib.util.spec_from_file_location("deep_scanner_external_test", SCANNER)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        sys.argv = old_argv


def write(path, content):
    path.write_text(content, encoding="utf-8")
    return str(path)


def main():
    scanner = load_scanner(["--no-proxy"])
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        masscan_ol = write(tmp / "masscan.lst", "open tcp 8443 192.0.2.10\nopen tcp 8080 192.0.2.11\n")
        assert scanner.load_targets(masscan_ol, "masscan") == [
            ("192.0.2.10:8443", "masscan", 0),
            ("192.0.2.11:8080", "masscan", 0),
        ]

        masscan_json = write(tmp / "masscan.json", json.dumps([
            {"ip": "192.0.2.20", "ports": [{"port": 80, "proto": "tcp"}, {"port": 53, "proto": "udp"}]},
            {"ip": "192.0.2.21", "port": 9443},
        ]))
        assert scanner.load_targets(masscan_json, "masscan") == [
            ("192.0.2.20:80", "masscan", 0),
            ("192.0.2.21:9443", "masscan", 0),
        ]

        naabu = write(tmp / "naabu.txt", "192.0.2.30:8080\nhttps://192.0.2.31:8443\n")
        assert scanner.load_targets(naabu, "hostport") == [
            ("192.0.2.30:8080", "hostport", 0),
            ("https://192.0.2.31:8443", "hostport", 0),
        ]

        httpx = write(tmp / "httpx.jsonl", "\n".join([
            json.dumps({"url": "http://192.0.2.40:8080", "title": "one", "status_code": 200}),
            json.dumps({"final_url": "https://192.0.2.41/app/", "title": "two", "status_code": 302}),
        ]))
        assert scanner.load_targets(httpx, "httpx-json") == [
            ("http://192.0.2.40:8080", "one", 200),
            ("https://192.0.2.41/app/", "two", 302),
        ]

        assert scanner.dedupe_targets([
            ("http://a", "", 0),
            ("http://a", "dup", 200),
            ("http://b", "", 0),
        ]) == [("http://a", "", 0), ("http://b", "", 0)]

    auto = load_scanner(["--http-prober", "auto", "--httpx-bin", "/no/such/httpx"])
    assert auto.run_httpx_probe([("127.0.0.1:9", "", 0)]) is None
    print("EXTERNAL TOOL PARSE PASS")


if __name__ == "__main__":
    main()
