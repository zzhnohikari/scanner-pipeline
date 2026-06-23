#!/usr/bin/env python3
"""Regression checks for prefetch/preload JS discovery and dry-run JS stats."""

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "pipeline" / "deep_scanner.py"


def load_scanner():
    old_argv = sys.argv[:]
    sys.argv = [str(SCANNER), "--no-proxy"]
    try:
        spec = importlib.util.spec_from_file_location("deep_scanner_prefetch_test", SCANNER)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        sys.argv = old_argv


def main():
    scanner = load_scanner()
    html = """<!doctype html>
<html><head>
  <link href=/hnb/assets/js/chunk-a.111.js rel=prefetch>
  <link rel=preload href="/hnb/assets/js/chunk-b.222.js?x=1" as=script>
  <link rel="modulepreload" href="/hnb/assets/js/chunk-c.333.js">
  <link rel=prefetch href="/hnb/assets/css/chunk-a.css">
  <script src="/hnb/assets/js/app.444.js"></script>
</head><body></body></html>"""
    js = scanner.extract_js_from_html(html, "https://example.test/hnb/")
    expected = {
        "https://example.test/hnb/assets/js/chunk-a.111.js",
        "https://example.test/hnb/assets/js/chunk-b.222.js?x=1",
        "https://example.test/hnb/assets/js/chunk-c.333.js",
        "https://example.test/hnb/assets/js/app.444.js",
    }
    assert expected.issubset(js), f"missing js urls: {expected - js}"
    assert not any(url.endswith(".css") for url in js), js
    print("PREFETCH JS LAB PASS")


if __name__ == "__main__":
    main()
