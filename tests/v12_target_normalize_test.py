#!/usr/bin/env python3
"""Regression checks for target URL normalization and HTTPS port mapping."""

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "pipeline" / "deep_scanner.py"


def load_scanner():
    old_argv = sys.argv[:]
    sys.argv = [str(SCANNER)]
    try:
        spec = importlib.util.spec_from_file_location("deep_scanner_norm_test", SCANNER)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        sys.argv = old_argv


def main():
    scanner = load_scanner()
    cases = {
        "222.184.27.194:8089": ("http://222.184.27.194:8089", "222.184.27.194", 8089),
        "1.2.3.4:9443": ("https://1.2.3.4:9443", "1.2.3.4", 9443),
        "1.2.3.4:10443": ("https://1.2.3.4:10443", "1.2.3.4", 10443),
        "https://example.com:8443/path/": ("https://example.com:8443/path/", "example.com", 8443),
        "example.com": ("", "example.com", None),
    }
    for raw, expected in cases.items():
        got = scanner.target_url_with_scheme(raw)
        assert got == expected, f"{raw}: expected {expected}, got {got}"
    print("TARGET NORMALIZE PASS")


if __name__ == "__main__":
    main()
