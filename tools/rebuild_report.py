#!/usr/bin/env python3
"""Rebuild v13 report.json/report.md from checkpoint JSON files in an outdir."""

import argparse
import importlib.util
import json
from pathlib import Path


def load_scanner(root):
    candidates = [
        root / "deep_scanner.py",
        root / "scripts" / "pipeline" / "deep_scanner.py",
    ]
    scanner_path = next((path for path in candidates if path.exists()), None)
    if not scanner_path:
        raise FileNotFoundError("deep_scanner.py not found in project root or scripts/pipeline")
    spec = importlib.util.spec_from_file_location("deep_scanner_rebuild", scanner_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    parser = argparse.ArgumentParser(description="Rebuild v13 reports from checkpoint JSON files")
    parser.add_argument("--outdir", required=True)
    args, scanner_args = parser.parse_known_args()

    root = Path(__file__).resolve().parents[1]
    mod = load_scanner(root)
    outdir = Path(args.outdir)

    vulnerable = []
    for path in sorted(outdir.glob("*.json")):
        if path.name in ("report.json", "apis.json"):
            continue
        item = json.loads(path.read_text(encoding="utf-8"))
        findings = mod.merge_findings([], item.get("findings", []))
        if not findings:
            continue
        item["findings"] = findings
        item["finding_count"] = len(findings)
        vulnerable.append(item)
        path.write_text(json.dumps(item, ensure_ascii=False, indent=2), encoding="utf-8")

    stats = mod.report_stats(vulnerable)
    report = {
        "scan_time": "rebuilt",
        "targets": None,
        "live": None,
        "apis": None,
        "vulnerable": len(vulnerable),
        "stats": stats,
        "findings": [
            {"url": v["base"], "title": v.get("title", ""), "findings": v.get("findings", [])}
            for v in vulnerable
        ],
    }
    (outdir / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    md = [
        "# 扫描报告 v13 (rebuilt)\n",
        "## 统计口径\n",
        f"- 漏洞目标: {len(vulnerable)}",
        f"- 原始发现: {stats['raw_findings']}",
        f"- 去重端点: {stats['unique_endpoints']}",
        f"- 数据类发现: {stats['data_findings']} / 去重数据端点: {stats['unique_data_endpoints']}",
        f"- 高价值发现: {stats['high_value_findings']}",
        f"- 文件类发现: {stats['file_leaks']} / 公开下载情报: {stats['public_download_intel']}",
        "\n## 漏洞汇总\n",
        "| # | URL | 标题 | 发现数 |",
        "|---|-----|------|--------|",
    ]
    for i, v in enumerate(vulnerable, 1):
        md.append(f"| {i} | {v['base']} | {v.get('title','')[:30]} | {v.get('finding_count',0)} |")
    (outdir / "report.md").write_text("\n".join(md), encoding="utf-8")

    print(f"rebuilt: targets={len(vulnerable)} raw={stats['raw_findings']} unique={stats['unique_endpoints']} files={stats['file_leaks']} public={stats['public_download_intel']}")


if __name__ == "__main__":
    main()
