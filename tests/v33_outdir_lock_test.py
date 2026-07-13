#!/usr/bin/env python3
"""Regression: concurrent scanner processes must not share one outdir."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "pipeline" / "deep_scanner.py"


def main():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        outdir = root / "out"
        outdir.mkdir()
        sentinel = outdir / "phase2_full.jsonl"
        sentinel.write_text("sentinel\n", encoding="utf-8")
        target_file = root / "targets.json"
        target_file.write_text(json.dumps([]), encoding="utf-8")

        holder_source = "\n".join([
            "import sys,time",
            "sys.path.insert(0, " + repr(str(ROOT)) + ")",
            "import pipeline.deep_scanner as scanner",
            "scanner.OUTDIR = " + repr(str(outdir)),
            "scanner.args.outdir = scanner.OUTDIR",
            "scanner.acquire_outdir_lock()",
            "print('LOCKED', flush=True)",
            "time.sleep(30)",
        ])
        holder = subprocess.Popen(
            [sys.executable, "-c", holder_source],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            assert holder.stdout is not None
            ready = holder.stdout.readline().strip()
            assert ready == "LOCKED", (ready, holder.stderr.read() if holder.stderr else "")
            contender = subprocess.run(
                [
                    sys.executable,
                    str(SCANNER),
                    "--input", str(target_file),
                    "--outdir", str(outdir),
                    "--dry-run",
                    "--fresh",
                ],
                text=True,
                capture_output=True,
                timeout=20,
            )
            assert contender.returncode == 2, (contender.returncode, contender.stdout, contender.stderr)
            assert "already in use" in contender.stderr, contender.stderr
            assert sentinel.read_text(encoding="utf-8") == "sentinel\n", sentinel.read_text(encoding="utf-8")
        finally:
            holder.terminate()
            try:
                holder.wait(timeout=5)
            except subprocess.TimeoutExpired:
                holder.kill()
                holder.wait(timeout=5)
        print("OUTDIR LOCK TEST PASS")


if __name__ == "__main__":
    main()
