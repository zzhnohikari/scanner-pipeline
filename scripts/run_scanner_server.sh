#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <input-file> [outdir] [extra deep_scanner args...]" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INPUT="$1"
OUTDIR="${2:-/tmp/scanner_run_$(date +%Y%m%d_%H%M%S)}"
shift || true
shift || true

mkdir -p "$OUTDIR"
LOG="$OUTDIR/run.log"
PIDFILE="$OUTDIR/run.pid"

export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"
cd "$ROOT"

nohup python3 pipeline/deep_scanner.py \
  --input "$INPUT" \
  --outdir "$OUTDIR" \
  --workers "${SCANNER_WORKERS:-12}" \
  --timeout "${SCANNER_TIMEOUT:-5}" \
  --phase2-timeout "${SCANNER_PHASE2_TIMEOUT:-600}" \
  --phase3a-timeout "${SCANNER_PHASE3A_TIMEOUT:-90}" \
  --rescue-timeout "${SCANNER_RESCUE_TIMEOUT:-60}" \
  --phase3b-layer-timeout "${SCANNER_PHASE3B_LAYER_TIMEOUT:-90}" \
  --no-proxy \
  --full-bypass \
  --fresh \
  "$@" > "$LOG" 2>&1 &

PID=$!
echo "$PID" > "$PIDFILE"
echo "started pid=$PID"
echo "outdir=$OUTDIR"
echo "log=$LOG"
echo "tail -f $LOG"
