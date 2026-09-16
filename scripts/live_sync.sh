#!/usr/bin/env bash
# Real-time flow sync: pull the server's growing cicflowmeter CSV to this PC so the
# dashboard's "Live (real-time)" mode can forecast it. Needs passwordless SSH
# (BatchMode) — set up an SSH key first (see docs/live_test_runbook.md).
#
#   SERVER=aayush-gupta@100.72.80.52 ./scripts/live_sync.sh
#
# Writes atomically (.tmp + mv) so the dashboard never reads a half-copied file.
set -u
SERVER=${SERVER:-aayush-gupta@100.72.80.52}
REMOTE=${REMOTE:-nv_flows/live.csv}          # path on the server (relative to $HOME)
HERE="$(cd "$(dirname "$0")/.." && pwd)"
LOCAL=${LOCAL:-"$HERE/data/live/live.csv"}
INTERVAL=${INTERVAL:-3}

mkdir -p "$(dirname "$LOCAL")"
echo "[sync] $SERVER:~/$REMOTE -> $LOCAL every ${INTERVAL}s (Ctrl-C to stop)"
while true; do
  if scp -q -o BatchMode=yes -o ConnectTimeout=5 "$SERVER:$REMOTE" "$LOCAL.tmp" 2>/dev/null && [ -s "$LOCAL.tmp" ]; then
    mv -f "$LOCAL.tmp" "$LOCAL"
  fi
  rm -f "$LOCAL.tmp" 2>/dev/null
  sleep "$INTERVAL"
done
