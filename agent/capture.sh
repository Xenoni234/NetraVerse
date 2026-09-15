#!/usr/bin/env bash
# Rolling capture agent for the Tailscale server.
# Captures 30 s pcap chunks on an interface, converts each to CICFlowMeter flow
# CSVs (feature parity with CIC-IDS training), and drops them in a watched dir
# that scripts/live_forecast.py tails. Run on the server under sudo.
#
#   sudo IFACE=tailscale0 CFM=/opt/CICFlowMeter/bin/cfm OUTDIR=~/nv_flows ./capture.sh
#
# IFACE : interface to sniff (tailscale0 to see tailnet attacks; eth0 for LAN).
# CFM   : path to the CICFlowMeter launcher (Java tool: github ahlashkari/CICFlowMeter).
# OUTDIR: directory where flow CSVs accumulate (point live_forecast --flows here).
set -euo pipefail

IFACE="${IFACE:-tailscale0}"
OUTDIR="${OUTDIR:-$HOME/nv_flows}"
CFM="${CFM:-cfm}"
WINDOW="${WINDOW:-30}"
TMP="$(mktemp -d)"
mkdir -p "$OUTDIR"
echo "[agent] iface=$IFACE window=${WINDOW}s outdir=$OUTDIR cfm=$CFM"
echo "[agent] Ctrl-C to stop."

cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

while true; do
  CHUNK="$TMP/chunk_$(date +%s).pcap"
  # capture one WINDOW-second chunk
  timeout "${WINDOW}s" tcpdump -i "$IFACE" -w "$CHUNK" -q 2>/dev/null || true
  [ -s "$CHUNK" ] || { echo "[agent] (no packets this window)"; continue; }
  # convert to CICFlowMeter flow CSV -> OUTDIR (Java CFM writes <name>_Flow.csv)
  "$CFM" "$CHUNK" "$OUTDIR" >/dev/null 2>&1 || echo "[agent] CFM failed on $CHUNK"
  rm -f "$CHUNK"
  echo "[agent] $(date +%H:%M:%S) flows updated in $OUTDIR"
done
