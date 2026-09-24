#!/usr/bin/env bash
# NetraVerse all-IPs live capture via ARP mirroring.
#
# AUTHORIZED TESTING ON YOUR OWN NETWORK ONLY. This puts the sensor between the
# gateway and the LAN (ARP MITM) so it observes every device's internet-bound
# traffic, then converts packets to CICFlowMeter flows for the forecaster. It is
# fully reversible: stop it (Ctrl-C) and the network returns to normal.
#
# Chosen because the TP-Link Archer A6 V4 (Broadcom) has no OpenWrt support, so a
# clean router-side tcpdump is not possible. ARP mirroring needs no router change.
#
# Usage:  sudo ./agent/arp_mirror_capture.sh [IFACE] [GATEWAY] [OUTDIR]
#   e.g.  sudo ./agent/arp_mirror_capture.sh wlp0s20f3 192.168.0.1 /home/aayush-gupta/nv_flows_live
#
# Point the forecaster and API at OUTDIR:
#   nv-live:  scripts/live_forecast.py --flows OUTDIR --entity-granularity src_ip
#   nv-api :  NETRAVERSE_LIVE_FLOWS=OUTDIR  NETRAVERSE_LIVE_CHECKPOINT=models/wm_server/best.ckpt
set -euo pipefail

IFACE="${1:-wlp0s20f3}"
GATEWAY="${2:-192.168.0.1}"
OUTDIR="${3:-$HOME/nv_flows_live}"
VENV="${NETRAVERSE_VENV:-/opt/netraverse/.venv}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run with sudo — ARP spoofing, IP forwarding and raw capture need root." >&2
  exit 1
fi
if [ ! -x "$VENV/bin/cicflowmeter" ]; then
  echo "cicflowmeter not found at $VENV/bin/cicflowmeter (set NETRAVERSE_VENV)." >&2
  exit 1
fi

mkdir -p "$OUTDIR"
echo "[arp-mirror] iface=$IFACE gateway=$GATEWAY out=$OUTDIR"
echo "[arp-mirror] AUTHORIZED TESTING ON YOUR OWN NETWORK ONLY — Ctrl-C restores the network."

# Keep the LAN online while we sit in the middle.
OLD_FWD="$(cat /proc/sys/net/ipv4/ip_forward)"
echo 1 > /proc/sys/net/ipv4/ip_forward

CF_PID=""; MITM_PID=""
cleanup() {
  echo; echo "[arp-mirror] restoring the network…"
  [ -n "$CF_PID" ]   && kill "$CF_PID"   2>/dev/null || true
  [ -n "$MITM_PID" ] && kill "$MITM_PID" 2>/dev/null || true
  sleep 2   # ettercap re-ARPs the hosts back to the real gateway on clean exit
  echo "$OLD_FWD" > /proc/sys/net/ipv4/ip_forward
  echo "[arp-mirror] done. ip_forward restored to $OLD_FWD."
}
trap cleanup EXIT INT TERM

# Preferred: ettercap re-ARPs the WHOLE subnet to the gateway and cleans up on exit.
if command -v ettercap >/dev/null 2>&1; then
  echo "[arp-mirror] ettercap MITM: gateway <-> all hosts"
  ettercap -Tq -i "$IFACE" -M arp:remote "/$GATEWAY//" "//" >/dev/null 2>&1 &
  MITM_PID=$!
elif command -v arpspoof >/dev/null 2>&1; then
  echo "[arp-mirror] arpspoof: telling the LAN we are the gateway ($GATEWAY)"
  arpspoof -i "$IFACE" "$GATEWAY" >/dev/null 2>&1 &
  MITM_PID=$!
else
  echo "Need ettercap or dsniff. Install one:" >&2
  echo "  sudo apt install -y ettercap-text-only   # preferred" >&2
  echo "  sudo apt install -y dsniff                # arpspoof fallback" >&2
  exit 1
fi
sleep 3

# Convert the mirrored packets to CICFlowMeter flows the forecaster reads.
"$VENV/bin/cicflowmeter" -i "$IFACE" -c "$OUTDIR/live.csv" &
CF_PID=$!
echo "[arp-mirror] capturing all-IPs flows -> $OUTDIR/live.csv (Ctrl-C to stop)."
wait "$CF_PID"
