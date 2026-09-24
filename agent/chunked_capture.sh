#!/usr/bin/env bash
# NetraVerse chunked live capture — fixes cicflowmeter's live flush lag.
#
# Problem: `cicflowmeter -i` buffers each flow until a ~120 s inactivity timeout,
# so a live port scan / SYN flood barely appears in time (each scan flow is a
# separate short-lived 5-tuple that never flushes promptly). This captures fixed
# 30 s pcap CHUNKS with tcpdump and runs cicflowmeter OFFLINE on each completed
# chunk — reaching pcap EOF flushes *every* flow, so the scan's fan-out shows up
# within one 30 s window.
#
# AUTHORIZED TESTING ON YOUR OWN NETWORK ONLY.
#
# Usage:  sudo ./agent/chunked_capture.sh [IFACE] [OUTDIR] [GATEWAY]
#   e.g.  sudo ./agent/chunked_capture.sh wlp0s20f3 /home/aayush-gupta/nv_flows_live 192.168.0.1
#
# Set MIRROR=1 to also ARP-mirror the LAN (all-IPs). Without it, captures traffic
# to/from the sensor — enough for an attack aimed AT the sensor.
#   sudo MIRROR=1 ./agent/chunked_capture.sh wlp0s20f3 /home/aayush-gupta/nv_flows_live 192.168.0.1
set -uo pipefail

IFACE="${1:-wlp0s20f3}"
OUTDIR="${2:-$HOME/nv_flows_live}"
GATEWAY="${3:-192.168.0.1}"
CHUNK="${CHUNK_SECONDS:-30}"
MIRROR="${MIRROR:-0}"
KEEP="${KEEP_CHUNKS:-40}"
VENV="${NETRAVERSE_VENV:-/opt/netraverse/.venv}"

if [ "$(id -u)" -ne 0 ]; then echo "Run with sudo — tcpdump needs root." >&2; exit 1; fi
command -v tcpdump >/dev/null || { echo "install tcpdump: sudo apt install -y tcpdump" >&2; exit 1; }
[ -x "$VENV/bin/cicflowmeter" ] || { echo "cicflowmeter not at $VENV/bin/cicflowmeter" >&2; exit 1; }

mkdir -p "$OUTDIR/pcap"
OLD_FWD="$(cat /proc/sys/net/ipv4/ip_forward)"
MITM_PID=""
cleanup() {
  echo; echo "[chunk] stopping…"
  [ -n "$MITM_PID" ] && kill "$MITM_PID" 2>/dev/null || true
  sleep 1
  echo "$OLD_FWD" > /proc/sys/net/ipv4/ip_forward
  echo "[chunk] done."
}
trap cleanup EXIT INT TERM

if [ "$MIRROR" = "1" ]; then
  echo 1 > /proc/sys/net/ipv4/ip_forward
  if command -v ettercap >/dev/null 2>&1; then
    ettercap -Tq -i "$IFACE" -M arp:remote "/$GATEWAY//" "//" >/tmp/nv-ettercap.log 2>&1 &
    MITM_PID=$!
    sleep 3
    echo "[chunk] ettercap MITM pid=$MITM_PID — verify on a client that 'arp -a' shows the SENSOR's MAC for $GATEWAY (see /tmp/nv-ettercap.log)."
  else
    echo "[chunk] MIRROR=1 but ettercap missing (sudo apt install -y ettercap-text-only); capturing sensor traffic only."
  fi
fi

echo "[chunk] capturing iface=$IFACE out=$OUTDIR chunk=${CHUNK}s mirror=$MIRROR — Ctrl-C to stop."
while true; do
  ts="$(date +%Y%m%d_%H%M%S)"
  pc="$OUTDIR/pcap/c_$ts.pcap"
  timeout "$CHUNK" tcpdump -i "$IFACE" -w "$pc" "ip and (tcp or udp)" 2>/dev/null || true
  if [ -s "$pc" ]; then
    "$VENV/bin/cicflowmeter" -f "$pc" -c "$OUTDIR/c_$ts.csv" >/dev/null 2>&1 || true
  fi
  rm -f "$pc"
  # keep only the most recent KEEP chunks (~KEEP*30 s of history)
  ls -1t "$OUTDIR"/c_*.csv 2>/dev/null | tail -n +"$((KEEP + 1))" | xargs -r rm -f
done
