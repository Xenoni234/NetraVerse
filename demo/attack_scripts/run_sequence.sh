#!/usr/bin/env bash
# Rehearsed kill-chain against YOUR OWN lab device: recon -> brute force -> lateral probe.
# Each stage appends its exact time window to a schedule file so the capture can be labelled
# (src/training/lab_dataset.py). Record the sensor side at the same time, e.g.
#   sudo tcpdump -i <iface> -w data/raw/lab/session1.pcap
#
# usage: NV_I_OWN_THIS_TARGET=yes NV_ATTACKER_IP=<this machine's LAN IP> \
#        ./run_sequence.sh <target-ip> [ssh-user] [lateral-cidr]
set -euo pipefail
D="$(dirname "$0")"; T="${1:?target ip}"; U="${2:-testuser}"; NET="${3:-}"
ATK="${NV_ATTACKER_IP:?set NV_ATTACKER_IP to this machine's LAN IP (used for labels)}"
SCHED="${NV_LAB_SCHEDULE:-$D/../../data/raw/lab/schedule.jsonl}"; mkdir -p "$(dirname "$SCHED")"
stage() {  # stage <label> <targets-json> <command...>
  local label="$1" targets="$2"; shift 2
  local t0; t0=$(date +%s.%N)
  "$@" || true
  printf '{"label": "%s", "attacker": "%s", "targets": %s, "start": %s, "end": %s}\n' \
    "$label" "$ATK" "$targets" "$t0" "$(date +%s.%N)" >> "$SCHED"
}
echo "[baseline] 5 min of normal activity before the attack"; sleep 300
stage "PortScan"    "[\"$T\"]" "$D/01_recon.sh" "$T";            sleep 120
stage "SSH-Patator" "[\"$T\"]" "$D/02_bruteforce.sh" "$T" "$U";  sleep 120
if [ -n "$NET" ]; then stage "Infiltration" "[]" "$D/03_lateral.sh" "$NET"; fi
echo "[done] schedule -> $SCHED"
