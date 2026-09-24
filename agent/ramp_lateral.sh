#!/usr/bin/env bash
# Lateral-movement RAMP (authorized testing of your OWN LAN only).
#
# Reproduces the flow-level signature of lateral movement: a host reaching out to
# a growing set of NEW internal peers (n_distinct_dst_ip up, new_peer_count up)
# without a broad single-host port scan — so the world model warns as an internal
# host starts fanning out (LATERAL_MOVEMENT stage). Run FROM an owned device that
# the sensor can see (or from the sensor itself against owned LAN hosts).
#
#   SUBNET=192.168.0 PORTS="22 445 3389" ./agent/ramp_lateral.sh
set -u
SUBNET=${SUBNET:-192.168.0}
PORTS=${PORTS:-"22 445 3389 139"}
BENIGN=${BENIGN:-180}
STEP=${STEP:-3}          # +N new internal peers per 30 s window
WINDOWS=${WINDOWS:-10}
FIRST_HOST=${FIRST_HOST:-2}
log(){ echo "[$(date +%H:%M:%S) IST] $*"; }

log "BENIGN runway ${BENIGN}s (talk to the gateway only)"
end=$(( $(date +%s) + BENIGN ))
while [ "$(date +%s)" -lt "$end" ]; do curl -s -m 2 "http://$SUBNET.1/" >/dev/null 2>&1; sleep 4; done

log "RAMP start: +${STEP} new internal peers/window across ports [$PORTS]"
host=$FIRST_HOST
for w in $(seq 1 "$WINDOWS"); do
  wend=$(( $(date +%s) + 30 ))
  reached=0
  while [ "$reached" -lt "$STEP" ] && [ "$host" -le 254 ]; do
    ip="$SUBNET.$host"
    for p in $PORTS; do curl -s -m 1 "telnet://$ip:$p" >/dev/null 2>&1; done
    reached=$(( reached + 1 )); host=$(( host + 1 ))
  done
  log "window $w: touched $(( STEP * w )) internal peers so far"
  while [ "$(date +%s)" -lt "$wend" ]; do sleep 0.2; done
done
log "RAMP done"
