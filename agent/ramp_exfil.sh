#!/usr/bin/env bash
# Exfiltration RAMP (authorized testing of your OWN network only).
#
# Reproduces the flow-level signature of data exfiltration: large, ASYMMETRIC
# outbound volume (bytes_per_sec high, fwd/bwd ratio high) from the sensor to a
# collector host, so the world model warns as the transfer builds (EXFILTRATION
# stage). Sends random bytes — no real data leaves.
#
#   COLLECTOR=192.168.0.199 PORT=9000 ./agent/ramp_exfil.sh
# On the collector first:  nc -l -p 9000 >/dev/null   (or: nc -lk 9000 >/dev/null)
set -u
COLLECTOR=${COLLECTOR:-192.168.0.199}
PORT=${PORT:-9000}
BENIGN=${BENIGN:-180}
STEP_MB=${STEP_MB:-2}     # +N MB per 30 s window
WINDOWS=${WINDOWS:-8}
log(){ echo "[$(date +%H:%M:%S) IST] $*"; }

log "BENIGN runway ${BENIGN}s (small periodic requests)"
end=$(( $(date +%s) + BENIGN ))
while [ "$(date +%s)" -lt "$end" ]; do head -c 1024 /dev/urandom | nc -w1 "$COLLECTOR" "$PORT" >/dev/null 2>&1; sleep 5; done

log "RAMP start: rising outbound transfer to $COLLECTOR:$PORT"
for w in $(seq 1 "$WINDOWS"); do
  mb=$(( w * STEP_MB ))
  wend=$(( $(date +%s) + 30 ))
  log "window $w: sending ~${mb} MB"
  head -c $(( mb * 1024 * 1024 )) /dev/urandom | nc -w 25 "$COLLECTOR" "$PORT" >/dev/null 2>&1 || true
  while [ "$(date +%s)" -lt "$wend" ]; do sleep 0.2; done
done
log "RAMP done"
