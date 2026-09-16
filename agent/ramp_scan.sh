#!/usr/bin/env bash
# Slow / stealthy port-scan RAMP (authorized testing of your own server).
#
# Unlike an abrupt scan (fan-out 1->500 in one window, unforecastable), this grows
# the destination-port fan-out gradually so the world model can warn during the
# recon run-up, BEFORE a signature IDS (which only fires once fan-out is obvious).
#
#   SERVER=100.72.80.52 ./agent/ramp_scan.sh
#
# Sequence: BENIGN runway (build L=10 history) -> ramp: +STEP new dst ports each
# 30 s window for WINDOWS windows. Low parallelism (-P 4) avoids the client-side
# connection self-throttle we hit with a 60-way flood.
set -u
SERVER=${SERVER:-100.72.80.52}
BENIGN=${BENIGN:-300}     # 5 min benign runway
STEP=${STEP:-8}           # +N distinct dst ports per 30 s window
WINDOWS=${WINDOWS:-12}    # ramp length (windows) -> peak fan-out = STEP*WINDOWS
PAR=${PAR:-4}
FIRST_PORT=${FIRST_PORT:-1000}   # start above well-known ports (all filtered => clean fan-out)
log(){ echo "[$(date -u +%H:%M:%S) UTC] $*"; }

log "BENIGN runway ${BENIGN}s (SSH banner grabs to :22)"
end=$(( $(date +%s) + BENIGN ))
while [ "$(date +%s)" -lt "$end" ]; do curl -s -m 2 "telnet://$SERVER:22" >/dev/null 2>&1; sleep 1; done

log "RAMP start: +${STEP} ports/window x ${WINDOWS} windows (peak $((STEP*WINDOWS)) ports)"
port=$FIRST_PORT
for w in $(seq 1 "$WINDOWS"); do
  n=$(( w * STEP ))
  hi=$(( port + n - 1 ))
  wend=$(( $(date +%s) + 30 ))
  log "window $w: scanning $n ports (${port}-${hi})"
  seq "$port" "$hi" | xargs -P "$PAR" -I{} sh -c "curl -s -m 1 \"telnet://$SERVER:{}\" >/dev/null 2>&1"
  port=$(( hi + 1 ))
  while [ "$(date +%s)" -lt "$wend" ]; do sleep 0.2; done   # pad to the 30 s window
done
log "RAMP done"
