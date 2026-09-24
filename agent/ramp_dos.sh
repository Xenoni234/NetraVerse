#!/usr/bin/env bash
# DoS / flood RAMP (authorized testing of your OWN server/device only).
#
# Reproduces the flow-level signature of a volumetric flood: a rising packet/SYN
# rate to one host, so the world model warns during the build-up (maps to the
# IMPACT stage). BOUNDED on purpose — a gentle ramp, not an unbounded flood, so it
# never actually knocks your network over.
#
#   SERVER=100.72.80.52 ./agent/ramp_dos.sh
#
# Uses hping3 (SYN flood) if present, else a bounded curl connection flood.
set -u
SERVER=${SERVER:-100.72.80.52}
PORT=${PORT:-80}
BENIGN=${BENIGN:-180}     # 3 min benign runway
STEP=${STEP:-40}          # +N packets/connections per 30 s window
WINDOWS=${WINDOWS:-10}
log(){ echo "[$(date +%H:%M:%S) IST] $*"; }

log "BENIGN runway ${BENIGN}s"
end=$(( $(date +%s) + BENIGN ))
while [ "$(date +%s)" -lt "$end" ]; do curl -s -m 2 "http://$SERVER:$PORT/" >/dev/null 2>&1; sleep 3; done

HAVE_HPING=0; command -v hping3 >/dev/null && HAVE_HPING=1
log "RAMP start: rising flood to $SERVER:$PORT (hping3=$HAVE_HPING)"
for w in $(seq 1 "$WINDOWS"); do
  n=$(( w * STEP ))
  wend=$(( $(date +%s) + 30 ))
  log "window $w: ~${n} pkts/conns to :$PORT"
  if [ "$HAVE_HPING" = 1 ]; then
    sudo hping3 -S -c "$n" -i u100 -p "$PORT" "$SERVER" >/dev/null 2>&1 || true
  else
    seq 1 "$n" | xargs -P 8 -I{} sh -c "curl -s -m 1 \"http://$SERVER:$PORT/\" >/dev/null 2>&1"
  fi
  while [ "$(date +%s)" -lt "$wend" ]; do sleep 0.2; done
done
log "RAMP done"
