#!/usr/bin/env bash
# SSH brute-force RAMP (authorized testing of your own server).
#
# Reproduces the FLOW-LEVEL signature of a credential brute-force: a rising rate of
# short connections concentrated on ONE service port (22), so the world model can
# warn during the build-up before a signature IDS's rate threshold trips. This is
# not real credential stuffing (the model only sees flow features) — swap in
#   hydra -l <user> -P <wordlist> ssh://$SERVER
# with a throwaway account if you want literal auth attempts.
#
#   SERVER=100.72.80.52 ./agent/ramp_bruteforce.sh
#
# Sequence: BENIGN runway -> ramp: +STEP connections/window to :22 for WINDOWS
# windows. After it ends, do ONE real `ssh` login yourself = the "compromise" mark;
# the model should have warned before that.
set -u
SERVER=${SERVER:-100.72.80.52}
PORT=${PORT:-22}
BENIGN=${BENIGN:-300}    # 5 min benign runway
STEP=${STEP:-20}         # +N connections per 30 s window (rate ramp)
WINDOWS=${WINDOWS:-10}
PAR=${PAR:-4}
log(){ echo "[$(date -u +%H:%M:%S) UTC] $*"; }

log "BENIGN runway ${BENIGN}s (gentle: ~1 connect / 4s so the model stays quiet)"
end=$(( $(date +%s) + BENIGN ))
while [ "$(date +%s)" -lt "$end" ]; do curl -s -m 2 "telnet://$SERVER:$PORT" >/dev/null 2>&1; sleep 4; done

log "RAMP start: +${STEP} conns/window x ${WINDOWS} windows to :${PORT}"
for w in $(seq 1 "$WINDOWS"); do
  n=$(( w * STEP ))
  wend=$(( $(date +%s) + 30 ))
  log "window $w: ${n} connections to :${PORT} (~$(awk "BEGIN{printf \"%.1f\", $n/30}")/s)"
  seq 1 "$n" | xargs -P "$PAR" -I{} sh -c "curl -s -m 1 \"telnet://$SERVER:$PORT\" >/dev/null 2>&1"
  while [ "$(date +%s)" -lt "$wend" ]; do sleep 0.2; done   # pad to the 30 s window
done
log "RAMP done — now do ONE real 'ssh $SERVER' as the compromise marker"
