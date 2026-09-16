# Live test runbook — forecasting real attacks on the Tailscale server

**Authorized testing only** — this is for a server you own and fully control, over
your own tailnet. Do not run any of this against systems you don't own.

## Why this setup works (Cloudflare bypass)

The public site is Cloudflare-tunneled, so the origin only sees Cloudflare IPs for
web traffic. But **scan / brute-force / DoS target the server's IP and ports
directly** and bypass Cloudflare entirely — so we attack the server's **Tailscale
IP** and capture real per-host flows on `tailscale0`. Web attacks are tested by
hitting the app's port on the tailnet IP directly (not the Cloudflare hostname).

Roles:
- **Server** (tailnet IP `100.x.y.z`): runs `agent/capture.sh` + optionally the
  forecaster.
- **Attacker** (a second tailnet machine): runs the commands below at `100.x.y.z`.
- **Monitor** (laptop or the server): dashboard + `scripts/live_forecast.py`.

## 0. Prep

```bash
# server: start capture (see agent/README.md)
sudo IFACE=tailscale0 CFM=/opt/CICFlowMeter/bin/cfm OUTDIR=~/nv_flows ./agent/capture.sh
# monitor: capture ~30-60 min of NORMAL traffic first, then calibrate:
python scripts/calibrate.py --flows ~/nv_flows --checkpoint models/wm_final/best.ckpt \
    --out models/wm_server/best.ckpt
# monitor: start the live loop
python scripts/live_forecast.py --flows ~/nv_flows --checkpoint models/wm_server/best.ckpt
# (optional) dashboard live view
streamlit run demo/app.py
```

Record the **exact wall-clock time** you launch each attack — lead time =
(attack launch time) − (first sustained alert time).

## Real-time mode (live dashboard, PC + SSH-key sync)

This runs the dashboard **live**: the server captures flows continuously, this PC
auto-pulls them every few seconds, and the forecast updates on screen as an attack
unfolds. Positive lead time comes from a **ramping** attack measured against a
signature baseline (an abrupt attack is detected only *at* onset — nothing can
forecast a no-run-up attack).

### One-time: passwordless SSH (so the sync loop needs no password)
On this PC:
```bash
ls ~/.ssh/id_ed25519.pub || ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519
# copy the key to the server (paste your password once):
ssh aayush-gupta@100.72.80.52 "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys" < ~/.ssh/id_ed25519.pub
ssh -o BatchMode=yes aayush-gupta@100.72.80.52 echo KEY_OK   # must print KEY_OK, no prompt
```

### Server: live capture (continuous)
```bash
mkdir -p ~/nv_flows
sudo cicflowmeter -i tailscale0 -c ~/nv_flows/live.csv    # appends flows as they flush
```
If `-i` buffers and rows don't appear, fall back to rolling pcap chunks:
`sudo tcpdump -i tailscale0 -G 30 -w ~/nv_cap/chunk-%s.pcap` + a loop running
`cicflowmeter -d ~/nv_cap -c ~/nv_flows/live.csv` on new chunks.

### This PC: sync + dashboard
```bash
SERVER=aayush-gupta@100.72.80.52 ./scripts/live_sync.sh      # pulls live.csv every 3s
streamlit run demo/app.py                                    # pick "Live (real-time)"
```

### This PC: launch a ramping attack (authorized, your own server)
```bash
SERVER=100.72.80.52 ./agent/ramp_scan.sh          # gradual port fan-out
SERVER=100.72.80.52 ./agent/ramp_bruteforce.sh    # rising connection rate to :22
```
Watch the **model alert** line cross before the **baseline alert** line — the gap is
the lead time, shown live as "Lead vs signature IDS".

## 1. Port scan — the strongest case (recon ramp)

```bash
SERVER=100.x.y.z
nmap -sS -p1-65535 -T3 $SERVER          # SYN scan; -T2 for a slower, stealthier ramp
```
Expect: destination-port fan-out and port-entropy climb → risk rises **during** the
scan, before it finishes. The stealthy `-T1`/`-T2` scan is the headline
differentiator — it stays under a simple rate threshold while the trajectory model
still flags the rising fan-out.

## 2. SSH / FTP brute force

```bash
hydra -l root -P rockyou.txt ssh://$SERVER -t 4      # SSH
hydra -l admin -P rockyou.txt ftp://$SERVER          # FTP
```
Expect: repeated connection attempts + failed-connection ratio → forecastable ramp.

## 3. DoS (rate-limited — do NOT overwhelm your own box)

```bash
hping3 -S --flood -p 80 $SERVER    # SYN flood; stop quickly. Or a bounded ab/wrk run.
```
Expect: detectable, but starts abruptly → shorter lead time (state this honestly).

## 4. Web attack (bypass Cloudflare — hit the app port on the tailnet IP)

```bash
# hit the ORIGIN app directly on the tailnet IP:port, NOT the Cloudflare hostname
nikto -h http://$SERVER:8080
sqlmap -u "http://$SERVER:8080/vuln?id=1" --batch
```
Expect: partial — depends on the run-up. Only meaningful when hit directly (Cloudflare
would hide the attacker's identity).

## 5. Differentiation vs a signature/threshold baseline

Run a trivial baseline alongside (e.g., "alert if >N new dst ports in 30 s") and show
the world model warns **earlier** on the slow scan, with a measured lead-time gap.

## What to claim (and not)

- ✅ "The model warned N seconds **before** the scan/brute-force completed."
- ✅ "It forecasts the reconnaissance ramp, where a threshold IDS only fires after."
- ❌ Do not claim it predicts a single-packet exploit with no run-up — nothing can.
- Note the lab→server domain shift: expect clean firing on blatant ramps (nmap,
  hydra), noisier on subtle cases.
