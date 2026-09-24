# Multi-attack test matrix (server + LAN)

Authorized testing of **your own** network only. Validates that the forecaster
warns before compromise across attack types, not just C2. All commands run on the
sensor (`ssh laptop`, `/opt/netraverse`).

## 0. One-time capture + benign calibration

Install the flow tool and fix its 0.5.0 arg-order bug (crashes otherwise):

```bash
cd /opt/netraverse
.venv/bin/pip install cicflowmeter
.venv/bin/python scripts/patch_cicflowmeter.py     # idempotent
```

Live capture needs raw-socket rights. Grant them once (sudo):

```bash
# let the venv python sniff without running the whole app as root
sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f /opt/netraverse/.venv/bin/python3)"
```

Start the capture agent writing rolling flow CSVs (pick the interface: `wlp0s20f3`
for the LAN, `tailscale0` for the Tailscale server):

```bash
cd /opt/netraverse
.venv/bin/cicflowmeter -i wlp0s20f3 -c ~/nv_flows_benign/live.csv    # benign baseline
```

Let **30–60 min of benign traffic** accumulate, then recalibrate the threshold
on it and restart the services (aborts if anything is alerting):

```bash
.venv/bin/python scripts/auto_recalibrate.py --flows ~/nv_flows_benign \
    --entity-granularity dst_ip --target-host 100.72.80.52 --safety-margin 2.0
```

Enable the weekly self-tuning timer (see `deploy/systemd/README.md`):

```bash
systemctl --user enable --now nv-recalibrate.timer
```

## 1. Live forecaster (real capture, not replay)

Point the capture at a live dir and run the forecaster in live mode:

```bash
# terminal A — capture live flows
.venv/bin/cicflowmeter -i wlp0s20f3 -c ~/nv_flows_live/live.csv
# terminal B — forecast every host it sees (LAN) — restart nv-live pointed here
python scripts/live_forecast.py --flows ~/nv_flows_live --interval 30 \
    --entity-granularity src_ip --mc-samples 0
```

For the single-server scenario use `--entity-granularity dst_ip --target-host 100.72.80.52`.

## 2. The matrix

Run each attack from an owned box the sensor can see; watch `/live` and `/topology`.
Record: **predicted MITRE stage**, **lead time** (alert time − attack-onset time),
detector `attack_now`, and whether an approved `enforce` action contains it.

| # | Attack | Script | Target | Expected stage | Notes |
|---|---|---|---|---|---|
| 1 | Recon / port-scan | `agent/ramp_scan.sh` | server & LAN host | **RECON** | dst-port fan-out + entropy ramp |
| 2 | Brute-force / initial access | `agent/ramp_bruteforce.sh` | server `:22` | **INITIAL_ACCESS** | rising conns on one port; do one real `ssh` after = compromise mark |
| 3 | DoS / flood | `agent/ramp_dos.sh` | server `:80` | **IMPACT** | rising SYN/pkt rate (bounded) |
| 4 | Exfiltration | `agent/ramp_exfil.sh` | collector `:9000` | **EXFILTRATION** | large asymmetric egress; `nc -lk 9000 >/dev/null` on collector |
| 5 | Lateral movement | `agent/ramp_lateral.sh` | LAN `/24` | **LATERAL_MOVEMENT** | fan-out to new internal peers |

Each script does a **benign runway** first (builds the L=10 history) then a gradual
ramp so the model can warn *before* the signature is obvious. Examples:

```bash
SERVER=100.72.80.52 ./agent/ramp_scan.sh
SERVER=100.72.80.52 ./agent/ramp_bruteforce.sh
SERVER=100.72.80.52 ./agent/ramp_dos.sh
COLLECTOR=192.168.0.199 PORT=9000 ./agent/ramp_exfil.sh
SUBNET=192.168.0 ./agent/ramp_lateral.sh
```

## 3. Pass criteria

- Each attack raises the target/attacker host to `EARLY_WARNING`/`CONFIRMED_ALERT`
  with the **expected stage** and a **positive lead time** over the benign runway.
- Benign windows stay **below threshold** (0 false positives after calibration).
- The two-tier LLM produces a stage-appropriate action; an approved `enforce`
  action on a **non-management** attacker IP creates a real `nft` rule and the
  attack's flows stop (verify `sudo nft list tables | grep nv_`; TTL auto-reverts).
- Fill the per-attack lead-time / stage results into `RESULTS.md`.
