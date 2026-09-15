# Capture agent (server side)

Produces CICFlowMeter flow features from live traffic on the Tailscale server, so
the world model sees the **same feature shape it was trained on**. This is the one
piece that must run on the target server; everything else can run on your laptop.

## Why CICFlowMeter specifically

The model was trained on CIC-IDS flows, which come from **CICFlowMeter**. Using a
different flow tool changes the feature distribution and the model misbehaves. Use
CICFlowMeter for parity. `src/inference/live.py` auto-detects the exact header
variant and fills any missing feature with 0.

## Install on the server (Ubuntu/Debian, over SSH)

```bash
sudo apt-get update && sudo apt-get install -y tcpdump openjdk-17-jre-headless git
# Java CICFlowMeter (canonical, matches CIC-IDS):
git clone https://github.com/ahlashkari/CICFlowMeter /opt/CICFlowMeter
cd /opt/CICFlowMeter && ./gradlew build   # produces bin/cfm
```

Quicker fallback (Python port — easier, but confirm columns match; parity is weaker):
```bash
pipx install cicflowmeter   # then: cicflowmeter -i tailscale0 -c ~/nv_flows/live.csv
```

## Run

```bash
# sniff the tailnet interface so direct-to-IP attacks are visible as real flows
sudo IFACE=tailscale0 CFM=/opt/CICFlowMeter/bin/cfm OUTDIR=~/nv_flows ./capture.sh
```

Then, on the monitoring host (laptop or the server itself), point the forecaster at
that directory — pull it over Tailscale/SSH, or run the loop on the server:

```bash
python scripts/live_forecast.py --flows ~/nv_flows --checkpoint models/wm_server/best.ckpt
```

## Notes
- Sniff **`tailscale0`** so attacks sent to the server's tailnet IP (which bypass
  Cloudflare) appear as real per-host flows. `eth0` works for LAN attacks.
- Needs root for packet capture.
- ~30 s lag by design (one window). Fully offline.
