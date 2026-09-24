# All-IPs live capture (ARP mirror) + live decision theater

**Authorized testing on your own network only.**

The gateway is a **TP-Link Archer A6 V4** (Broadcom) — **no OpenWrt support**, so a
clean router-side `tcpdump` is not possible. We capture all-IPs traffic by **ARP
mirroring** from the sensor instead: no router change, fully reversible.

## 1. One-time install on the sensor

```bash
sudo apt install -y ettercap-text-only   # preferred (auto re-ARPs on exit)
# fallback: sudo apt install -y dsniff
# cicflowmeter must be able to capture raw packets:
sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f /opt/netraverse/.venv/bin/python)"
```

## 2. Start the all-IPs capture

```bash
sudo /opt/netraverse/agent/arp_mirror_capture.sh wlp0s20f3 192.168.0.1 /home/aayush-gupta/nv_flows_live
```

This puts the sensor between the gateway and every LAN device, enables IP
forwarding (so the LAN stays online), and writes CICFlowMeter flows to
`nv_flows_live/live.csv`. **Ctrl-C restores the network** (re-ARP + forwarding off).

Caveats (honest): ARP mirroring adds latency and the sensor forwards all LAN
traffic (a bottleneck under heavy load); with IP forwarding the sensor may see a
forwarded copy of some packets (mild volume inflation — relative patterns hold);
device↔device traffic that never crosses the gateway is not captured.

## 3. Point the forecaster and API at the live capture

```bash
# forecaster (writes reports/live/state.json)
NETRAVERSE_CAPTURE_TZ=Asia/Kolkata \
  /opt/netraverse/.venv/bin/python /opt/netraverse/scripts/live_forecast.py \
  --flows /home/aayush-gupta/nv_flows_live --interval 30 --entity-granularity src_ip

# API already runs as the nv-api user service; it needs the live env to serve the
# live decision theater. These are baked into ~/.config/systemd/user/nv-api.service:
#   NETRAVERSE_LIVE_FLOWS=/home/aayush-gupta/nv_flows_live
#   NETRAVERSE_LIVE_CHECKPOINT=/opt/netraverse/models/wm_server/best.ckpt
#   NETRAVERSE_OPERATOR_TOKEN=netra2026
systemctl --user restart nv-api
```

## 4. The live decision theater

On the **Live** page, select an alerting host → the **Live decision theater**
shows model-simulated containment options (block / isolate / rate-limit) with each
option's **projected Δrisk** (the world model run as if that action were applied,
projected forward with persistence). Click **Enforce (real)** → preview the exact
nft/router rule → **Approve** → the rule is applied for real (operator token,
TTL auto-rollback), and the live risk graph falls on the next windows.

Recalibrate the LAN threshold on ~30–60 min of benign capture first
(`scripts/calibrate.py`), and never block a management IP (guarded).
