# Live SIH demonstration runbook

This runbook is for the authorized Tailscale lab only. It assumes the monitored
Linux server is `100.72.80.52` and the operator device is `100.81.46.8`.

## Server setup

On the Linux server, capture the Tailscale interface with the same CICFlowMeter
feature contract used for training:

```bash
mkdir -p ~/nv_flows
sudo IFACE=tailscale0 CFM=/opt/CICFlowMeter/bin/cfm OUTDIR=~/nv_flows ./agent/capture.sh
```

Calibrate the checkpoint with at least 30 minutes of benign traffic before the
first demonstration. Then start the server-side forecaster and API:

```bash
python scripts/calibrate.py --flows ~/nv_flows --checkpoint models/wm_sih_demo/best.ckpt \
  --out models/wm_server/best.ckpt --entity-granularity dst_ip --target-host 100.72.80.52

NETRAVERSE_OPERATOR_TOKEN='use-a-long-random-token' \
NETRAVERSE_MANAGEMENT_IPS='100.81.46.8,100.72.80.52' \
NETRAVERSE_LIVE_DRY_RUN=1 \
python scripts/live_forecast.py --flows ~/nv_flows --checkpoint models/wm_server/best.ckpt \
  --interval 5 --mc-samples 8 --entity-granularity dst_ip --target-host 100.72.80.52
```

In another server terminal:

```bash
NETRAVERSE_OPERATOR_TOKEN='use-a-long-random-token' \
NETRAVERSE_ALLOWED_ORIGIN='http://100.81.46.8:5173' \
uvicorn api.server:app --host 100.72.80.52 --port 8000
```

Keep `NETRAVERSE_LIVE_DRY_RUN=1` until the dashboard preview and rollback path
have been demonstrated. Real enforcement additionally requires
`NETRAVERSE_LIVE_ENFORCE=1` and Linux `nftables` permissions.

## Operator dashboard

From the repository on the operator device:

```bash
cd frontend
npm run dev -- --host 100.81.46.8
```

Open `http://100.81.46.8:5173/live`. The frontend automatically selects
`http://100.72.80.52:8000` when it is opened on the operator IP. For another
operator hostname, use `/live?api=http://100.72.80.52:8000` or set
`window.NV_API_BASE` before loading the page.

The browser must have the same operator token used by the API. The live page
shows the +30/+60/+120-second risks, early-warning state, confirmed state,
robust-scaled feature evidence, action preview, approval, TTL and rollback.

## Validation procedure

Before each scenario, record a marker and note the exact start time:

```bash
python scripts/live_run_marker.py --scenario recon --phase start \
  --expected-stage RECON --host 100.72.80.52
```

Run only bounded, authorized traffic generators against the lab. Suggested
scenario categories are:

| Scenario | Controlled behaviour | Expected response |
|---|---|---|
| benign | normal background traffic | continue monitoring |
| recon | gradual service/port fan-out | restrict targeted port or source |
| initial_access | bounded authentication/service probing | restrict service and review auth |
| execution | controlled application/request pattern | preserve evidence and restrict service |
| c2 | periodic beacon-like requests to a lab endpoint | block destination/egress |
| lateral_movement | bounded fan-out across isolated lab services | restrict east-west traffic |
| impact | rate-limited SYN/HTTP load | rate-limit the attack port |

After the traffic run stops, record the stop marker:

```bash
python scripts/live_run_marker.py --scenario recon --phase stop \
  --expected-stage RECON --host 100.72.80.52
```

Do not use an unbounded flood or a destructive exploit. A single abrupt event
is a detection test, not an early-forecast test; ramping traffic is required to
demonstrate lead time.

## What to record for SIH

For each run, export:

- marker start time
- first `EARLY_WARNING`
- first `CONFIRMED_ALERT`
- operator approval time
- firewall application time or dry-run time
- measured traffic reduction
- rollback time
- measured lead time against the marker

The live system has 30-second measurement resolution. Report median lead time
and the percentage of runs with positive lead time; do not claim precision finer
than the observation window.
