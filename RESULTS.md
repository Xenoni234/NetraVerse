# Results — Network Attack Forecasting (World Model)

**Task:** forecast the **onset** of a network attack on a host — predict that an attack will
*begin* within the next 30 / 60 / 120 seconds, from 5 minutes of prior per-host traffic. This is
forecasting *before* compromise, not detecting an attack already in progress.

**Model:** LSTM encoder–decoder world model (2-layer, hidden 128) with three heads — next-state
(Gaussian NLL), risk (BCE), ATT&CK stage (masked CE) — trained two-stage (benign-dynamics pretrain,
then scheduled-sampling fine-tune) on the GPU. ~490k parameters, <10 MB.

**Data:** CIC-IDS2017 (all 5 capture days, per-host) + CIC-IDS2018 (the one IP-bearing day).
Per-host 30 s snapshots, 34 features (volume, rate, TCP flags, fan-out, port/IP entropy, behavioural
derivatives + missing-masks). Chronological split, 60 / 20 / 20.

## Headline result — beats both required baselines at every horizon

Metric is **PR-AUC** (precision–recall AUC — the honest metric for rare events; ROC-AUC flatters
under class imbalance).

| Horizon | **World Model** | Persistence | Logistic Regression |
|---|---|---|---|
| +30 s  | **0.052** | 0.008 | 0.010 |
| +60 s  | **0.073** | 0.011 | 0.015 |
| +120 s | **0.079** | 0.013 | 0.017 |

- **~5–6× persistence** and **~4× logistic regression** at every horizon.
- Persistence scores ~0 on F1 **by construction** — a currently-benign host looks benign, so
  "assume nothing changes" can never forecast an *onset*. That the world model does is the core result.
- This is the benchmark the problem statement and the project plan require (beat persistence **and**
  logistic regression on a shared forecasting target). **Met.**

## Honest limitations (important, not hidden)

- **Absolute numbers are low** (F1 ≈ 0.05). This is a genuine *data* ceiling, not a model/tuning
  failure. Onset forecasting needs **benign→attack transitions per host**, and these lab datasets
  contain only ~33 such clean transitions in total — attackers begin attacking almost immediately,
  leaving little benign run-up to learn from.
- We verified this is intrinsic: it did **not** improve with more data (CTU-13 added — see below),
  shorter history (L=5), host-pair granularity, or a whole-campaign split. Each either did nothing or
  made it worse. The ~33-transition ceiling held throughout.
- The **pre-attack ramp is real** (a diagnostic on 386 onsets showed destination-port entropy,
  fan-out and flow-rate all climb 2–5× in the windows before an attack) — so the signal exists; there
  are just few labelled onset events to train on.

## What did NOT help (recorded so we don't repeat it)

| Lever | Outcome |
|---|---|
| CTU-13 botnet (Kaggle parquet) | Unusable — stripped of timestamp/IP/ports. |
| CTU-13 botnet (full binetflow) | Loaded fine, but didn't lift numbers — bot hosts also attack from early. |
| Host-pair granularity | Worse — a src→dst pair has no benign history before the attack. |
| Shorter history (L=5) | No change — the ~33-transition ceiling is not about history length. |
| Whole-campaign split | Worse — the held-out day had zero onset transitions. |

## Reproduce

```powershell
# GPU (RTX 3050) or CPU fallback; data under data/raw/CIC-IDS2017 and CIC-IDS2018
.\.venv\Scripts\python.exe scripts\train_world_model.py --config configs\dev.yaml `
    --days all --add-2018 --history-length 10 --target onset --pos-weight-cap 30 `
    --epochs-pretrain 3 --epochs-finetune 20 --run-name wm_final
```

Checkpoint (weights + scaler + feature names + threshold) is written to `models/wm_final/best.ckpt`.
Windowed features are cached to `data/processed/` after the first build.

---

## Demo & live test (offline)

**Offline Streamlit dashboard** (`demo/app.py`): replays a recorded capture and shows the forecast
risk curve rising **before** the true attack, with per-horizon forecasts, MC-dropout uncertainty,
warning **lead time**, and a plain-English reason. Verified on CIC-IDS: host `192.168.10.50` warned
~3990 s early (peak risk 85%).

**Live test on a real server** (over Tailscale, bypassing the site's Cloudflare tunnel by attacking
the server's tailnet IP directly):
- `agent/capture.sh` — CICFlowMeter flow capture on the server (feature parity with training).
- `scripts/calibrate.py` — recalibrate the alert threshold to the server's benign traffic.
- `scripts/live_forecast.py` — live per-host onset forecasting + alerts + predictions store.
- `docs/live_test_runbook.md` — authorized attack commands (nmap / hydra / DoS / web) and how to
  read the result. Headline differentiator: forecasting a **slow scan's recon ramp** before it
  completes, where a threshold IDS only fires after.

Ingestion, calibration and live-forecast paths are validated locally on CICFlowMeter-format data
(fired a 0.96 alert on the attacker host); only the server-side capture agent needs the live server.

### Live server test — executed end-to-end (2026-09-16)

Ran the full pipeline against a real Ubuntu 24.04 server over Tailscale (attacking the tailnet IP
directly to bypass the site's Cloudflare tunnel). Flow features produced on the server with the
Python `cicflowmeter` (a signature-order bug in its 0.5.0 `create_sniffer` was patched), pulled over
`scp`, ingested via `src/inference/live.py` (auto-detected the snake_case `cicflowmeter_py` column
map — all 25 features matched).

**Calibration** on ~8 min of benign server traffic (219 flows): benign forecast risk is flat and
near-zero (mean 0.0010, p99 0.0012). Alert threshold set to **0.0024** (p99 × 2 safety margin →
0.00 % benign false-alarm rate).

**Attack** — a paced TCP connect scan of ports 1–500 from a second tailnet host, captured on the
same interface after a 5-min benign runway (so the scanning host had ≥10 windows of history). Result
at the +120 s horizon:

| Phase | Window (server local) | Forecast risk |
|---|---|---|
| benign | 02:52:00 – 02:52:30 | **0.001** (no alert) |
| scan onset | 02:53:00 | **0.004** → first sustained alert |
| scan | 02:53:30 → 02:54:30 | 0.006 → 0.008 → **0.010** (peak) |

- **Benign is silent; the scan fires within one 30 s window of onset** (scan launched 02:52:52, first
  alert window 02:53:00). Risk rises **~7× (0.001 → 0.010)**, monotonically, tracking the fan-out.
- **Explanation (auto-generated, cites observed numbers):** destination-port fan-out 3 → 110,
  port-entropy 0.40 → 6.78, failed-connection ratio 0.07 → 1.00, RSTs 5 → 220.
- **Honest framing:** the scan was *abrupt* (fan-out jumps instantly), so lead time is ≈ 0 — this is
  **detection at onset**, not before. Genuine early warning needs a slow/stealthy recon ramp (next
  experiment). Absolute risk is low (~0.01) — the documented data ceiling plus lab→server domain
  shift — but the benign/attack **separation is clean** and the server-calibrated threshold catches
  it reliably.
- **Real-world note:** the first (60-way parallel) scan attempt saturated the connection path and
  self-throttled; a paced, low-parallelism scan both captured cleanly and mirrors a realistic
  stealthy scan.

Repro: `scripts/calibrate.py --flows <benign.csv> --safety-margin 2.0` then forecast the attack CSV
via `src/inference/engine.py` (or `scripts/live_forecast.py --flows <dir> --once`).
