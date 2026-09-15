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
