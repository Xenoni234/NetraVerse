# CLAUDE.md — SIH26153 Project Context

**This is the authoritative context file for this repository.** It is loaded at the start of
every session. Where this file and any other document disagree, **this file wins** — update it
first, then propagate.

- **Problem Statement:** SIH26153 — AI-based Network Attack Forecasting from Network Traffic Data
- **Event:** Smart India Hackathon 2026
- **Team size:** 6
- **My role in this repo:** Member 4 — core ML (models, training, inference)
- **Deadline:** 2026-09-30
- **Today:** 2026-09-14 → **16 days remaining**

---

## 1. Core thesis

We are building a **world-model-based** network attack forecaster. Unlike classifiers that map a
single flow to attack/benign, this system:

1. Learns `P(S_t+1 | S_t)` — the transition dynamics of network state over time
2. Rolls forward K steps to predict **future** network state
3. Scores **the predicted future** for infiltration probability — never the current input
4. Maps predicted state to MITRE ATT&CK stages (Recon, Initial Access, Lateral Movement, C2,
   Exfiltration)
5. Provides SHAP-based explanations with human-readable evidence

### The attacker-footprint idea

Attackers ramp up during reconnaissance in observable ways: **destination-port entropy climbs, new-peer
count grows, connection fan-out increases**. The world model learns these trajectory *shapes* and warns
before the compromise completes. That ramp is the thing we are betting on — if it does not exist in the
data, the premise fails, and we need to know that early (see §10).

---

## 2. Non-negotiable rules

These separate this project from generic AI coding. Violating one invalidates results.

| # | Rule |
|---|---|
| 1 | Every **risk** output comes from the **decoder's predicted future**, NEVER from the encoder output directly |
| 2 | The **persistence baseline** appears in every results table |
| 3 | **Warning lead time** (seconds before the labelled event) is the headline metric — **not F1** |
| 4 | **Never** a random train/test split. Chronological only |
| 5 | **Never** use flow-final features (bytes, duration) for a window that ends mid-flow |
| 6 | Model runs on **CPU as fallback**, CUDA when available |
| 7 | All weights + config reproducible from `configs/train.yaml` |
| 8 | Streamlit dashboard runs **offline** — no cloud API calls |
| 9 | Explanations are **human-readable sentences**, not raw feature indices |

---

## 3. Datasets

Google Drive folder (shared, owner `soham152006@gmail.com`):
<https://drive.google.com/drive/folders/1GVfomZ86CzxVlludfSJzOCPtCqxTRENI>
→ `Dataset SIH/` → `SIH 2026 dataset/`

Colab mount path used by the team: `/content/drive/MyDrive/SIH 2026 dataset/`

| Dataset | Location | Size | Role |
|---|---|---|---|
| CIC-IDS2017 | `MachineLearningCVE/`, `TrafficLabelling/` (8 CSVs each) | ~500 MB | Dev loop / fast iteration |
| **CIC-IDS2018** | `csv_features/` (10 CSVs) | ~6.5 GB | **PRIMARY training set** |
| CIC-IoT-2023 | `CSV/`, `Merged_CSV/` (63 merged files) | ~15 GB | Secondary |
| CTU-13 | `archive/` (13 `.binetflow.parquet`) | ~130 MB | C2 / botnet trajectories |
| UNSW-NB15 | `unsw_nb15/` (`UNSW-NB15_1..4.csv`, training-set/testing-set) | — | **Cross-dataset test target** |
| DARPA-OpTC | `DARPA-OpTC/` (`2019-09-16/18/25.tar`) | ~140 GB | Stretch — host telemetry |
| LANL | `LANL/` (`auth/proc/flows/dns/redteam .txt.gz`) | — | Stretch — lateral movement labels |

> **Drive access status (checked 2026-09-14).** Both folders resolve and are shared with this
> account, but the connector **cannot enumerate any files inside** `SIH 2026 dataset/` — it returns
> empty, and a title search for `CIC` / `UNSW` / `CTU` / `OpTC` returns nothing. Two likely causes,
> both worth checking: (a) the contents were shared as a *view* of someone else's folder and are not
> indexed for this account; (b) the folder is genuinely still being populated.
>
> **Related, and more urgent:** the folder is **"Shared with me"**, not in My Drive. Colab's
> `drive.mount()` only mounts **My Drive** — so `/content/drive/MyDrive/SIH 2026 dataset/` will
> **not** resolve as written. Someone needs to right-click the folder in Drive →
> *Organise* → *Add shortcut to Drive* → **My Drive**. The shortcut then appears under
> `/content/drive/MyDrive/`. Worth confirming before anyone burns a session debugging a path.

---

## 4. Feature schema (locked)

### Flow-level (from CICFlowMeter output)
`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`
`syn_count`, `ack_count`, `fin_count`, `rst_count`, `psh_count`, `urg_count`
`fwd_bytes`, `bwd_bytes`, `fwd_packets`, `bwd_packets`
`flow_duration`, `iat_mean`, `iat_std`, `iat_max`
`fwd_bwd_ratio`, `packets_per_second`, `bytes_per_second`

### Packet-level (from PCAP via TShark, when available)
`ttl_mean`, `ttl_variance`
`tcp_window_mean`, `tcp_window_std`
`fragment_flag_count`
`payload_size_mean`, `payload_size_std`
`retransmission_count`

### Behavioral (computed over sliding windows)
`dst_port_entropy` (per host, per window)
`new_peer_count` (destinations not seen in last 7 days)
`off_hours_ratio`
`fan_out_count` (unique destination IPs)
`baseline_deviation` (Δ from per-host 7-day baseline)
`trajectory_velocity` (derivative of key features)

> **OPEN — blocks the locked schema.** The model spec says `input = 45 features`. The lists above
> total **31 numeric** (17 flow numeric + 8 packet + 6 behavioral) plus 5 identity columns = 36.
> **14 features are unaccounted for.** See §9-B. Do not invent them.

---

## 5. Window parameters (locked)

| Parameter | Value |
|---|---|
| Window size | **30 s** |
| Stride | **10 s** (overlapping, 3-deep) |
| History length `L` | **10 windows** (5 minutes of history) |
| Forecast horizons `K` | **[1, 2, 4]** → **30 s / 60 s / 120 s** ahead |

> **Reading of the horizon/stride interaction** (confirm — §9-A): the decoder step is **30 s = one
> window length = 3 strides**, not one stride. The decoder unrolls **4 steps** (t+30, t+60, t+90,
> t+120) and `K=[1,2,4]` selects steps 1, 2 and 4 → +30 s, +60 s, +120 s. Windows are still *emitted*
> every 10 s; the *forecast* advances in 30 s jumps. This is the only reading consistent with both
> "stride 10 s" and "K=[1,2,4] = 30s/60s/120s".

---

## 6. Labelling schema (per 30-second window)

| Label | Definition |
|---|---|
| `binary_label` | 0 (benign) or 1 (attack) |
| `attack_family` | from dataset, e.g. `SSH-BruteForce`, `Botnet`, `Infiltration` |
| `attt_stage` | from the ATT&CK mapping in `src/mitre/stage_mapping.py` |
| `distance_to_attack` | number of windows until the next attack (used for trajectory training) |

---

## 7. Dataset splits

- **Chronological only**, never random shuffle
- **Campaigns kept together** — an attack episode stays in one split
- **Train 60% / Val 20% / Test 20%**
- **Plus: held-out attack family** — train excludes one family entirely; test is only that family

---

## 8. Model architecture

LSTM encoder-decoder with three heads on the decoder output.

```
Encoder: 2-layer LSTM, hidden=128, input = 45 features x 10 windows
   -> context vector (batch, 128)

Decoder: 2-layer LSTM, hidden=128, generates 4 future state vectors
         (t+30s, t+60s, t+90s, t+120s)
   -> scheduled sampling (teacher forcing -> self-rollout)
   -> per-horizon output: predicted state vector (batch, K, 45)

Heads (on decoder output at each horizon):
  State head: Linear -> (mean, log_variance) per feature   -> Gaussian NLL loss
  Risk head:  Linear -> sigmoid -> P(infiltration in next K windows) -> BCE per horizon
  Stage head: Linear -> softmax over 6 classes             -> CE per horizon
              (5 ATT&CK stages + benign)
```

**Combined loss:** `L = λ_state·L_state + λ_risk·L_risk + λ_stage·L_stage`
Start weights: **λ_state = 1.0, λ_risk = 2.0, λ_stage = 1.0**

**Inference:** MC-dropout — dropout stays on at inference, **20 forward passes**, return mean + std.

### Stage classes (6)
`0 BENIGN`, `1 RECON`, `2 INITIAL_ACCESS`, `3 LATERAL_MOVEMENT`, `4 C2`, `5 EXFILTRATION`

---

## 9. Evaluation harness

### Report per horizon (K=1, K=2, K=4)
- Precision, Recall, F1
- **Precision-Recall AUC** (not ROC-AUC — class imbalance)
- False positive rate at fixed operating points
- **Warning lead time distribution (histogram)** ← the headline

### Report across three test conditions
1. **Known attacks** — chronological test split
2. **Held-out attack family**
3. **Cross-dataset** — trained on CIC-IDS2018, tested on UNSW-NB15

### Required ablation rows
| Row | Proves |
|---|---|
| Logistic Regression baseline | classical ML bar |
| **Persistence baseline** | mandatory in every table |
| Full LSTM encoder-decoder | the system |
| **Encoder-only (decoder disabled)** | **forecasting adds value** |
| Flow-only features (no packet features) | packet features earn their cost |
| Ordered vs shuffled history | the model reads dynamics, not a host fingerprint |

---

## 10. Open questions — blocking, need a decision

**A. Horizon step size.** Stated reading in §5 (decoder step = 30 s = 3 strides). Confirm or correct.
*Blocks:* windowing, sequence construction, every metric label.

**B. The 45-feature list.** 14 of 45 are unaccounted for (§4). Need the missing names, or a decision
to lock the schema at 31 numeric features and set `input_size=31`.
*Blocks:* `unified_schema.FEATURE_COLUMNS`, encoder input size, the parquet cache.

**C. The 7-day baseline is impossible on the primary datasets.** `new_peer_count` ("not seen in last
7 days") and `baseline_deviation` ("per-host 7-day baseline") both assume ≥7 days of history.
CIC-IDS2017 is **5 capture days**; CIC-IDS2018 is ~10 days but split across separate captures with
no continuity; UNSW-NB15 is ~31 hours. A literal 7-day lookback yields an empty baseline for most
hosts.
*Proposal:* define the baseline as a **trailing max-available window, capped at 7 days**, with an
explicit `baseline_warmup` flag; exclude warm-up windows from training and report how many were
dropped. Needs a yes/no.

**D. Rule 5 conflicts with using CICFlowMeter CSVs at all.** "Never use flow-final features (bytes,
duration) for a window that ends mid-flow" is correct and important — but every row in a CIC CSV
*is* a flow-final record. A flow that starts at t=25 s and ends at t=95 s has `flow_duration=70 s`
and total byte counts that are only knowable at t=95 s. Assigning that row to the 30 s window by its
**start** time leaks 65 s of future into that window.
*Proposal:* assign each flow to the window containing its **end** time, so every feature is known by
window close; a long flow then contributes nothing to the windows it spans, which is the honest
behaviour. The alternative — re-deriving sub-flow counters from PCAP — is correct but expensive and
only possible where PCAPs exist. Needs a decision; it changes `windowing.py` and the meaning of
every volume feature.

**E. DoS/DDoS have no stage in the six-class scheme.** The five ATT&CK stages are Recon, Initial
Access, Lateral Movement, C2, Exfiltration. DoS and DDoS are none of them — and they are a **large
fraction of attack windows in CIC-IDS2017/2018**, the primary training data. Mapping them to
Exfiltration would be flatly wrong.
*Currently implemented:* `stage_mapping.STAGE_MASKED = -1`. Those windows keep `binary_label = 1`
and train the **risk head**, but are masked out of the **stage-head** loss.
*Alternatives:* (a) add a 6th ATT&CK stage `IMPACT` (TA0040) → 7 classes; (b) drop DoS/DDoS windows
entirely (loses a lot of data and the easiest attacks to forecast). I recommend (a) if the stage
head matters for the demo, masking otherwise. Needs a decision.

---

## 11. Working agreements

- **Do NOT** tell me to edit env files, run git commits, or execute terminal commands — I do those
  manually.
- **End every response** with a `## Commands for me to run` section listing exactly what to paste
  into PowerShell.
- Prefer showing the delta and the reasoning over re-explaining settled decisions.
- Flag conflicts with this file rather than silently resolving them.

---

## 12. Repo conventions

- `pathlib.Path` everywhere, never string paths. All roots come from `src/data/paths.py`.
- pandas + pyarrow (parquet). CSV only at the raw-ingest boundary.
- PyTorch ≥ 2.0; CPU fallback mandatory (`src.models.get_device`).
- Configs via OmegaConf/Hydra — no hard-coded hyperparameters in `src/`.
- Type hints required on every public function.
- Scaffold state: every module has its docstring, signatures and TODOs; bodies raise
  `NotImplementedError`. Tests are `@pytest.mark.skip`-ed until their module lands.
