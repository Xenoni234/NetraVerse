# DESIGN — SIH26153: AI-Based Network Attack Forecasting (World Model)

> **Status:** DRAFT / scaffold. Sections marked **LOCKED** must not change without a team vote,
> because downstream code (feature extractor, windowing, model heads, eval harness) hard-depends
> on them. Everything else is open for iteration.

---

## 1. Problem Definition (from the Problem Statement)

**PS ID:** SIH26153

Conventional network defence is *reactive*: an IDS/IPS raises an alert once malicious traffic has
already been observed. The objective of this project is to be **predictive** — to forecast that an
attack is *about to happen* on a network segment, early enough that a human analyst or an automated
control can act before impact.

**Formal statement.**
Let `x_t` in `R^F` be the feature vector describing a monitored entity (host or host-pair) during
time window `t`. Given the history `(x_{t-L+1}, ..., x_t)`, learn a **world model** that predicts
the future evolution of the network state:

```
f_theta : (x_{t-L+1..t})  ->  { x_hat_{t+k} , r_hat_{t+k} , s_hat_{t+k} }   for k in K
```

where

- `x_hat_{t+k}` — predicted **next state** (feature vector) — the world-model / dynamics head
- `r_hat_{t+k}` — predicted **attack risk** in `[0, 1]` — the risk head
- `s_hat_{t+k}` — predicted **MITRE ATT&CK stage** (categorical) — the stage head

**What makes this a world model and not a classifier.** The model is trained to roll its own
predictions forward (K-step autoregressive simulation, with scheduled sampling during training).
That buys three things a plain classifier cannot: (a) a **lead time** — how many windows ahead we
fire; (b) a **simulated trajectory** an analyst can inspect; (c) **trajectory matching** — comparing
the simulated future against a library of known attack campaigns.

**Non-goals.** Payload inspection / DPI on encrypted traffic; automated blocking or active response;
line-rate real-time inference (we target near-real-time at the 10 s stride).

**Deliverable.** A trained model + an evaluation report + a Streamlit replay dashboard that shows,
for a recorded campaign, the forecast risk curve rising *before* the labelled attack window.

---

## 2. Feature Schema — **LOCKED**

Unit of observation: one **entity** (`src_ip`, or the `(src_ip, dst_ip)` pair for pairwise views)
aggregated over one **30 s window**. All datasets (CIC-IDS2017 / CSE-CIC-IDS2018, UNSW-NB15,
CTU-13) are mapped into this single schema by `src/data/unified_schema.py`.

### 2.1 Identity / index columns (not fed to the model)

| Column | dtype | Notes |
|---|---|---|
| `window_start` | `datetime64[ns, UTC]` | Inclusive left edge of the window |
| `window_end` | `datetime64[ns, UTC]` | Exclusive right edge (`window_start + 30 s`) |
| `entity_id` | `string` | `src_ip` or `src_ip>dst_ip`; the sequence key |
| `dataset` | `category` | `cicids2017` / `cicids2018` / `unsw_nb15` / `ctu13` |
| `campaign_id` | `string` | Capture-day / scenario id — splits never cut across this |

### 2.2 Model input features (`F = 32`)

**Volume (6)**
`n_flows`, `n_pkts_fwd`, `n_pkts_bwd`, `bytes_fwd`, `bytes_bwd`, `bytes_ratio_fwd_bwd`

**Rate (4)**
`flows_per_sec`, `pkts_per_sec`, `bytes_per_sec`, `mean_flow_duration_s`

**Fan-out / topology (5)**
`n_distinct_dst_ip`, `n_distinct_dst_port`, `n_distinct_src_port`, `dst_port_entropy`,
`dst_ip_entropy`

**Protocol mix (4)**
`frac_tcp`, `frac_udp`, `frac_icmp`, `frac_other`

**TCP flag / handshake health (5)**
`frac_syn`, `frac_syn_ack`, `frac_rst`, `frac_fin`, `failed_conn_ratio`

**Packet-size / timing shape (4)**
`mean_pkt_size`, `std_pkt_size`, `mean_iat_s`, `std_iat_s`

**Baseline deviation (2)** — from `src/features/baselines.py`
`zscore_bytes_vs_host_baseline`, `zscore_fanout_vs_peergroup`

**Trajectory / derivative (2)** — from `src/features/trajectory.py`
`d_bytes_per_sec_dt`, `d_fanout_dt`

> **Locked rules.**
> 1. Order is fixed by `unified_schema.FEATURE_COLUMNS` — index `i` means the same thing everywhere.
> 2. All features are `float32`, finite; NaNs filled with `0.0` **after** scaling.
> 3. Scaling: per-feature robust scaling (median / IQR) fit on the **training split only**.
> 4. No feature may use information from `t' > t`. Any lookahead is a bug, not a feature.
> 5. Adding a feature = appending to the end of the list + a bump of `SCHEMA_VERSION`.

`SCHEMA_VERSION = "1.0.0"`

---

## 3. Window Parameters — **LOCKED**

| Parameter | Value | Rationale |
|---|---|---|
| Window length `W` | **30 s** | Long enough for stable rate/entropy estimates, short enough that a scan is not smeared out |
| Stride `S` | **10 s** | 3x overlap, so 10 s forecast granularity |
| History length `L` | **10 windows** | 10 x 10 s stride ~ **100 s** of context; trains without vanishing gradients |
| Horizons `K` | **[1, 2, 4]** | +10 s / +20 s / +40 s ahead — the three numbers every metric is reported at |
| Min windows per entity | **L + max(K) = 14** | Shorter sequences are dropped, not padded |

Sample shapes produced by `src/data/windowing.py`:

```
X        : (N, L, F)    = (N, 10, 32)   float32   history
Y_state  : (N, |K|, F)  = (N, 3, 32)    float32   future feature vectors
Y_risk   : (N, |K|)     = (N, 3)        float32   future binary attack label
Y_stage  : (N, |K|)     = (N, 3)        int64     future ATT&CK stage id
```

Windows are built **per `entity_id`, in chronological order**, and never cross an `entity_id` or a
`campaign_id` boundary.

---

## 4. Labelling Schema — **LOCKED**

Implemented in `src/data/labeller.py`. Three labels per window, derived from the source dataset's
own ground truth.

### 4.1 Binary attack label

`is_attack` in `{0, 1}` — `1` if **any** flow in the window is labelled malicious by the source
dataset.

### 4.2 ATT&CK stage label

`attack_stage` in `{0..6}` — coarse kill-chain stage, mapped from the dataset's attack-family
string by `src/mitre/stage_mapping.py`.

| id | Stage | ATT&CK tactic | Example families |
|---|---|---|---|
| 0 | `BENIGN` | — | normal traffic |
| 1 | `RECON` | TA0043 Reconnaissance | PortScan, network scan |
| 2 | `INITIAL_ACCESS` | TA0001 Initial Access | Web attack, brute force (SSH/FTP), Heartbleed |
| 3 | `EXECUTION` | TA0002 Execution | Infiltration, exploit delivery |
| 4 | `C2` | TA0011 Command & Control | Botnet / CTU-13 bot channels |
| 5 | `LATERAL_MOVEMENT` | TA0008 Lateral Movement | internal scan / spread post-compromise |
| 6 | `IMPACT` | TA0040 Impact | DoS, DDoS, exfiltration |

### 4.3 Distance-to-attack label

`dist_to_attack` — number of **strides** from the current window to the start of the next attack
window for that entity. `0` inside an attack; `-1` encodes "no future attack" (infinity).

Derived flag used to train the risk head at long horizons:

```
is_pre_attack = 1  if  1 <= dist_to_attack <= PRE_ATTACK_HORIZON   (default 6 strides = 60 s)
```

> **Locked rules.**
> 1. Labels are computed on the **raw, unshuffled, time-ordered** frame.
> 2. The label for window `t` derives only from `[window_start, window_end)` — no smearing back.
> 3. `dist_to_attack` is computed per `entity_id` **and** per `campaign_id`.
> 4. A window is *never* relabelled to balance classes. Imbalance is handled by loss weights.

---

## 5. Dataset Splits — **LOCKED**

Implemented in `src/eval/splits.py`.

1. **Chronological.** Within every `campaign_id`, split by wall-clock time, never randomly.
   Train = earliest 70 %, Val = next 15 %, Test = latest 15 %.
2. **Campaigns kept together.** A `campaign_id` (a capture day / CTU scenario) is atomic: all of its
   windows land in the same split. This stops the model memorising a campaign's host set.
3. **One held-out attack family.** One entire attack family — default **`Infiltration`** — is
   removed from train and val and evaluated only on test, measuring zero-shot generalisation to an
   unseen attack type.
4. **Gap buffer.** A `L + max(K) = 14`-window gap is dropped at every split boundary, so no test
   window's history overlaps a training window.
5. **Scalers, class weights and thresholds are fit on train only**, then frozen for val/test.

| Split | Purpose | Selection rule |
|---|---|---|
| `train` | fit weights | earliest 70 % of each in-train campaign, held-out family removed |
| `val` | early stopping, threshold selection | next 15 %, held-out family removed |
| `test` | reported numbers, **touched once** | latest 15 % + all held-out-family windows |

---

## 6. Success Criteria

Reported by `src/eval/harness.py` at each horizon `k` in `{1, 2, 4}` on the **test** split.

### 6.1 Detection quality (risk head)

| Metric | Target (MVP) | Stretch |
|---|---|---|
| F1 @ k=1 (+10 s) | >= **0.75** | >= 0.85 |
| F1 @ k=2 (+20 s) | >= **0.65** | >= 0.78 |
| F1 @ k=4 (+40 s) | >= **0.55** | >= 0.70 |
| PR-AUC @ k=1 | >= **0.70** | >= 0.85 |
| Held-out-family F1 @ k=1 | >= **0.40** | >= 0.60 |

### 6.2 Lead time

Lead time = wall-clock seconds between the first window where `r_hat >= tau` (sustained for 2
windows) and the first truly malicious window of that campaign-entity.

| Metric | Target |
|---|---|
| Median lead time | >= **30 s** |
| P25 lead time | >= **10 s** (i.e. >= 75 % of campaigns are caught early at all) |
| Fraction of campaigns with lead time > 0 | >= **0.70** |

### 6.3 False positive rate

| Metric | Target |
|---|---|
| Windowed FPR on benign traffic | <= **0.02** |
| Benign hours per false alarm (alert-level, after 2-window sustain) | >= **4 h** |

### 6.4 Stage head

| Metric | Target |
|---|---|
| Macro-F1 over the 7 stages @ k=1 | >= **0.50** |

### 6.5 Must-beat baselines

The world model is only interesting if it beats **all three**:

- `baseline_persistence` — "next window = current window" (`src/models/baseline_persistence.py`)
- `baseline_lr` — logistic regression on the flattened `L x F` history
- encoder-only ablation — no decoder, no forward simulation

Ablations that must be reported (`src/eval/ablations.py`): encoder-only, flow-features-only (no
packet features), shuffled-time (sanity check — must collapse to chance).

---

## 7. Roles Per Team Member

| Role | Owns (code) | Owns (deliverable) |
|---|---|---|
| **Data Lead** | `src/data/*` — loaders, unified schema, labeller, windowing | Clean parquet cache for all datasets + `docs/attack_taxonomy.md` |
| **Features Lead** | `src/features/*` — extractor, packet features, baselines, trajectory | The locked 32-feature table + feature-sanity notebook |
| **Modelling Lead** | `src/models/*`, `src/training/*` | Trained checkpoints, training curves, scheduled-sampling ablation |
| **Inference & Explainability Lead** | `src/inference/*`, `src/explain/*` | K-step simulation, MC-dropout uncertainty bands, SHAP-to-English |
| **Evaluation Lead** | `src/eval/*`, `tests/*` | The one-page results table, lead-time plots, ablation table |
| **Demo & Docs Lead** | `demo/*`, `docs/*`, `README.md` | Streamlit replay dashboard + the 5-minute SIH pitch |

> Names to be filled in before the first sprint review. Every module has exactly one owner; PRs
> touching a **LOCKED** section need a second reviewer.

---

## 8. Open Questions

- [ ] Entity granularity: per-`src_ip` only, or also per-`(src, dst)` pair? (changes `N` by ~10x)
- [ ] Do packet-level features (`src/features/packet_features.py`) earn their cost, or is flow-only
      enough? — answered by the flow-only ablation.
- [ ] Is CTU-13's bot-channel labelling compatible with a 30 s window, or does it need 60 s?
- [ ] Loss weighting across state / risk / stage heads — fixed, or uncertainty-weighted?
