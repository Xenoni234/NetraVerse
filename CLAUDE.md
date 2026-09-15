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

> **Data audit (2026-09-15, files now on disk).** Findings that shaped the build:
> - **CIC-IDS2017 `TrafficLabelling`** has Timestamp + Source IP + Label -> per-host forecasting.
>   The `MachineLearningCVE` copy has **no Timestamp** -> dropped (glob restricted to TrafficLabelling).
> - **CIC-IDS2018**: 9/10 day files are **IP-stripped** (80 cols, no Src/Dst IP); only the 3.9 GB
>   `Thuesday-20-02` file (84 cols, misspelled on disk) carries IPs. So 2018 cannot do per-host in general.
> - 2017 vs 2018 use **different column names** -> separate maps (`CICIDS2017_COLUMN_MAP`).
> - 2017 quirks handled in the loader: duplicate `Fwd Header Length` column; Windows-1252 en-dash in
>   the "Web Attack" labels (read as latin-1, matched by prefix).
>
> **Decision (user, 2026-09-15): snapshot unit = per computer (host).** Therefore the **primary
> training set is CIC-IDS2017 (TrafficLabelling)**; 2018 is whole-network extra + its one IP-bearing
> day; UNSW-NB15 stays the cross-dataset test. `configs/train.yaml` now trains on `cicids2017`.

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

> **RESOLVED 2026-09-15 (was open question B).** The "missing 14" was a malformed question. Per
> M3 §20, F is **derived, not decreed** — it is finalised only after categorical expansion and
> missing-value indicators are added. The gap to 45 is made of: (a) **protocol one-hot** — one
> `protocol` field becomes `[is_tcp, is_udp, is_icmp, is_other]` (M3 §15); (b) **missing-mask
> columns** — one flag per feature that can be absent, because "0" and "not observed" are different
> and conflating them is a bug (M3 §12). So `input_size` is read from the feature dictionary the
> state-builder produces, never hard-coded. The `input_size: 31` in the configs is a placeholder and
> will be overwritten once the dictionary exists.

---

## 5. Window parameters (locked)

| Parameter | Value |
|---|---|
| Window size | **30 s** |
| Stride | **30 s** (disjoint, back-to-back) |
| History length `L` | **10 windows** (5 minutes of history) |
| Rollout length | **4 windows** (simulate next 2 minutes) |
| Forecast horizons `K` | **[1, 2, 4]** → **30 s / 60 s / 120 s** ahead |

> **RESOLVED 2026-09-15 (was open question A).** Stride is **30 s disjoint**, per both research docs
> (M3 §10: "Compare 30-second disjoint windows first, with L = 10 and K = 2"; Workflow §5:
> "Window stride — 30 seconds"). My earlier 10-s-overlap guess was wrong and is retracted. With
> disjoint 30-s windows each decoder step is exactly one window, so `K=[1,2,4]` maps directly to
> +30 / +60 / +120 s with no re-indexing. History spans `L × 30 s = 300 s = 5 min`. The derived
> counts are unchanged: `min_windows_per_entity = gap_windows = L + max(K) = 14` (in window units).
> All three configs updated.

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

## 10. Decisions log

Updated 2026-09-15 after reading the three research PDFs (Member 3 feature doc, Member 4 world-model
doc, Workflow). User approved "go with the research recommendations" on the six-item plain-language
list (stride, horizons, leakage/no-peek, missing masks, defer OpTC, pretrain-normal-first).

**A. Horizon / stride — RESOLVED.** 30-s **disjoint** windows (stride = 30 s). See §5. My earlier
10-s-overlap guess was wrong and is retracted. All three configs updated.

**B. Feature count — RESOLVED.** F is derived, not decreed (§4). Protocol one-hot + missing-mask
columns close the gap to ~45; `input_size` comes from the state-builder's dictionary. `input_size:
31` in configs is a placeholder.

**D. Completed-flow leakage — RESOLVED (approach chosen).** Assign each flow to the window containing
its **end / availability** time, so every feature is known by window close; a long flow contributes
nothing to the windows it spans. This is the concrete form of the approved no-peek rule. The
partial-flow-from-PCAP alternative stays available where PCAPs exist but is not the default. Changes
`windowing.py` and the meaning of every volume feature — build it in from the start.

**F. Live deployment test — DEFERRED to Phase 6 / stretch.** User has an owned test server with full
access and wants to launch real attacks at it and watch the model forecast them (authorised testing
on their own infra). Decision: **replay demo is primary** (safe, always works); **live demo is
stretch**. Offline requirement is already satisfied by the design (no APIs, ~10 MB local model). The
real work for "live" is a **live feature pipeline**: sniff packets on the server → build the same
30-s flow windows in real time → feed the model. Same model, new input path. Only attacks with a
runway (scan, brute-force, botnet beaconing) can be forecast 30–120 s ahead; single-packet exploits
cannot, and we will not claim otherwise. Revisit only once the replay demo is solid.

> **F — EXECUTED end-to-end 2026-09-16 (see RESULTS.md "Live server test").** Ran the full pipeline
> against a real Ubuntu 24.04 server over Tailscale (attacked the tailnet IP to bypass Cloudflare).
> Flows via Python `cicflowmeter` (patched a signature-order bug in its 0.5.0 `create_sniffer`);
> ingested through `src/inference/live.py` (`cicflowmeter_py` column map). Calibrated on benign
> server traffic → threshold 0.0024 (p99 × 2 margin, 0 % benign FP). A paced port scan fired the
> first alert **within one 30 s window of onset**, risk rising ~7× (0.001 → 0.010) with correct
> feature attribution (fan-out 3→110, entropy 0.40→6.78, failed-conn 0.07→1.0). Honest limits:
> abrupt scan → ~0 lead time (detection at onset, not before); low absolute risk (data ceiling +
> domain shift) but clean benign/attack separation. Live artifacts in `data/live/`. **Landmines:**
> cicflowmeter writes timestamps in **server-local time** (not UTC); a **60-way parallel scan
> self-throttled** the client — use low parallelism (which also mirrors a stealthy scan).

---

**G. Forecast target = ATTACK ONSET (decided 2026-09-15, user-approved).** The first working model
trained on "attack ongoing" (future binary_label) and **lost to persistence** (F1 0.01 vs 0.40-0.59):
per-host, "attacking now" trivially predicts "attacking in 30s", so persistence wins. Reframed the
risk target to **onset** — at a currently-benign origin window, predict whether an attack *begins*
within k windows (from `distance_to_attack`). Persistence structurally scores ~0 on onset (a
benign-looking host -> "benign"), which is the point. `build_sequences(target="onset")` is the
default; `"ongoing"` kept for the ablation. This is the PS's "warn before compromise" and yields a
real lead-time number.

**Ramp confirmed (2026-09-15).** Diagnostic on 386 onsets: the 4 windows before an attack show
elevated `dst_port_entropy` (0.5-1.06 vs benign 0.0), `n_distinct_dst_port`, `n_distinct_dst_ip`,
`flows_per_sec` (2-5x). So onset IS forecastable — weak model performance is a tuning/feature issue,
not a data dead-end. Two dead features found and fixed: `new_peer_count` (now a true vectorised
never-before-seen-destination count) and the behavioural derivatives (re-pointed at the ramp:
`trajectory_velocity` = d(port-entropy), `baseline_deviation` = robust-z of flows/sec, floored+clipped).

**Results so far (2026-09-15, onset target, 2017 all-days + 2018 IP-day, pos_weight cap 30):**
world model **beats persistence and logistic regression at every horizon** — PR-AUC 0.052/0.073/0.079
at +30/60/120s vs persistence 0.008/0.011/0.013 and LR 0.010/0.015/0.017 (~5-6x persistence). The
required benchmark is met. Absolute numbers are low because **onset examples are scarce** (~33 clean
"attack-in-next-window" training positives): in CIC-IDS2017, per-host attackers have little benign
precursor. Main lever for higher absolute performance is **more onset examples** (more datasets /
finer entity granularity / wider pre-attack labelling), not more hyperparameter tuning. Focal loss
(`--risk-loss focal`) and windows caching are wired and ready. Checkpoints in models/wm_onset_v3/.

**CTU-13 loader PREPPED (2026-09-15, awaiting full data).** `loaders.load_ctu13` + `CTU13_COLUMN_MAP`
+ `stage_mapping.ctu13_family` are written for the ORIGINAL Stratosphere `.binetflow`
(StartTime/SrcAddr/DstAddr/Sport/Dport). Verified: label mapping (Botnet->C2, Normal/Background->
BENIGN) works, and the loader **rejects the stripped Kaggle parquet with a clear message**. When the
full data lands under data/raw/CTU-13/, it flows load->unify->label->window (Dur seconds->µs handled;
flag/IAT/pkt-len features unavailable -> filled 0; fan-out/ports/rate/entropy work). Untested against
real full data (none on disk yet).

**Dead-ends recorded (don't repeat):**
- **Host-pair granularity (src>dst) FAILED** for onset (4 train / 0 test positives). A pair has no
  benign history before the attack (it appears *at* the attack), so there are almost no benign->attack
  transitions to learn. Per-host (src_ip) is correct — a host exists and behaves benignly before it
  attacks. Best model stays the per-host v3 (beats persistence + LR).
- **CTU-13 (dhoogla Kaggle parquet) unusable** for the temporal model: stripped of timestamp, IPs and
  ports (flat-ML variant). Full `.binetflow` from Stratosphere IPS (stratosphereips.org/datasets-ctu13)
  would work; needs a fresh download.

**H. CIC-IDS2018 now included (user request).** Most 2018 days are IP-stripped, but the 3.9 GB
`Thuesday-20-02` day carries Source IP, so it joins per-host training via `--add-2018` (streamed with
a row cap to avoid OOM). Adds DDoS onset examples. The IP-less 2018 days remain whole-network-only
(future experiment).

### Still open (have a working default, not blocking the next step)

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

---

## 13. Dataset landmines (from the research docs — verify before trusting labels)

- **CIC-IDS2018 has documented label errors** (DistriNet / KU Leuven analysis, cited in M3 §9). Some
  traffic labelled brute-force actually reached a **closed** service — a failed TCP connection, not a
  credential attempt. Audit the `SSH-Bruteforce` / `FTP-BruteForce` labels before believing them.
- **CTU-13's full PCAP is not public** (privacy; M3 §9). Only botnet-only PCAPs + labelled
  bidirectional flows are available. So packet-level features on CTU-13 are partial — expect to run
  the flow-only path there.
- **Lab-schedule shortcuts** (M3 §15): attack days/times and fixed attacker IPs make the clock and
  the address near-perfect predictors *in the lab* that transfer to nothing. Keep IPs, dates,
  capture IDs out of model inputs (already enforced by `unified_schema.LEAK_COLUMNS`).

## 14. Two-stage training plan (from Member 4 research)

1. **Self-supervised pretrain** on benign traffic only — state head + Gaussian NLL, learns "what does
   normal look like next?" No attack labels. Exploits the large benign majority of the data.
2. **Supervised fine-tune** on labelled traffic — add risk + stage heads, scheduled sampling
   0.0 → 0.9, curriculum K=1 → 2 → 4.
   Plus: **high state-prediction error + high MC-dropout variance = unseen-attack signal**, reported
   independently of the risk head (Member 4 §6.3). This is the main generalisation argument for the
   held-out attack family.
