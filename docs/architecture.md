# Architecture

Two pages on how the system works and why it is built this way. Design
*decisions* and locked schemas live in [DESIGN.md](../DESIGN.md); this document
explains the *shape* of the code.

---

## 1. The idea in one paragraph

An IDS tells you an attack is happening. This system tells you one is *about to*.
It watches per-host traffic in 30-second windows, feeds the last ten windows to a
sequential **world model**, and asks the model to simulate the next 10-40 seconds
of network state. From that simulated future it reads off three things: how the
traffic will look, how likely an attack is, and which MITRE ATT&CK stage it
would belong to. The gap between the alert and the real attack is the **lead
time** — the quantity the whole design optimises for.

---

## 2. Data flow

```
 raw datasets (CIC-IDS2017/2018, UNSW-NB15, CTU-13) + optional PCAP
        |
        |  src/data/loaders.py          per-dataset quirks absorbed here
        v
 unified flow records                   src/data/unified_schema.py  [LOCKED]
        |
        |  src/data/windowing.py        30 s windows, 10 s stride, per entity
        v
 per-(entity, window) rows
        |
        |  src/features/*               32 features  [LOCKED]
        |    extractor.py        volume, rate, fan-out, protocol, flags, shape
        |    packet_features.py  optional TShark enrichment
        |    baselines.py        deviation from own + peer normality
        |    trajectory.py       first derivatives
        v
 feature frame
        |
        |  src/data/labeller.py         is_attack, attack_stage, dist_to_attack
        v
 labelled windows  ->  data/processed/<dataset>/windows.parquet
        |
        |  src/data/windowing.build_sequences
        v
 X (N, 10, 32)  |  Y_state (N, 3, 32)  Y_risk (N, 3)  Y_stage (N, 3)
```

Everything up to the parquet cache is built once by
`scripts/extract_features.py`. Training reads the cache.

---

## 3. The model

```
x: (B, 10, 32)
   |
   v
Encoder LSTM ------------------> h_L   (summary of ~100 s of history)
   |
   v
Decoder LSTM, unrolled 4 steps, autoregressive
   |
   |  at each step k:
   +--> StateHead -> x_hat_{t+k}  (B, 32)   Huber loss
   +--> RiskHead  -> logit        (B,)      BCE, pos-weighted
   +--> StageHead -> logits       (B, 7)    CE, class-weighted
```

**Why encoder-decoder rather than a classifier with three outputs.** A classifier
maps history straight to a label per horizon. It never has to represent *what the
network will look like*, so it has no mechanism for simulating a future, no way
to compound reasoning across steps, and nothing an analyst can inspect. The
decoder is forced to produce a feature vector good enough to condition its own
next prediction on — that constraint is what makes the learned representation a
model of network dynamics rather than a lookup table of attack signatures. It is
also what enables [forward simulation](#5-inference) and trajectory matching.

The `encoder_only` ablation exists precisely to test whether that claim survives
contact with data. If it does not, we report that.

**Scheduled sampling.** During training the decoder is fed its own predictions
with a probability that ramps from 0 to ~0.9 (`src/training/scheduled_sampling.py`).
Without it the model only ever sees ground-truth inputs and falls apart at
inference, when it must consume its own errors for four steps. This is the single
most important training detail in the project.

**Multitask loss.** `L = 1.0*state + 3.0*risk + 0.5*stage`. Risk is weighted
highest because it is the product goal; the state loss is the auxiliary task that
forces genuine dynamics learning; the stage loss makes the output actionable.

---

## 4. Training

`src/training/train_loop.py`, driven by `scripts/train.py`.

- **Splits** come from `src/eval/splits.py` and are chronological,
  campaign-atomic, with one attack family held out entirely. `assert_no_leakage`
  runs before a single gradient step.
- **Scaling** is robust (median/IQR), fit on train only, stored in the checkpoint.
- **Validation runs free-running** — teacher forcing off — because that is the
  regime inference faces.
- **Monitoring** is on `val/risk_f1_k1`, not the loss; the multitask loss minimum
  does not coincide with the best forecaster.
- **Checkpoints are self-sufficient**: weights, model config, scaler state, class
  weights, chosen threshold, schema version, git SHA.

---

## 5. Inference

```
history -> forward_sim.simulate(K steps, free-running)
              |
              +--> uncertainty.mc_dropout_simulate   T stochastic rollouts
              |        -> confidence band per step
              |
              +--> trajectory_match.match            vs. known campaigns
              |        -> "resembles Tuesday PortScan, similarity 0.84"
              |
              +--> explain.shap_wrapper              SHAP on the risk head
                       -> explain.human_readable     -> English sentences
```

Three deliberate choices here:

**MC-dropout, not a point estimate.** Asking someone to act before anything has
happened requires telling them how sure the model is. A widening band with
horizon is honest and useful; a bare number is neither.

**Trajectory matching operates on the *simulated* future.** This is something a
classifier structurally cannot do, and it is the clearest demonstration that the
world-model framing buys something real.

**Explanations are template-based, not generated.** Deterministic, auditable,
offline, and incapable of inventing a hostname.

---

## 6. Evaluation

`src/eval/harness.py` produces one report containing:

- per-horizon F1, precision, recall, PR-AUC, FPR (`metrics.py`)
- the lead-time distribution **with its miss count** — a median lead time quoted
  without the miss rate is misleading
- two false-positive views: windowed FPR and benign-hours-per-false-alarm
- stage macro-F1 and a kill-chain-ordered confusion matrix
- both must-beat baselines, run under identical preprocessing
- the ablation table, each with a hypothesis recorded *before* the run

The test split is touched once. Everything else happens on validation.

---

## 7. Demo

`demo/app.py` (Streamlit) replays a recorded campaign from precomputed
artefacts — predictions parquet, cached SHAP, trajectory library. It never
trains, never loads a raw dataset, and never computes SHAP live. The replay
controller enforces that at step *t* the UI can only see windows `<= t`, so the
risk curve on screen is a genuine forecast rather than a plot of the answer.

---

## 8. What could go wrong

Honest list, kept current:

| Risk | Mitigation |
|---|---|
| Overlapping windows leak across splits | 14-window gap buffer + `assert_no_leakage` |
| Model keys on host identity, not dynamics | `shuffled_time` ablation must collapse |
| Baselines contaminated by the attack they measure | trailing rolling window, `closed="left"` |
| Error compounding makes k=4 useless | scheduled sampling; report per-horizon, never averaged |
| Great F1, useless lead time | lead time is a first-class metric, not an afterthought |
| Great numbers on one dataset only | per-dataset breakdown + held-out attack family |
| Demo works only on the cherry-picked campaign | campaign picker exposes all of them |
| CTU-13 lacks fwd/bwd split | imputation rule must be documented before use |
