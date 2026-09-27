# NetraVerse: Architecture Document (PS 26153)

**Problem:** forecast *which hosts will be involved in attack activity in the next 5 minutes*, from network telemetry, early enough to act, and support the defender's decision. **Approach:** a latent **world model** learns how per-host network state evolves. It imagines the future and scores the *imagined* states.

## 1. Pipeline

```
CSV (CIC/CTU/UNSW) ─┐                                                   ┌─ Captum IG: "why" (every forecast)
PCAP (Scapy) ───────┼─► Feature fusion ─► World model ─► rollout 300 s ─┼─ MITRE stage (7 classes, TA00xx)
Live NIC (sniffer) ─┘   one schema,        RSSM-lite +     prior-only     └─ Rule engine ─► Accept/Modify/Reject
                        60 s host windows  GraphSAGE       imagination           │                 │
                                                                    counterfactual re-rollout   nftables (live)
```

- **One schema (R6).** Every source becomes one canonical flow table.
  - CSV rows are mapped per dataset; PCAPs and live packets go through the *same* Scapy flow assembler.
  - The table becomes per-host 60 s windows of 28 features: 17 outbound behaviour, 8 inbound exposure, and 3 packet-level (TTL, TCP window, retransmissions) with "observed" masks.
  - A flow counts in the window where it **ends**, so there is no look-ahead.
- **Host graph.** Nodes are hosts and edges are flows in the same window.
  - GraphSAGE (mean + max aggregation) gives every host its neighbours' context.
  - The same graph drives the 3D topology view.
- **World model (R8).**
  - Encoder: an MLP over the window plus GraphSAGE.
  - Transition: a GRU deterministic state *h* and a Gaussian latent *z*, with prior p(z|h) and posterior q(z|h,e).
  - Decoder: reconstructs the features, the risk and a 7-class stage.
  - Training has two parts:
    - filtering (reconstruction + KL + current risk/stage);
    - **latent overshooting**, where from the end of a 10-minute history the prior alone imagines 5 steps, supervised against what really happened.
  - The rollout never reads future observations.
- **One rollout (R7).** `rollout(state, horizon=5, intervention)` serves file replay, live mode and counterfactuals alike. 16 MC samples give the 10–90% band.
- **Explainability (R5).** Integrated gradients attribute the forecast peak to the history features, rendered as sentences against typical active-window values. SHAP is used for the baseline.
- **Decision (R9).**
  - A deterministic table maps stage + drivers to an action and alternatives: block source/pair, isolate, rate-limit, block egress, throttle.
  - Attacker/victim roles come from the forecast plus flow direction (R14).
  - A local Ollama model (qwen2.5:3b) only *narrates* the chosen action. It is asynchronous with a template fallback.
- **Counterfactual (R17).** Drop or throttle the flows the action would stop, from the decision time on. Then re-run the same fusion and rollout, giving a "with action" curve and a "no action" curve.
- **Live (R13).** An AsyncSniffer feeds 60 s sliding windows at 15 s stride (about 0.1–0.2 s per tick on a laptop CPU).
  - Accept installs a TTL'd nftables rule. It is guarded against management IPs and needs an operator token.
  - Risk is then re-measured on real traffic.

## 2. Data, training, evaluation

- **Datasets with host identity and time:**
  - CIC-IDS2017 (TrafficLabelling);
  - CIC-IDS2018 (the IP-bearing 20-02 day);
  - CTU-13 (7 `.binetflow` scenarios);
  - UNSW-NB15 (raw).

  In total that's 1.14 M host-windows. CIC-IoT-2023 and the IP-stripped CIC-2018 days cannot form host timelines. The label→ATT&CK mapping is in `data/mitre_mapping.yaml`.
- **Split.** A blocked temporal split: 1-hour blocks in a 3:1:1 cycle, and no sequence crosses a block. The threshold is chosen on validation (macro-F1 across datasets), with Platt calibration.
- **Balancing (documented, R20).**
  - Keep all attack sequences and 15% of all-benign ones.
  - Sample by (dataset × attack/benign).
  - Weight onsets 5×.
  - Drop packet features at p = 0.5 so CSV and PCAP inputs share one model.

**Results** (test blocks, target = "attack activity within 300 s"; full tables in `reports/benchmarks.md`):

| | F1 | PR-AUC | CIC-2017 PR-AUC | CTU-13 PR-AUC |
|---|---|---|---|---|
| World model (RSSM-lite + GraphSAGE) | **0.860** | **0.921** | **0.603** | **0.598** |
| Logistic regression, same features | 0.543 | 0.766 | 0.157 | 0.027 |
| World model without GNN (ablation) | 0.858 | 0.904 | 0.512 | 0.566 |

- The current-window detection F1 is 0.906.

**Honest limits.**
- Alerts come at or shortly after attack onset. Early-warning recall on fully benign histories is 0%.
- The oracle persistence reference (which knows the true current label) scores higher.
- Zero-shot cross-dataset transfer fails: training on CIC and testing on CTU-13 gives PR-AUC 0.006, and on UNSW-NB15 0.19. LogReg fails too (0.007 / 0.16).
- On a live home network the dataset-trained model does not recognise a real port scan. **Targeted retraining on recorded lab traffic** (`src/training/lab_dataset.py`) is the prescribed fix (R4).

## 3. Deployment

Everything runs natively and fully offline: a FastAPI backend (:8000), a Streamlit dashboard (:8501) and local Ollama (:11434, optional).
- The live sensor runs the same backend on a Linux laptop, and the dashboard connects to it remotely.
- Weights, scaler, calibration and config ship in `models/` (R18).
- The dashboard uses Streamlit + Plotly with the preserved three.js 3D topology, bundled offline.
- Its three modes (CSV replay, PCAP replay, Live Monitor) all use the same model and rollout.
- Setup: `docs/SETUP.md`. Live deployment: `docs/LIVE_SENSOR.md`.
