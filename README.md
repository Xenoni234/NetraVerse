# NetraVerse: World-Model Network Attack Forecasting

SIH 2026 · PS 26153 (NTRO). This is a latent world model that learns how per-host network state evolves, `P(s_t+1 | s_t)`. It imagines the next **300 s** to forecast which hosts will be involved in attack activity, maps the forecast to **MITRE ATT&CK** stages, and explains every forecast. It also lets an analyst **Accept / Modify / Reject** a recommended containment and see the re-simulated future.

The spec lives in [`prd.md`](prd.md), [`architecture.md`](architecture.md), [`rules.md`](rules.md), [`phases.md`](phases.md) and [`design.md`](design.md). Measured results are in [`reports/benchmarks.md`](reports/benchmarks.md).

```
CSV ─┐                                  ┌─ Captum IG explanation (every forecast)
PCAP ┼─ fusion.windowize ─ WorldModel ──┼─ rollout(state, 300 s) ─ MITRE stage ─ rule engine ─ counterfactual re-rollout
Live ┘   (one 39-feature schema)        └─ GraphSAGE host context            (deterministic)   (same rollout, action applied)
```

## Quick start: Docker (one command, R19)

```bash
docker compose up --build          # backend :8000, dashboard http://localhost:8501 (Ollama internal only)
```

- Bundled replay samples are mounted from `demo/samples`. Generate them once with `python -m demo.make_samples`, or just upload any CSV or PCAP in the UI.
- The narration model is pulled once into a volume. Set `NV_NARRATION=0` to run with template narration only.
- Two-page architecture summary: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Quick start (offline, one machine, no Docker)

```bash
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt      # Linux: .venv/bin/pip
python -m uvicorn src.api.main:app --port 8000        # backend: loads models/world_model.pt
python -m streamlit run dashboard/app.py              # dashboard: http://localhost:8501
```

- Pick **CSV Upload**, then a bundled sample, then **Analyse**, then **▶ Play**. [`demo/demo_script.md`](demo/demo_script.md) has the full demo narrative.
- Bundled samples come from `data/raw`, so regenerate them with `python -m demo.make_samples`.
- Run the tests with `pytest -q`.
- Split machines (API on the sensor, dashboard on another PC): set `NV_API_URL=http://<sensor>:8000` for the dashboard. Also set `NV_API_PUBLIC_URL` if the browser reaches the API under a different address.

## How it works

| Layer | Code | Notes |
|---|---|---|
| Flow extraction | `src/features/flow_features.py` | Handles CIC-IDS2017/2018 CSVs, cicflowmeter CSVs, CTU-13 `.binetflow` and UNSW-NB15 raw. Every format becomes one canonical flow table. |
| Packet extraction | `src/features/packet_features.py` | A Scapy bidirectional flow assembler that also records TTL, TCP window and retransmissions. The **same class** serves PCAP and live capture. |
| Fusion | `src/features/fusion.py` | Builds per-host 60 s windows: 17 outbound, 8 inbound and 3 packet features, plus 3 "observed" masks. A flow belongs to the window containing its **end** (no look-ahead). It also builds the host-graph edges. |
| World model | `src/models/{encoder,gnn,transition,decoder,world_model}.py` | See the architecture paragraph below. |
| Rollout | `src/models/rollout.py` | `rollout(state, horizon, intervention)`: prior-only imagination, 5 × 60 s, with an MC-sampled 10–90% band. |
| MITRE | `data/mitre_mapping.yaml`, `src/mitre/` | Hand-built label-to-tactic table. IMPACT (TA0040) is added for DoS. |
| Explainability | `src/explainability/` | Captum Integrated Gradients on the *forecast* (every API forecast). SHAP LinearExplainer for the baseline. |
| Decision | `src/decision/rule_engine.py` | Stage + drivers → action + alternatives. Deterministic. |
| Counterfactual | `src/decision/counterfactual.py` | Drops or throttles the flows the action would stop, then re-runs fusion and the same rollout. |
| Roles | `src/graph/host_graph_builder.py` | Attacker/victim come from the forecast plus traffic direction. Nothing is hardcoded (R14). |
| Live | `src/live/` | AsyncSniffer → FlowAssembler → sliding 60 s windows (15 s stride) → same service. Real nftables actions have a TTL and a management-IP guard. |
| API | `src/api/` | FastAPI: `/upload`, `/upload/{id}/timeline, explain, topology, decision, branch`, `/live/*`. |
| Dashboard | `dashboard/` | Streamlit + Plotly. The original **three.js 3D topology** is preserved as a CCv2 component, bundled offline in `dashboard/components/topology3d/dist`. |

**World-model architecture.**
- The encoder is an MLP over each window plus a **GraphSAGE** embedding (mean/max over the hosts it talked to in that window).
- An **RSSM-lite** transition carries the state: a GRU deterministic state `h` plus a Gaussian latent `z`, with a prior `p(z|h)` and a posterior `q(z|h,e)`.
- Decoder heads reconstruct the features and output risk and a 7-class stage.
- Training combines two objectives:
  - filtering losses: reconstruction, KL(q‖p) with free nats, current risk and current stage;
  - **latent overshooting**: from the end of the 10-window history, the prior alone imagines 5 steps, and the imagined risk, stage and features are supervised against the real future.
- So the forecast is a learned transition model, not a direct regressor (R8).

## Datasets

See [`reports/dataset_stats.md`](reports/dataset_stats.md).

| Dataset | Used as |
|---|---|
| CIC-IDS2017 `TrafficLabelling` | Training |
| CIC-IDS2018, 20-02 day (the only one with IPs) | Training |
| CTU-13 scenarios 1/4/5/7/8/10/12 (`.binetflow`) | Training |
| UNSW-NB15 raw | Training |

What was left out, and why:
- **CIC-IoT-2023** and the IP-stripped CIC-IDS2018 days have no host identity or timestamps, so they cannot form per-host timelines.
- Raw data sits in `data/raw/` (gitignored). Rebuild with `python -m src.training.build_dataset`.

## Reproduce training

```bash
python -m src.training.build_dataset          # raw -> data/processed/*.parquet + reports/dataset_stats.md
python -m src.training.train_world_model      # -> models/world_model.pt, training_config.yaml, reports/wm_main.json
python -m src.training.train_baseline         # -> models/baseline_logreg.pkl, reports/baseline_main.json (LogReg + SHAP + persistence)
python -m src.training.train_world_model --no-gnn --tag nognn   # Phase 5 ablation
python -m src.training.cross_dataset_eval     # Phase 6 zero-shot: CIC -> CTU-13, UNSW-NB15
python -m src.training.report                 # -> reports/benchmarks.md
```

The config (hyper-parameters, split and balancing) ships next to the weights as `models/training_config.yaml`, and the scaler and calibration are stored inside `world_model.pt` (R18).

## Tuning decisions (R20)

Every decision below was applied identically to the world model and the baselines.

1. **60 s windows, K = 5 (300 s), L = 10.** CIC-IDS2017 timestamps are minute-resolution with AM/PM dropped (hours 1–7 are shifted +12 h). Anything finer than 60 s would be fabricated precision.
2. **Blocked temporal split.** 1-hour blocks per capture are assigned train/val/test in a fixed 3:1:1 cycle. Sequences never cross a block, so there is no row shuffling and no leakage. As a side effect, some CIC-2017 attack types fall only in train/val blocks, and `benchmarks.md` shows which datasets have scoreable test positives.
3. **Label semantics.**
   - A host-window is "attack" if the host **initiates** attack-labelled flows.
   - A host-window is also "attack" if it **receives** them for recon, initial access, lateral movement or impact.
   - For C2 and exfiltration the destination is attacker infrastructure (DNS resolvers, C2 servers), so only the compromised source is labelled.
   - The first version labelled every destination. That made the CTU-13 DNS server and Google IPs "attacked" and was dropped for being semantically wrong. The earlier results are kept in `reports/*_rawlabels.json`.
4. **Attack episodes.** Attack windows of one host separated by ≤ 5 quiet minutes count as one episode.
5. **Class balancing.**
   - Training keeps every sequence that touches an attack and 15% of all-benign sequences.
   - Batches are drawn so that every (dataset, attack/benign) group has equal expected mass, so UNSW-NB15's huge attack volume does not dominate.
   - The BCE `pos_weight` is computed under that sampler.
   - A finer (dataset, dominant MITRE stage) sampler was tried and **rejected**: its validation macro PR-AUC was lower (0.742 vs 0.759). The result is kept in `reports/wm_stagebalanced_rejected.json`.
   - The model is always selected by validation macro PR-AUC, never by demo behaviour.
6. **Onset emphasis.** Sequences that are benign now but have an attack inside the horizon get 5× weight on the imagined-risk loss, because early warning is the goal.
7. **Packet-feature dropout (p = 0.5).** Flow CSVs never carry TTL, window or retransmission data. Randomly hiding them in training makes one model valid for CSV and PCAP input alike.
8. **Cross-dataset normalisation (R4).** `--capture-norm` optionally re-centres each capture on its own median/IQR. It is unsupervised: no labels, only that network's traffic statistics. It was evaluated in `reports/cross_dataset_cn.json`, **did not improve** zero-shot transfer (CTU-13 PR-AUC 0.006 either way; UNSW 0.107 vs 0.189 without it), and is therefore **off** in the shipped model.
9. **Threshold.** The threshold maximises the *mean* F1 across datasets on validation, so no single easy dataset sets the operating point. Platt calibration (fitted on validation, monotone) makes the displayed probabilities interpretable. It does not change any ranking metric.

## Honest limitations

These are also reflected in `benchmarks.md`.

- **Detection is strong, but true forecasting before onset is weak.** On most CIC/CTU campaigns the first labelled attack window has no benign precursor at 60 s resolution. The world model flags attacks within about one window of onset and then forecasts their continuation and escalation. It rarely alerts *before* the first attack flow.
- **Persistence (oracle) scores higher on continuation.** It is told the true current label, which no deployed system has. It is reported for transparency and cannot score early warning.
- **UNSW-NB15 is trivially separable per host.** Its attacker hosts never behave benignly. Per-dataset rows are reported so it does not inflate the pooled numbers.
- **Cross-dataset generalisation fails (R4, reported, not dropped).** Trained on CIC only, the model does not transfer zero-shot to CTU-13 (PR-AUC 0.006) or UNSW-NB15 (0.189). LogReg fails the same way (0.007 and 0.158). The testbeds differ too much in what "normal" per-host traffic looks like; per-capture normalisation did not fix it.
- **GraphSAGE helps.** With host-graph context, test PR-AUC is 0.921 vs 0.904 without it. CIC-2017 goes from 0.51 to 0.60 and CTU-13 from 0.57 to 0.60.
- **Counterfactuals are replay-based.** For recorded traffic the "after" curve replays the real traffic minus the flows the rule would have stopped. It cannot model an adaptive attacker.

## Decision narration (Phase 10)

- `src/decision/ollama_narration.py` asks a **local** Ollama model (default `qwen2.5:3b`, set via `NV_OLLAMA_MODEL`) to describe the decision the rule engine already made.
- It runs asynchronously with a 30 s timeout and falls back to a template. The model is warmed up when the API starts.
- The dashboard labels the text as descriptive only. Disable it with `NV_NARRATION=0`.

## Targeted retraining on your own lab (Phase 11, R4)

The dataset-trained model does not transfer to a new network: see the cross-dataset results, and in a live home-network test a real port scan scored 0%. The fix is to record labelled traffic on your own lab.

1. **Record on the sensor:** `tcpdump -i <iface> -w data/raw/lab/session1.pcap`
2. **Run the attack sequence** from the attacker machine, against your own device only:

   ```bash
   NV_I_OWN_THIS_TARGET=yes NV_ATTACKER_IP=<attacker LAN IP> demo/attack_scripts/run_sequence.sh <target>
   ```

   It starts with 5 minutes of benign baseline, then runs recon, brute force and (optionally) a lateral probe. Each stage's time window goes into `data/raw/lab/schedule.jsonl`.
3. **Build and retrain:**

   ```bash
   python -m src.training.lab_dataset
   python -m src.training.train_world_model --datasets cic2017 cic2018 ctu13 unsw lab
   ```

   The lab rows are reported per dataset in `benchmarks.md`. Keep the capture as the R12 fallback PCAP.

## Live demo (Phases 8/11)

- Run the sensor with `NV_LIVE_IFACE=<iface> NV_ENFORCE=1 NV_OPERATOR_TOKEN=<secret> uvicorn src.api.main:app --host 0.0.0.0`. It needs root for capture and passwordless `sudo nft` for enforcement.
- Rehearse without a network using `NV_LIVE_REPLAY_PCAP=<file>`.
- The attack scripts in `demo/attack_scripts/` refuse non-RFC1918 targets and require `NV_I_OWN_THIS_TARGET=yes` (R11).
