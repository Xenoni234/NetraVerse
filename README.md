# NetraVerse — World-Model AI for Network Attack Forecasting

> A world-model AI that learns the evolving state of a network from traffic telemetry and **forecasts attacker progression before compromise completes** — mapping the forecast to MITRE ATT&CK stages, explaining it, and turning it into a human-approved, verifiable defensive action.

---

## 1. What is the Problem

Traditional IDS/IPS/SIEM answer only one question — *"is this traffic malicious now?"* — a reactive, per-flow verdict delivered after the fact. They do not model how the network **state** evolves, cannot anticipate an attacker's next move, and bury analysts in context-less alerts. Defenders get **no lead time** to prevent a breach.

## 2. What is NetraVerse

NetraVerse reframes network defence from **detection** to **prediction**. It models the whole network as an evolving latent state, simulates the next five minutes, and answers *"where is this attack heading, and what should I do?"* — as a closed loop:

**Predict → Decide → Act → Verify**

```
CSV  ─┐                                   ┌─ Captum IG + SHAP evidence (every forecast)
PCAP ─┼─ fusion.windowize ─ World Model ──┼─ rollout(state, 300 s) ─ MITRE stage ─ rule engine ─ counterfactual re-rollout
Live ─┘   (one 31-feature schema)         └─ GraphSAGE host-graph context          (deterministic)   (Accept / Modify / Reject)
```

---

## How it works

1. **See** — ingest CSV flow records, PCAP packet captures (Scapy), and live NIC capture. All three resolve to **one unified feature schema** (31 fused flow + packet features per host per 60 s window, with a 10-minute history).
2. **Understand state** — build a host graph (nodes = hosts, edges = flows) encoded with a **GraphSAGE GNN** to capture lateral movement and multi-host spread. Attacker/victim roles are derived per window, never hardcoded.
3. **Imagine the future** — a genuine world model (**RSSM-lite**: encoder → GRU latent transition, deterministic + stochastic state, prior/posterior KL-trained dynamics) runs a **K-step, prior-only imagination rollout over a 300 s horizon** — a real latent-dynamics model, not an LSTM classifier in disguise.
4. **Forecast + explain** — decode each imagined state into an infiltration-probability timeline and a predicted **MITRE ATT&CK stage** (Reconnaissance, Initial Access, Lateral Movement, Command & Control, Exfiltration, Impact). Captum integrated gradients and SHAP attribute every forecast to its driving features.
5. **Decide (human-in-the-loop)** — a deterministic rule engine maps stage + drivers to a recommended action with ranked alternatives and a rationale; the analyst chooses **Accept / Modify / Reject**, and a **counterfactual** re-rollout shows the "no-action vs action" branches. A local LLM (Ollama) narrates the decision — it never makes it.
6. **Act + verify** — the approved action is enforced (a guarded nftables rule with a TTL and protected-IP safeguards), then live traffic is re-measured to confirm the risk actually dropped.

**Auto-Calibration Engine** — one trained model adapts to any deployment online, with no retraining: it learns each site's benign baseline, normalizes features per environment, auto-tunes the alert threshold to a target false-alarm budget, detects drift, and optimizes lead time.

## What makes it unique

| Capability | Conventional IDS | NetraVerse |
|---|---|---|
| Current-threat detection | ✓ | ✓ |
| Network state over time | — | ✓ |
| Future-state simulation (latent world model) | ✗ | ✓ |
| K-step attack forecasting (300 s) | ✗ | ✓ |
| MITRE attack-stage forecasting | ✗ | ✓ |
| Forecast explanation + evidence (SHAP/Captum) | ✗ | ✓ |
| Counterfactual "what-if" simulation | ✗ | ✓ |
| Actionable loop (Accept/Modify/Reject + enforce + verify) | ✗ | ✓ |
| GNN multi-host / lateral-movement modeling | ✗ | ✓ |
| Per-environment auto-calibration | ✗ | ✓ |
| Runs fully offline / on-prem, local LLM | ✗ | ✓ |

## Results (measured, held-out test)

| Model | Precision | Recall | F1 | FPR | PR-AUC |
|---|---|---|---|---|---|
| **NetraVerse (RSSM-lite + GraphSAGE)** | **0.986** | **0.762** | **0.860** | **0.00015** | **0.921** |
| Logistic Regression (same features) | 0.424 | 0.756 | 0.543 | 0.01413 | 0.766 |

- **+58% F1** and **+20% PR-AUC** over the Logistic-Regression baseline; **~94× lower false-alarm rate** (FPR 0.015% vs 1.413%).
- Current-window detection head: **F1 0.906 · PR-AUC 0.961**.
- GraphSAGE host context helps: **PR-AUC 0.921 vs 0.904** without the GNN (CIC-2017 0.603 vs 0.512).
- Compact: **~480K parameters · 1.94 MB**, real-time on a single GPU, fully offline.

Full numbers, per-dataset breakdown and the GNN ablation: [reports/benchmarks.md](reports/benchmarks.md).

## Quick start

```bash
git clone https://github.com/Xenoni234/NetraVerse.git && cd NetraVerse
python -m venv .venv && .venv/Scripts/python -m pip install -r requirements.txt   # Linux: .venv/bin/python
python -m pytest -q                                                               # sanity check
```

**Backend + Streamlit dashboard**

```bash
python -m uvicorn src.api.main:app --port 8000        # backend (loads models/world_model.pt)
python -m streamlit run dashboard/app.py              # dashboard -> http://localhost:8501
```
Pick **CSV Upload**, choose a CIC/CTU/UNSW flow CSV or a PCAP (or a bundled sample), then **Analyse** and **▶ Play**. Playback pauses at the first forecast, where you choose Accept / Modify / Reject.

**Analyst console** (standalone forecasting UI with the 3D host-graph)

```bash
cd netraverse_ui && python server.py                  # -> http://localhost:8600
```
Open the landing page → **Launch analyst console** → CSV / PCAP / Live Monitor. In Live Monitor, run the terminal launchers to drive campaigns:

```bash
python launch_recon_scan.py        # e.g. reconnaissance scan (Ctrl+C to stop)
python stop_attack.py              # stop all active campaigns
```

Optional local narration: install [Ollama](https://ollama.com) and `ollama pull qwen2.5:3b`.

## Architecture

```
             ┌──────────── Feature Fusion (one 31-feature schema, 60 s windows) ────────────┐
 CSV ──┐     │                                                                              │
 PCAP ─┼────▶│  Host graph (GraphSAGE) ─▶ World Model (RSSM-lite) ─▶ Rollout (300 s) ─▶ Forecast + MITRE stage
 Live ─┘     │                                                            │                 │
             └──────────────────────────────────────────────────────────┼─────────────────┘
                                                                          ▼
   Explainability (Captum/SHAP) ─▶ Decision Engine (deterministic) ─▶ Accept/Modify/Reject ─▶ Enforcement ─▶ Verify
                                            │                                                       ▲
                                     Ollama narration (offline)                     Auto-Calibration Engine
```

## Tech stack

PyTorch + PyTorch Geometric (RSSM-lite world model + GraphSAGE) · Captum + SHAP · Scapy / CICFlowMeter (feature fusion) · FastAPI (inference API) · NetworkX (host graph) · Ollama (local, offline narration) · Streamlit + Plotly and a vendored three.js 3D host-graph console. Trained and evaluated on **CIC-IDS2017, CIC-IDS2018, CTU-13, UNSW-NB15** with cross-dataset evaluation. Fully offline at runtime.

## Documentation

| Doc | For |
|---|---|
| [docs/SETUP.md](docs/SETUP.md) | Install, data layout, running on one or two machines, environment variables |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Repo layout, the contracts to preserve, common tasks, tests |
| [docs/TRAINING.md](docs/TRAINING.md) | Model details, reproducing training, results, tuning decisions |
| [docs/API.md](docs/API.md) | Backend endpoints |
| [docs/LIVE_SENSOR.md](docs/LIVE_SENSOR.md) | Live capture and enforcement |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 2-page architecture document |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Known problems and fixes |
| [demo/demo_script.md](demo/demo_script.md) | Demo walkthrough |
| [reports/benchmarks.md](reports/benchmarks.md) | All measured results |

---

**Team — Code Bandits**
