# Architecture Document

**Project:** NetraVerse — AI-Based Network Attack Forecasting (PS 26153)

---

## 1. System Overview

Three ingestion paths (CSV, PCAP, Live capture) converge on **one unified feature schema**, feed **one trained world model**, and share **one rollout/decision engine**. The dashboard is the same component regardless of input source; only the data source behind it changes.

```
 CSV file ──┐
 PCAP file ─┼──▶ Feature Fusion Layer ──▶ World Model (RSSM-lite + GNN) ──▶ Rollout Engine ──▶ Decision Engine ──▶ Dashboard
 Live NIC ──┘         (unified schema)         │                              │                    │
                                                ▼                              ▼                    ▼
                                          Explainability                 Counterfactual        Ollama (narration
                                          (Captum/SHAP)                  Re-rollout            layer, optional)
```

---

## 2. Complete Tech Stack

### 2.1 Data Processing & Feature Engineering
| Component | Tool | Purpose |
|---|---|---|
| Bulk CSV loading | **Polars** | Fast load/clean of multi-GB CIC/CTU CSVs |
| Post-clean tabular work | **Pandas** | Feature manipulation after downsampling |
| Packet-level extraction | **Scapy** | TTL variance, window size, fragment flags, retransmissions from raw PCAPs |
| Flow-level extraction (offline + live) | **CICFlowMeter** (CLI/subprocess or Python port) | NetFlow-style flow features, consistent schema between datasets and live capture |
| Feature storage | **PyArrow / Parquet** | Fast repeated load of fused feature matrix during model iteration |

### 2.2 Modeling
| Component | Tool | Purpose |
|---|---|---|
| Core framework | **PyTorch** | Custom latent rollout logic (imperative, easier than TF/Keras for this) |
| Graph modeling | **PyTorch Geometric (PyG)** | GNN host-graph layer (GraphSAGE/GAT) |
| World model | Custom `nn.Module`s: Encoder (MLP) → GRUCell (latent transition) → Decoder (MLP) | RSSM-lite: encode → P(z_t+1\|z_t) → decode |
| Baseline | **scikit-learn** | Logistic regression baseline required by PS for benchmarking |

### 2.3 Explainability
| Component | Tool | Purpose |
|---|---|---|
| Deep model attribution | **Captum** | Attention/integrated-gradients extraction from RSSM/GNN |
| Baseline attribution | **SHAP** | Feature attribution for logistic regression; offline use only (too slow for real-time on deep model) |

### 2.4 Decision & Narration
| Component | Tool | Purpose |
|---|---|---|
| Decision logic | Deterministic Python rule-engine | MITRE stage + driving features → recommended action (auditable, no hallucination risk) |
| Narration layer | **Ollama** (Phi-3-mini or Llama-3.2-3B, quantized) | Converts structured decision output into analyst-style natural language. Optional/async, never the decision source |

### 2.5 Backend / Serving
| Component | Tool | Purpose |
|---|---|---|
| API layer | **FastAPI** | Serves CSV/PCAP upload endpoints and live-capture inference endpoint from the same model + rollout function; async for streaming live windows |
| Windowing state | **Redis** (or in-process ring buffer for simpler setup) | Holds rolling window of recent flows per host for live sliding-window inference |
| Live host-graph | **NetworkX** | Incremental host-graph structure feeding the GNN, updated per window |

### 2.6 Dashboard / Frontend
| Component | Tool | Purpose |
|---|---|---|
| UI framework | **Streamlit** | Fast to build; file upload widget, live-refreshing charts, sufficient polish for demo video |
| Charting | **Plotly** | Probability timeline, host-graph network visualization, counterfactual before/after comparison |
| Styling | Custom CSS override on Streamlit (see `design.md`) | Enforce subtle/professional look, override Streamlit's default theme |

### 2.7 Packaging & Deployment
| Component | Tool | Purpose |
|---|---|---|
| Environment | **Conda or `uv`** | Pin PyTorch/PyG/Scapy versions (PyG wheels are CUDA-sensitive; Scapy needs elevated privileges) |
| Containerization | **Docker + docker-compose** | One-command judge deployment: backend + dashboard + Ollama (+ Redis if used), auto-opens dashboard |
| Registry | **Docker Hub** | Public image hosting for judges — images published as `<dockerhub-user>/netraverse-backend` and `<dockerhub-user>/netraverse-dashboard` |

---

## 3. Application Flow

### 3.1 File Upload Flow (CSV or PCAP)
1. User uploads file via Streamlit dashboard.
2. FastAPI backend routes to `from_csv()` or `from_pcap()` — both output the same unified feature schema.
3. Feature Fusion Layer normalizes and windows the data.
4. Topology builder extracts all unique IPs → constructs host graph (NetworkX) for this file.
5. World Model encodes the current state, runs a K-step latent rollout (horizon = 300s).
6. Rollout output → infiltration probability time-series + MITRE stage per window + driving features (Captum).
7. Dashboard renders: building probability curve, host-graph with attacker/victim highlighted, MITRE annotations.
8. When probability crosses alert threshold: pause playback, Decision Engine computes recommended action, Ollama generates narration.
9. User selects **Accept / Modify / Reject**:
   - Accept → apply intervention to state → re-rollout from this point → render continuation.
   - Modify → user picks alternate action from rule-engine's option list → re-rollout.
   - Reject → rollout continues unmodified → render "cost of inaction" branch.
10. Loop continues until the 300s horizon is exhausted or user replays.

### 3.2 Live Network Flow
1. Sensor machine runs Scapy/tshark sniffer on the monitored interface (mirrored/promiscuous).
2. Packets batched into windows → CICFlowMeter-equivalent flow generation → Scapy packet-level stats merged → same Feature Fusion Layer as file path.
3. Redis/ring buffer holds the last N windows per host.
4. NetworkX host-graph updated incrementally as new flows arrive.
5. FastAPI live-inference endpoint feeds the same trained World Model + rollout engine.
6. Dashboard live-updates (via polling or WebSocket) with the same visual components as the file-upload flow.
7. Accept/Modify decisions in live mode execute **real** actions (e.g., iptables rule via a controlled script) — not just simulated state changes — then re-measure actual traffic to confirm risk reduction.
8. Fallback: pre-recorded PCAP of the demo attack sequence can be replayed through the file-upload path if live capture fails during judging.

### 3.3 Training Flow (offline, not part of live demo)
1. Load CIC-IDS-2017/2018, CTU-13, UNSW-NB15, CIC-IoT-2023 → Feature Fusion Layer → unified Parquet dataset.
2. Attack-type → MITRE stage lookup table applied to labels.
3. Train World Model (encoder/transition/decoder + GNN) via supervised dynamics learning (ground-truth transitions derived from attack timeline annotations).
4. Train logistic regression baseline on the same features.
5. Evaluate both: F1, precision, recall, FPR.
6. Cross-dataset generalization test: train on dataset A, zero-shot evaluate on dataset B.
7. Export model weights + training config for reproducibility.

---

## 4. File & Folder Structure

```
netraverse/
├── README.md
├── prd.md
├── architecture.md
├── rules.md
├── phases.md
├── design.md
├── docker-compose.yml
├── Dockerfile.backend
├── Dockerfile.dashboard
├── .env.example
├── pyproject.toml / environment.yml
│
├── data/
│   ├── raw/                        # untouched dataset downloads (gitignored)
│   │   ├── cic_ids_2017/
│   │   ├── cic_ids_2018/
│   │   ├── ctu_13/
│   │   ├── unsw_nb15/
│   │   └── cic_iot_2023/
│   ├── processed/                  # unified schema, Parquet
│   └── mitre_mapping.yaml          # attack-type → MITRE ATT&CK stage lookup
│
├── src/
│   ├── features/
│   │   ├── flow_features.py        # NetFlow/IPFIX-style extraction
│   │   ├── packet_features.py      # Scapy/PyShark PCAP extraction
│   │   ├── fusion.py                # unified schema: from_csv(), from_pcap(), from_live_window()
│   │   └── schema.py                # canonical feature definitions/ordering
│   │
│   ├── graph/
│   │   ├── host_graph_builder.py    # NetworkX graph construction (static + incremental)
│   │   └── graph_utils.py
│   │
│   ├── models/
│   │   ├── encoder.py
│   │   ├── transition.py            # GRU-based latent transition (RSSM-lite)
│   │   ├── decoder.py
│   │   ├── gnn.py                   # GraphSAGE/GAT host-graph layer
│   │   ├── world_model.py           # composes encoder+transition+decoder(+gnn)
│   │   ├── rollout.py               # rollout(state, horizon, intervention=None)
│   │   └── baseline_logreg.py
│   │
│   ├── explainability/
│   │   ├── captum_explainer.py
│   │   └── shap_explainer.py
│   │
│   ├── mitre/
│   │   ├── stage_mapper.py          # predicted state → ATT&CK stage
│   │   └── mitre_lookup.py
│   │
│   ├── decision/
│   │   ├── rule_engine.py           # stage + driving features → recommended action
│   │   ├── counterfactual.py        # intervention application + re-rollout wiring
│   │   └── ollama_narration.py      # structured decision → analyst-style text (async, optional)
│   │
│   ├── live/
│   │   ├── sniffer.py               # Scapy/tshark capture
│   │   ├── windowing.py             # sliding window buffer (Redis or in-process)
│   │   ├── live_flow_gen.py         # CICFlowMeter-equivalent live flow assembly
│   │   └── action_executor.py       # applies real actions (iptables etc.) in live mode
│   │
│   ├── training/
│   │   ├── train_world_model.py
│   │   ├── train_baseline.py
│   │   ├── evaluate.py              # F1/precision/recall/FPR
│   │   ├── cross_dataset_eval.py
│   │   └── configs/
│   │       ├── world_model.yaml
│   │       └── baseline.yaml
│   │
│   ├── api/
│   │   ├── main.py                  # FastAPI app
│   │   ├── routes_upload.py         # CSV/PCAP endpoints
│   │   ├── routes_live.py           # live capture endpoints
│   │   └── schemas.py               # pydantic request/response models
│   │
│   └── utils/
│       ├── logging.py
│       └── config.py
│
├── dashboard/
│   ├── app.py                       # Streamlit entrypoint
│   ├── components/
│   │   ├── probability_timeline.py
│   │   ├── topology_view.py
│   │   ├── decision_panel.py        # Accept/Modify/Reject UI
│   │   └── counterfactual_panel.py
│   └── styles/
│       └── theme.css                # subtle/professional override (see design.md)
│
├── models/                          # trained weights + configs (tracked via git-lfs or excluded, documented in README)
│   ├── world_model.pt
│   ├── baseline_logreg.pkl
│   └── training_config.yaml
│
├── notebooks/                       # exploratory analysis only, not part of the shipped pipeline
│
├── demo/
│   ├── attack_scripts/              # Nmap/Hydra/pivot scripts for controlled home-network demo
│   ├── fallback_pcap/               # pre-recorded backup capture
│   └── demo_script.md               # step-by-step recorded demo narrative
│
└── tests/
    ├── test_feature_fusion.py
    ├── test_rollout.py
    ├── test_rule_engine.py
    └── test_api.py
```

---

## 5. Key Interfaces (contract-level, keeps everything consistent)

- `fusion.from_csv(path) -> FeatureMatrix`
- `fusion.from_pcap(path) -> FeatureMatrix`
- `fusion.from_live_window(window) -> FeatureMatrix`
- `world_model.encode(FeatureMatrix) -> LatentState`
- `rollout.rollout(state: LatentState, horizon: int, intervention: Optional[Action]) -> RolloutResult` (probability series, MITRE stages, driving features)
- `rule_engine.recommend(stage, driving_features) -> Action` (with `alternatives: List[Action]` for the Modify option)
- `action_executor.apply(action, live=True|False) -> None`

All model-facing and dashboard-facing code should depend on these interfaces only — never on CSV/PCAP/live specifics directly. This is what keeps the CSV, PCAP, and live paths genuinely unified rather than three separate systems.

---

## 6. Deployment Architecture

```
docker-compose.yml
 ├── backend    (FastAPI + PyTorch model + rule engine)     :8000
 ├── dashboard  (Streamlit)                                  :8501
 ├── ollama     (local LLM narration service)                :11434
 └── redis      (optional, sliding window state)             :6379
```

`docker-compose up` → dashboard container waits for backend health check → opens/points to `localhost:8501`. Fully offline: no service in this stack calls out to any external API.
