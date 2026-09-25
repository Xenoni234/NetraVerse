# Project Requirement Document (PRD)

**Project:** NetraVerse — AI-Based Network Attack Forecasting from Network Traffic Data
**PS ID:** 26153
**Organization:** National Technical Research Organisation (NTRO)
**Theme:** Blockchain & Cybersecurity
**Author:** Aayush Gupta

---

## 1. Problem Statement Summary

Build a World-Model-based AI system that learns the evolving state of a computer network from traffic telemetry and forecasts the likelihood and progression of malicious activity **before** compromise completes — moving beyond static intrusion classification (single-flow benign/malicious labels) toward predictive, simulation-based cyber defence.

The system must:
- Represent network state as a feature vector or graph.
- Learn state-transition dynamics P(S_t+1 | S_t) using sequence models (LSTM/Transformer), GNNs, or latent state models.
- Forecast future network states and estimate probability of attacker progression.
- Map predicted behaviour to MITRE ATT&CK stages.
- Explain predictions via attention/feature attribution (SHAP).
- Demonstrate applicability to enterprise/Critical Information Infrastructure environments.

---

## 2. Objectives

1. Ingest **both** flow-level (NetFlow/IPFIX) and packet-level (PCAP-derived) features — required together, not optional.
2. Train a genuine **World Model** (latent transition dynamics), not a static classifier, on open datasets: CIC-IDS-2017, CIC-IDS-2018, CTU-13, UNSW-NB15, CIC-IoT-2023.
3. Perform **K-step forward simulation** (target: 300 seconds / 5 minutes ahead) from any current traffic snapshot, producing an infiltration-probability timeline.
4. Map predicted future states to MITRE ATT&CK phases (Reconnaissance, Initial Access, Lateral Movement, Command & Control, Exfiltration).
5. Surface **explainable, interpretable decision support** — not just a probability number — including a **counterfactual "what-if" simulation** engine that lets a defender apply an action and see the projected risk change.
6. Provide **three input modes**: CSV upload, PCAP upload, and live network capture — all sharing one unified model and one unified feature schema.
7. Provide an **Accept / Modify / Reject** actionable-recommendation loop at the point an attack is predicted, with the simulation continuing based on the chosen decision.
8. Visualize network topology (host graph) for all three input modes, with attacker/victim IPs highlighted.
9. Benchmark against a logistic regression baseline (F1, precision, recall, FPR) and demonstrate cross-dataset generalization.
10. Ship as a one-command Docker deployment for judge evaluation.

---

## 3. Differentiators (what makes this submission unique)

| # | Differentiator | Why it matters |
|---|---|---|
| 1 | True World Model (RSSM-lite: encoder → latent transition → decoder), not a disguised LSTM classifier | Most teams will build a direct probability regressor and call it a "world model"; a real latent-rollout architecture is defensible under judge questioning |
| 2 | Counterfactual decision simulation (Accept/Modify/Reject → re-rollout) | Directly answers the PS's "interpretable decision support for defenders" line, which most teams will skip |
| 3 | GNN host-graph modeling (nodes = hosts, edges = flows) | Captures lateral movement / multi-host attack spread, not just per-flow anomalies |
| 4 | Cross-dataset generalization test (train on one dataset, zero-shot eval on another) | Concrete, benchmarkable proof of "generalises to unseen attack patterns" (a PS requirement almost no one will actually test) |
| 5 | Live home-network demo with real controlled attack → real detection → real intervention → re-measured risk drop | Closes the full loop (predict → decide → act → verify) live, not just a static dashboard |
| 6 | Local LLM (Ollama) as an explanation/narration layer only, never the decision-maker | Keeps the system deterministic/auditable while still reading like a SOC analyst tool |

---

## 4. Functional Requirements

### 4.1 Input & Ingestion
- FR1: Accept CSV upload (CIC/CTU-style flow records).
- FR2: Accept PCAP upload; extract flow + packet-level features via Scapy/PyShark.
- FR3: Accept live traffic capture from a network interface (sensor mode).
- FR4: All three paths must resolve to one unified, normalized feature schema (flow-level + packet-level fused).
- FR5: Build a network topology graph (hosts as nodes, flows as edges) from any of the three input sources.

### 4.2 World Model & Forecasting
- FR6: Represent network state as a structured feature vector/graph at time t.
- FR7: Learn P(S_t+1 | S_t) via latent transition model (GRU-based RSSM-lite) and/or GNN.
- FR8: Perform K-step rollout covering a 300-second (5-minute) forecast horizon from the current state.
- FR9: Output a time-series infiltration probability curve across the forecast horizon.
- FR10: Map each predicted future state to a MITRE ATT&CK stage.
- FR11: Report "early warning margin" — time between detection/alert and the predicted point of compromise.

### 4.3 Explainability
- FR12: Provide attention-weight or feature-attribution (Captum) output identifying which flags/ports/flow stats drove each prediction.
- FR13: Provide SHAP-based explanation for the logistic regression baseline.

### 4.4 Decision Support & Counterfactual Simulation
- FR14: When infiltration probability crosses an alert threshold, pause and present a recommended action (from a deterministic rule-engine keyed on MITRE stage + driving features).
- FR15: Offer three responses: **Accept**, **Modify** (choose an alternate action from a fixed set), **Reject** (no action).
- FR16: Re-run the K-step rollout from the decision point using the modified state, and display the new probability curve.
- FR17: In live mode, "Accept"/"Modify" must trigger a real network action (e.g., iptables rule) and the system must re-measure and display the actual resulting risk change.
- FR18: Generate an analyst-style natural-language explanation of each decision point using a local LLM (Ollama), clearly marked as descriptive/optional and never the source of the decision itself.

### 4.5 Topology Visualization
- FR19: Render host-graph topology for CSV/PCAP/live inputs alike.
- FR20: Highlight attacker IP(s) and victim IP(s) in distinct colors, derived from model output (not hardcoded).
- FR21: Update topology incrementally in live mode.

### 4.6 Benchmarking
- FR22: Train and evaluate a logistic regression baseline on the same unified features.
- FR23: Report F1, precision, recall, false positive rate for world model vs. baseline.
- FR24: Run a cross-dataset generalization test (train on dataset A, zero-shot evaluate on dataset B).

### 4.7 Deployment
- FR25: Package the full system (backend, model, dashboard, Ollama) as Docker images + docker-compose, published to Docker Hub, runnable in one command with the dashboard opening automatically.

---

## 5. Non-Functional Requirements

- NFR1: Must run **fully offline** — no cloud API dependencies (this is a hard PS requirement).
- NFR2: Model performance target: 80–85% on key metrics (F1/accuracy), achieved through legitimate means — class balancing, threshold tuning, feature engineering, and honest scenario scoping — **not** by curating/filtering data to artificially inflate the number (see rules.md for the standing policy on this).
- NFR3: UI must read as a professional security-analyst tool: subtle, restrained palette; no neon, no purple, no heavy glassmorphism/glow effects (see design.md).
- NFR4: Live inference loop must run within the window size (near real-time; sub-few-second latency per window).
- NFR5: Reproducibility — training scripts, model weights, and configs included and documented.
- NFR6: Explainability output must always accompany a prediction; black-box output alone is not acceptable per the PS.

---

## 6. Deliverables (per PS evaluation requirements)

1. Source code (GitHub/Drive link)
2. README with setup instructions
3. Architecture Document (max 2 pages) — condensed from `architecture.md`
4. Demo video (max 2 minutes)
5. Technical presentation (max 5 slides)
6. Docker Hub image + compose file for one-command judge evaluation

---

## 7. Datasets

- CIC-IDS-2017
- CIC-IDS-2018
- CTU-13
- UNSW-NB15
- CIC-IoT-2023

Used for: unified feature schema training, cross-dataset generalization testing, and MITRE ATT&CK stage label mapping (via a manually built attack-type → stage lookup, since these datasets are not natively ATT&CK-labeled).

---

## 8. Success Criteria (demo-day)

- Upload a CSV or PCAP → see a building probability curve across a simulated 5-minute horizon, with MITRE stage annotations.
- At the predicted attack point, see a recommended action with Accept/Modify/Reject, and see the simulation branch accordingly.
- Launch a controlled attack on the live home network (10–15 devices) → system detects it measurably earlier than compromise completion → apply the recommended action live → observe the model re-confirm reduced risk.
- Topology view correctly and visibly distinguishes attacker vs. victim IPs in all three input modes.
- Benchmark table shows world model beating logistic regression baseline, and holding up in a cross-dataset test.
- One-command Docker Hub deployment opens the working dashboard.
