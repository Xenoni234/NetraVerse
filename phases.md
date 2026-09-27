# Development Phases — NetraVerse

Build order is dependency-driven (see `rules.md` R21): each phase must produce a working, testable artifact before the next begins. This lets you stop at any phase boundary and still have a demoable system.

---

## Phase 0 — Setup & Data Foundation
**Goal:** Environment ready, datasets loaded and understood.

- Set up Conda/`uv` environment; pin PyTorch, PyG, Scapy versions.
- Set up repo structure per `architecture.md` §4.
- Load all 5 datasets (CIC-IDS-2017/2018, CTU-13, UNSW-NB15, CIC-IoT-2023); inspect schemas, label formats, class balance.
- Draft the MITRE ATT&CK attack-type → stage lookup table (`data/mitre_mapping.yaml`).

**Exit criteria:** All datasets load cleanly into Polars; class distribution and available attack types documented.

---

## Phase 1 — Unified Feature Schema & Fusion Layer
**Goal:** One canonical feature vector, three ways in.

- Implement `flow_features.py` (NetFlow-style extraction from CSVs).
- Implement `packet_features.py` (Scapy extraction from PCAPs — TTL variance, window size, fragment flags, retransmissions, port-scan signature).
- Implement `fusion.py` with `from_csv()`, `from_pcap()`, `from_live_window()` — all returning the same schema (`schema.py`).
- Build the host-graph builder (`host_graph_builder.py`) from any of the three sources.
- Write unit tests confirming CSV-derived and PCAP-derived features for the *same* underlying traffic produce matching schema shape.

**Exit criteria:** A CIC-2018 CSV and a raw PCAP of comparable traffic both produce feature matrices with identical columns/ordering.

---

## Phase 2 — World Model Core (RSSM-lite)
**Goal:** A model that genuinely learns transition dynamics, proven on one dataset first.

- Implement encoder, GRU-based latent transition, decoder (`models/`).
- Train on one dataset first (e.g., CIC-IDS-2018) using supervised dynamics learning from labeled attack timelines.
- Implement `rollout.py`: `rollout(state, horizon, intervention=None)`.
- Train the logistic regression baseline on the same features.
- Evaluate both: F1, precision, recall, FPR (`evaluate.py`).

**Exit criteria:** World model outperforms logistic regression baseline on held-out CIC-2018 data; rollout produces a sane probability curve on a known-attack sample.

---

## Phase 3 — MITRE Mapping & Explainability
**Goal:** Predictions come with a stage label and a reason.

- Implement `stage_mapper.py` using the lookup table from Phase 0.
- Integrate Captum for attention/attribution extraction from the world model.
- Integrate SHAP for the baseline model (offline use only).

**Exit criteria:** Every rollout output includes a MITRE stage per window and a ranked list of driving features.

---

## Phase 4 — Decision Engine & Counterfactual Simulation
**Goal:** The core "wow" feature — Accept/Modify/Reject with a re-simulated future.

- Implement the deterministic rule-engine (`rule_engine.py`): stage + driving features → recommended action + alternatives list.
- Implement `counterfactual.py`: apply an intervention to the current state, call `rollout()` again, compute probability delta.
- Wire Accept/Modify/Reject logic end-to-end (still CLI/notebook-level at this point, no UI yet).

**Exit criteria:** Given a sample attack trajectory, applying the recommended action visibly reduces the rolled-out probability curve versus the "reject" branch.

---

## Phase 5 — GNN Host-Graph Layer
**Goal:** Model attack spread across hosts, not just single-flow trajectories.

- Implement GraphSAGE/GAT layer (PyG) over the host graph from Phase 1.
- Integrate with or alongside the RSSM (decide: GNN feeds into the encoder, or runs as a parallel signal).
- Re-evaluate benchmark metrics with the GNN included.

**Exit criteria:** Model shows measurable benefit on a lateral-movement/multi-host attack scenario compared to the non-GNN version.

---

## Phase 6 — Cross-Dataset Generalization
**Goal:** Prove the model isn't just memorizing one dataset.

- Train on one dataset, zero-shot evaluate on a different one (e.g., CIC-2018 → CTU-13).
- Document F1/precision/recall delta.
- If generalization is poor, address via feature normalization or targeted retraining — not by quietly dropping this test.

**Exit criteria:** Documented, honest cross-dataset benchmark table.

---

## Phase 7 — Backend API
**Goal:** Expose the pipeline over FastAPI for both file and live modes.

- `routes_upload.py`: CSV/PCAP endpoints → fusion → world model → rollout → response.
- `routes_live.py`: live-capture endpoint scaffold (windowed inference).
- Pydantic schemas for all request/response shapes.

**Exit criteria:** `curl`/Postman can upload a CSV and get back a full rollout + MITRE + explainability JSON response.

---

## Phase 8 — Live Capture Pipeline
**Goal:** The same model, fed by real-time traffic.

- Implement sniffer (`sniffer.py`) via Scapy/tshark.
- Implement windowing buffer (`windowing.py`) — Redis or in-process ring buffer.
- Implement live flow generation matching the unified schema.
- Implement incremental NetworkX host-graph updates.
- Implement `action_executor.py` for real interventions (e.g., iptables) in live mode.

**Exit criteria:** Live traffic on a test machine produces the same shape of rollout output as the file-upload path, using identical model weights.

---

## Phase 9 — Dashboard
**Goal:** The full interactive experience, styled per `design.md`.

- Streamlit app shell; upload widgets for CSV/PCAP.
- Probability timeline component (Plotly).
- Topology view component (Plotly network graph, attacker/victim highlighting).
- Decision panel (Accept/Modify/Reject) wired to the counterfactual engine.
- Live mode wiring (auto-refresh / WebSocket to backend).
- Apply `theme.css` — subtle, professional palette; no neon/purple/glassmorphism.

**Exit criteria:** A full run-through — upload → building curve → decision point → Accept → re-simulated curve — works end-to-end in the browser.

---

## Phase 10 — Local LLM Narration Layer (Ollama)
**Goal:** Analyst-style explanation text, optional and non-blocking.

- Set up Ollama with a small quantized model (Phi-3-mini or Llama-3.2-3B).
- Implement `ollama_narration.py`: structured decision → natural-language summary.
- Make the call async with a timeout/fallback (static templated text) if Ollama is slow or unavailable.

**Exit criteria:** Narration text appears alongside each decision point without blocking or breaking the core flow if disabled.

---

## Phase 11 — Live Home-Network Demo Prep
**Goal:** A rehearsed, repeatable, real attack-detection-intervention loop.

- Set up sensor machine + port mirroring/ARP-based capture on home network (10–15 devices).
- Script the controlled attack sequence: recon (Nmap) → brute force (Hydra) → simulated lateral movement.
- Record a fallback PCAP of this exact sequence.
- Rehearse the full loop: baseline → attack → detection → decision → real action → re-confirmed risk drop.

**Exit criteria:** The loop runs successfully at least twice in a row without manual intervention beyond the Accept/Modify click.

---

## Phase 12 — Benchmarking Write-up & Documentation
**Goal:** Defensible numbers, clean docs.

- Finalize benchmark tables (baseline vs. world model, cross-dataset).
- Condense `architecture.md` into the 2-page Architecture Document deliverable.
- Write README with setup instructions.
- Document every tuning decision (thresholds, class weights, scoping) per `rules.md` R20.

**Exit criteria:** All PS-required documents drafted and reviewed.

---

## Phase 13 — Dockerization & Packaging
**Goal:** One-command judge deployment.

- Write `Dockerfile.backend`, `Dockerfile.dashboard`, `docker-compose.yml`.
- Include Ollama (and Redis if used) as services.
- Test `docker-compose up` on a clean machine/VM — confirm dashboard opens with no extra steps.
- Push images to Docker Hub.

**Exit criteria:** A machine with no prior setup can run one command and reach the working dashboard.

---

## Phase 14 — Demo Video & Presentation
**Goal:** Final deliverables assembled.

- Record the 2-minute demo video following the rehearsed narrative arc (baseline → attack escalation → detection+explanation → decision → re-rollout showing risk reduction).
- Build the 5-slide technical presentation.
- Final review against `prd.md` §8 (Success Criteria).

**Exit criteria:** All 5 PS deliverables complete and reviewed against the original problem statement one final time.

---

## Suggested Priority Tiers (if time runs short)

- **Must-ship (core grading):** Phases 0–4, 7, 9 (file-upload path only), 12.
- **High-value if time permits:** Phase 5 (GNN), Phase 6 (cross-dataset), Phase 8 (live), Phase 11 (live demo).
- **Polish tier:** Phase 10 (Ollama narration), Phase 13 (Docker), full topology highlighting refinement.
