# Project Rules — NetraVerse

Standing rules for building this project — technical, evaluation-integrity, and demo rules. When in doubt, these override convenience.

---

## 1. Model Integrity Rules

- **R1 — No data curation to hit a target metric.** The 80–85% performance target must be reached through legitimate means only: class balancing (weighting/SMOTE-style techniques for the minority attack class), threshold tuning, proper feature engineering, and honest scenario scoping (picking attack categories where temporal modeling has a genuine edge). Never filter, cherry-pick, or manipulate the dataset specifically to inflate a reported number. If a judge asks how the number was validated, the answer must hold up.
- **R2 — Report the truth even if it's below target.** If after legitimate tuning the model lands at, say, 74%, report 74% and explain why, rather than adjusting data to reach the target range. A defensible 74% beats an indefensible 85%.
- **R3 — Always benchmark against the logistic regression baseline** on the exact same features — this comparison is a required deliverable, not optional polish.
- **R4 — Cross-dataset generalization must be a real zero-shot test** (train on dataset A, evaluate on dataset B with no fine-tuning) — not a re-split of the same dataset relabeled as "generalization."
- **R5 — No black-box output.** Every prediction the system surfaces must be accompanied by an explainability output (attention/SHAP-derived driving features). This is an explicit PS requirement, not a nice-to-have.

## 2. Architecture Rules

- **R6 — One unified feature schema.** CSV, PCAP, and live inputs must all resolve to the exact same feature vector definition and ordering before touching the model. Never let the three paths drift into separate schemas — this was the root cause of the original CSV/PCAP/live pipelines fighting each other.
- **R7 — One model, one rollout function.** CSV, PCAP, and live modes call the same trained weights and the same `rollout()` function. Never train or maintain separate models per input mode.
- **R8 — The world model must genuinely learn transition dynamics** (encoder → latent transition → decoder, i.e., a real RSSM-lite), not a disguised direct regression from raw features to probability. If asked, the team must be able to explain the distinction.
- **R9 — The decision engine is deterministic, not LLM-based.** The Ollama/local-LLM layer only narrates a decision already produced by the rule-engine; it must never be the source of the recommended action, and the system must remain fully functional if the LLM layer is disabled or slow.
- **R10 — Fully offline.** No component may depend on a cloud API at runtime. This is a hard PS requirement (NFR1) and a Docker acceptance criterion.

## 3. Live Demo Rules

- **R11 — Attack only your own devices/network.** Nmap/Hydra/pivot demonstrations are confined to devices and networks you own or have explicit permission to test. Never target anything outside your own LAN.
- **R12 — Always have a fallback.** A pre-recorded PCAP of the exact demo attack sequence must exist and be replayable through the file-upload path in case live capture fails during judging.
- **R13 — Real actions in live mode.** When Accept/Modify is chosen during the live demo, the system must apply a real mitigation (e.g., an actual iptables rule) and re-measure actual traffic — not merely a simulated internal state change. The "prevention loop" is the headline feature; it must be real.
- **R14 — Attacker/victim IP identification must be derived from model output**, not hardcoded for the demo. If the labeling logic is faked for the sake of a clean demo, say so nowhere — don't fake it; make the derivation logic actually work on the captured traffic.

## 4. UI/UX Rules

- **R15 — No "AI-generated" visual clichés.** No neon colors, no purple/violet accents, no glassmorphism, no heavy glow/blur effects, no gradient-as-decoration. See `design.md` for the enforced palette and style.
- **R16 — Dashboard must read like a SOC/analyst tool** (Grafana/Datadog-adjacent), not a marketing landing page.
- **R17 — The Accept/Modify/Reject flow must always show a re-simulated forward curve** after any decision — a decision without a visible consequence undermines the entire "decision support" pitch.

## 5. Reproducibility & Delivery Rules

- **R18 — Every trained model ships with its training config and weights.** No "trust me, it trains this way" — the PS explicitly requires this.
- **R19 — One-command deployment.** `docker-compose up` (or equivalent) must bring up the full stack and land the judge on a working dashboard, with no manual setup steps beyond that command.
- **R20 — Document every manual/tuning decision** (thresholds, class weights, attack-category scoping) in the architecture doc or README so it can be explained and defended, not just quietly applied.

## 6. Scope Discipline

- **R21 — Build in dependency order**, not feature-popularity order: unified schema → world model core → rollout → rule engine → counterfactual → GNN → live pipeline → LLM narration → polish. Each layer must work before the next is added (see `phases.md`).
- **R22 — Every added feature must reuse the same core rollout/decision contract** (see `architecture.md` §5). If a new feature needs a special-case path, that's a signal to refactor the interface, not to fork the pipeline.
