# Development guide

Read the five spec documents in the repo root first: `prd.md`, `architecture.md`, `rules.md`, `phases.md` and `design.md`. They are authoritative, and the rules R1–R22 are enforced in review.

## Repository layout

```
src/
  features/   schema.py (THE feature contract) · flow_features.py (CSV loaders) ·
              packet_features.py (Scapy flow assembler) · fusion.py (from_csv/from_pcap/from_live_window)
  graph/      host_graph_builder.py (graph, attacker/victim roles, topology snapshot) · graph_utils.py (GraphSAGE aggregation)
  models/     encoder.py · gnn.py · transition.py (RSSM) · decoder.py · world_model.py (+scaler, checkpoints)
              rollout.py (the ONE forecasting function) · baseline_logreg.py
  mitre/      mitre_lookup.py (label -> stage via data/mitre_mapping.yaml) · stage_mapper.py
  explainability/ captum_explainer.py (IG, per forecast) · shap_explainer.py (baseline)
  decision/   rule_engine.py (deterministic actions) · counterfactual.py · ollama_narration.py
  live/       sniffer.py (LiveMonitor) · live_flow_gen.py · windowing.py (ring buffer) · action_executor.py (nft)
  api/        main.py · routes_upload.py · routes_live.py · schemas.py · service.py (orchestration)
  training/   build_dataset.py · data.py (splits/sequences) · train_world_model.py · train_baseline.py ·
              evaluate.py · cross_dataset_eval.py · lab_dataset.py · report.py · configs/world_model.yaml
  utils/      config.py (all paths)
dashboard/    app.py · components/ (api_client, topology_view, probability_timeline, decision_panel,
              counterfactual_panel, topology3d/{src,dist}) · styles/theme.css
data/         mitre_mapping.yaml (tracked) · raw/ processed/ uploads/ (gitignored)
models/       trained checkpoints (tracked, see models/README.md)
reports/      benchmarks.md + JSON results (tracked; regenerate, never hand-edit numbers)
demo/         make_samples.py · demo_script.md · attack_scripts/ · fallback_pcap/ · samples/ (gitignored)
tests/        pytest suite + fixtures (small PCAPs)
docs/         this documentation
```

## The contracts (do not break these)

| Contract | Where | Rule |
|---|---|---|
| Flow table columns | `schema.FLOW_COLUMNS` | Every loader and the PCAP/live assembler emit exactly this. |
| Model input | `schema.FEATURE_COLUMNS` (31 = 17 outbound + 8 inbound + 3 packet + 3 masks, in this order) | Changing it **invalidates every checkpoint**; `load_checkpoint` refuses mismatches. Retrain after any change. |
| Windowing | `fusion.windowize` | The only place flows become windows (60 s, flow assigned to the window containing its end). |
| Forecast | `rollout.rollout` / `rollout.batch_forecast` | CSV, PCAP, live and counterfactuals all use these (R7). No mode-specific model. |
| Decisions | `rule_engine.recommend(stage, drivers, context)` | Deterministic. The LLM only narrates (R9). |
| Roles | `host_graph_builder.roles_at` | Derived from forecast + traffic direction, never hardcoded (R14). |

## Common tasks

**Add a new CSV format.** Add a loader in `flow_features.py` that returns `_finalise(df)` with `FLOW_COLUMNS`. Register it in `detect_format` / `load_flows`, and add a test in `tests/test_feature_fusion.py`.

**Add a training dataset.** Add an entry to `DATASETS` in `build_dataset.py` (a list of `(capture_name, loader)`). Add any new attack labels to `data/mitre_mapping.yaml`. Then run `build_dataset --datasets <name>` and add it to `data.train_datasets` in the config.

**Add a new action.** Add a kind to `ACTION_KINDS` and the stage rules in `rule_engine.py`. Then add its flow-level effect in `counterfactual.affected_mask`, and its nftables form in `action_executor.nft_commands`. Extend `tests/test_rule_engine.py`.

**Change the UI.** Follow `design.md`: flat graphite, a teal accent, and muted red-orange/amber/gray/green for roles. No neon, purple, gradients or blur. The 3D topology is the one exception: it keeps its glow, pulse and particles by team decision.

**Rebuild the 3D bundle.** Only needed after editing `dashboard/components/topology3d/src/topology.js`:

```bash
cd dashboard/components/topology3d
npm install            # installs three@0.186 + esbuild
npm run build          # -> dist/topology3d.js (commit this file)
```

The dashboard imports it from `<API>/static/topology3d.js`, served by FastAPI, because Streamlit's static serving does not send JS with the right MIME type.

## Tests

```bash
python -m pytest -q                       # full suite (~20 s)
python -m pytest -q tests/test_api.py     # end-to-end: needs models/world_model.pt + demo/samples
```

| File | Covers |
|---|---|
| `test_feature_fusion.py` | CSV and PCAP give an identical schema; the live path equals the PCAP path; masks; end-time windowing |
| `test_rollout.py` | 300 s horizon, intervention state, determinism, loss backprop |
| `test_rule_engine.py` | Every stage has an action and alternatives; counterfactual flow filtering; protected-IP guard |
| `test_api.py` | Upload, timeline, explain, topology, decision (accept/reject) |
| `test_live.py` | Packets, live flow generator, sliding windows, same service |
| `test_lab_dataset.py` | Lab schedule labelling |

## Working rules

- Branch from `rebuild`, open PRs back into it, and keep `pytest -q` green.
- **Never hand-edit numbers in reports.** Rerun the script and `python -m src.training.report`.
- Every tuning decision gets a line in [TRAINING.md](TRAINING.md#tuning-decisions) (R20), including rejected attempts.
- Model selection uses validation macro PR-AUC. **Never pick a model or threshold because a demo looks better** (R1/R2).
- Attack scripts only target your own lab devices (R11).
