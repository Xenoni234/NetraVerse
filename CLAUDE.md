# CLAUDE.md - NetraVerse (SIH 2026, PS 26153)

The five spec documents in the repo root are authoritative. Read them before changing behaviour:
`prd.md` (requirements), `architecture.md` (structure + interfaces), `rules.md` (R1-R22),
`phases.md` (build order), `design.md` (UI). Where code and spec disagree, flag it rather than
silently resolving it.

## Invariants
- One unified feature schema (`src/features/schema.py`); CSV, PCAP and live all go through
  `src/features/fusion.py::windowize` (R6).
- One model, one `rollout()` (`src/models/rollout.py`) for every input mode (R7). Risk shown to the
  analyst is always decoded from a latent state; forecasts come from prior-only imagination (R8).
- Decisions come from `src/decision/rule_engine.py` (deterministic). An LLM may only narrate (R9).
- Every surfaced forecast has an attribution (`src/explainability/captum_explainer.py`) (R5).
- Attacker/victim roles are derived in `src/graph/host_graph_builder.py::roles_at`, never hardcoded (R14).
- Fully offline at runtime (R10): the 3D bundle is vendored in `dashboard/components/topology3d/dist`.
- Report metrics as they come (R1/R2). Every tuning decision goes in README "Tuning decisions" (R20).

## Workflow
- `python -m src.training.build_dataset` -> `python -m src.training.train_world_model` ->
  `python -m src.training.train_baseline` -> `python -m src.training.cross_dataset_eval`.
- `pytest -q` must pass before committing.
- Commits: plain messages, **no Claude co-author / generated-by trailer** (user instruction).
