# Trained models

All checkpoints use the feature schema in `src/features/schema.py` (loading fails loudly if it
changes). Each `.pt` stores the weights plus everything needed to reproduce inference:
scaler statistics, Platt calibration, the validation-chosen threshold, the test metrics and the
`typical` reference window used in explanation sentences.
Load with `src.models.world_model.load_checkpoint(path)`.

| file | what it is | trained on | used by |
|---|---|---|---|
| `world_model.pt` + `training_config.yaml` | **Shipped model.** RSSM-lite + GraphSAGE, 60 s windows, 300 s rollout | CIC-IDS2017, CIC-IDS2018 (20-02), CTU-13, UNSW-NB15 | API / dashboard / live sensor |
| `baseline_logreg.pkl` | Logistic-regression baseline, same features and split (`{"model", "scaler", "threshold"}`) | same | `reports/baseline_main.json` |
| `world_model_nognn.pt` + `training_config_nognn.yaml` | Phase 5 ablation: identical but without GraphSAGE | same | `reports/wm_nognn.json` |
| `world_model_xsrc.pt` + `training_config_xsrc.yaml` | Phase 6 source model for zero-shot tests | CIC-IDS2017 + CIC-IDS2018 only | `reports/cross_dataset.json` |
| `world_model_xsrc_cn.pt` + `training_config_xsrc_cn.yaml` | Same, with per-capture normalisation (R4 experiment, rejected) | CIC-IDS2017 + CIC-IDS2018 only | `reports/cross_dataset_cn.json` |

To serve a different checkpoint, pass its path to `src.api.service.Engine(ckpt=...)`, or replace
`world_model.pt`. Retraining overwrites these files; see `docs/TRAINING.md`.
