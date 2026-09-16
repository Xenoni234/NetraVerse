# Repaired pipeline and world-model results

**Completed:** real-data pipeline repair, three validation-selected training experiments, test evaluation, and offline inference checks.

Selected model: `repaired_baseline`. Checkpoint: `models/wm_repaired/best.ckpt`.

## What changed

- Corrected unmarked 12-hour afternoon times in the CIC-IDS2017 WorkingHours CSVs. The original parser incorrectly placed afternoon captures before morning captures.
- The dataset-specific repair is supported by the [official CIC-IDS2017 capture schedule](https://www.unb.ca/cic/datasets/ids-2017.html). Explicit AM/PM and ISO timestamps are preserved; live traffic is not shifted.
- Verified that 288,602 discarded rows in Thursday morning are entirely empty CSV records, not lost timestamped flows. They are now reported as empty records.
- Added an observed-history mask. Histories stay on the 30-second clock; missing past observations are marked unknown. All four future targets must actually exist, and the origin must be observed and benign.
- Kept timestamps tied to one split, fixed mixed-dataset provenance, and versioned cache identity by source metadata, row caps, scenario selection and pipeline version.
- Replaced per-window Python aggregation and trailing-statistics loops with equivalent vectorized calculations, with regression tests.
- Retained the LSTM decoder, actual future-state loss, real labels, train-only scaling, and validation-only candidate/epoch/threshold selection.
- Tested residual state prediction, explicit temporal differences, and cumulative onset probabilities. Validation selected the simpler architecture trained on repaired data.
- No synthetic training, validation, or test records were added. No IP addresses, dates or campaign identifiers were added to model inputs.

## Data support

| Split | Examples | Positive at 30s | Positive at 60s | Positive at 120s |
|---|---:|---:|---:|---:|
| train | 12424 | 146 | 217 | 274 |
| val | 4019 | 14 | 27 | 45 |
| test | 3702 | 6 | 10 | 16 |

This experiment uses the repaired CIC-IDS2017 corpus. CIC-IDS2018 and CTU-13 were not mixed back into this run: their coverage, row-cap effects and missing-feature semantics need separate validation.

## Validation selection

| Candidate | Mean validation average precision |
|---|---:|
| repaired_baseline | 0.3120 |
| residual_deltas | 0.1603 |
| cumulative_dynamics | 0.1424 |

## Test results on the same repaired examples

| Model | Horizon | Precision | Recall | F1 | AP (PR-AUC) | FPR |
|---|---:|---:|---:|---:|---:|---:|
| World model | 30s | 0.0870 | 0.3333 | 0.1379 | 0.0952 | 0.0057 |
| World model | 60s | 0.1818 | 0.4000 | 0.2500 | 0.1667 | 0.0049 |
| World model | 120s | 0.1875 | 0.5625 | 0.2812 | 0.2311 | 0.0106 |
| Logistic regression | 30s | 0.1667 | 0.3333 | 0.2222 | 0.0564 | 0.0027 |
| Logistic regression | 60s | 0.1667 | 0.8000 | 0.2759 | 0.2363 | 0.0108 |
| Logistic regression | 120s | 0.3333 | 0.7500 | 0.4615 | 0.3630 | 0.0065 |
| Persistence | 30s | 0.0000 | 0.0000 | 0.0000 | 0.0016 | 0.0000 |
| Persistence | 60s | 0.0000 | 0.0000 | 0.0000 | 0.0027 | 0.0000 |
| Persistence | 120s | 0.0000 | 0.0000 | 0.0000 | 0.0043 | 0.0000 |
| Shuffled history | 30s | 0.1250 | 0.5000 | 0.2000 | 0.1140 | 0.0057 |
| Shuffled history | 60s | 0.2105 | 0.4000 | 0.2759 | 0.1997 | 0.0041 |
| Shuffled history | 120s | 0.2667 | 0.5000 | 0.3478 | 0.3034 | 0.0060 |

The world model still loses to logistic regression at 60 and 120 seconds. Shuffling histories does not hurt this run, so it does **not** establish that temporal ordering improves risk prediction.

## Dynamics

| Horizon | Model MSE | State-persistence MSE | Error reduction |
|---|---:|---:|---:|
| 30s | 0.6719 | 1.4137 | 52.5% |
| 60s | 0.6479 | 0.8171 | 20.7% |
| 120s | 0.6786 | 0.8994 | 24.5% |

These are autonomous state forecasts in train-fitted signed-log standardized units; the comparator repeats the last observed state.

## Warning lead time and limitations

Only **6 eligible events** exist in the test set. The model alerted on 4, of which 3 were strictly early.
Detected-event leads: [30.0, 30.0, 90.0, 0.0] seconds. A zero is an alert at the labelled event boundary, not early warning.

Lead is measured from forecast-window close to the first attacked window start, using the matching forecast horizon. It concerns attack-labelled completed-flow windows, not independently verified compromise time. CSV timestamp precision also limits timing claims.

**Do not compare the old published table directly with this table.** Clock repair changes both partition membership and eligible examples. The legacy checkpoint may already have seen traffic that is now in the repaired test split. Its descriptive scores are retained in `metrics.json`, but they are not an independent benchmark.

The higher F1 than the previously published run does not prove general improvement. The dataset has already been inspected, the eligible test-event count is tiny, and no held-out-family, external-dataset or deployment evaluation was completed.

The pipeline and training run are ready for further work; a claim of reliably beating the current benchmarks or the classical baseline is **not** supported.

## Reproduce

```powershell
.\.venv\Scripts\python.exe -u scripts/repair_data_pipeline.py
.\.venv\Scripts\python.exe -u scripts/train_repaired_model.py --config configs/repaired.yaml
.\.venv\Scripts\python.exe scripts/report_repaired_model.py
.\.venv\Scripts\python.exe -m pytest -q
```

In the offline demo, set Checkpoint to `models/wm_repaired/best.ckpt` and Recorded windows to `data/processed/windows_repaired_cicids2017_v2.parquet`. The original checkpoint remains available.
