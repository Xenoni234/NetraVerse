# Corrected world-model experiment

**Follow-up:** this earlier experiment has been superseded by a timestamp and
missing-history audit. See [repaired pipeline results](pipeline_repair_results.md).
The tables below remain the historical record of the earlier experiment.

Validation-selected candidate: **risk_focused**.

**Do not replace wm_final with this candidate for attack alerts.** It improves
state prediction error but regresses on test attack forecasting. Shuffling history
does not reduce its longer-horizon AP, so this run does not establish useful temporal risk learning.

All rows below use the same 9,066 continuous-clock test sequences. Historical
scores over gap-skipping sequences are not directly comparable. This is a
development benchmark on previously inspected data, not an untouched external test.

| Model | Horizon | Precision | Recall | F1 | Average precision (PR-AUC) | FPR |
|---|---:|---:|---:|---:|---:|---:|
| original_corrected_test | 30s | 0.0357 | 0.1786 | 0.0595 | 0.0264 | 0.0149 |
| original_corrected_test | 60s | 0.0563 | 0.2093 | 0.0887 | 0.0443 | 0.0167 |
| original_corrected_test | 120s | 0.0822 | 0.3103 | 0.1300 | 0.0642 | 0.0223 |
| world_model | 30s | 0.0000 | 0.0000 | 0.0000 | 0.0083 | 0.0050 |
| world_model | 60s | 0.0000 | 0.0000 | 0.0000 | 0.0120 | 0.0062 |
| world_model | 120s | 0.0143 | 0.0172 | 0.0156 | 0.0189 | 0.0077 |
| logistic_regression | 30s | 0.0000 | 0.0000 | 0.0000 | 0.0022 | 0.0060 |
| logistic_regression | 60s | 0.0000 | 0.0000 | 0.0000 | 0.0047 | 0.0032 |
| logistic_regression | 120s | 0.0000 | 0.0000 | 0.0000 | 0.0069 | 0.0068 |
| persistence | 30s | 0.0000 | 0.0000 | 0.0000 | 0.0031 | 0.0000 |
| persistence | 60s | 0.0000 | 0.0000 | 0.0000 | 0.0047 | 0.0000 |
| persistence | 120s | 0.0000 | 0.0000 | 0.0000 | 0.0064 | 0.0000 |
| shuffled_history | 30s | 0.0000 | 0.0000 | 0.0000 | 0.0081 | 0.0044 |
| shuffled_history | 60s | 0.0000 | 0.0000 | 0.0000 | 0.0141 | 0.0063 |
| shuffled_history | 120s | 0.0429 | 0.0517 | 0.0469 | 0.0218 | 0.0074 |

## Dynamics

MSE is evaluated in the new train-fitted signed-log standardized feature space.
It cannot be compared numerically with the original raw-scaled training NLL.

| Horizon | Model MSE | Original model MSE | Persistence MSE | Skill vs persistence |
|---|---:|---:|---:|---:|
| 30s | 0.7230 | 0.9773 | 0.9149 | 20.97% |
| 60s | 0.7209 | 0.9822 | 0.6802 | -5.98% |
| 120s | 0.7382 | 1.0098 | 0.6808 | -8.42% |

## Warning lead time

{
  "eligible_events": 32,
  "alerted_events": 1,
  "events_warned_strictly_before_start": 1,
  "lead_seconds": [
    60.0
  ],
  "median_lead_seconds": 60.0,
  "definition": "Attack-window start minus forecast window close; eligible events only, no sustain requirement"
}

Lead is measured to the first attacked window start from the forecast window close.
A next-window alert has zero guaranteed lead, not 30 seconds. Only events with
a valid five-minute observed history and four future windows enter this denominator.

## Limitations

- Training has only 10 / 19 / 26 positive examples at 30 / 60 / 120 seconds.
- All 30-second training positives come from Thursday; validation/test positives from Friday.
- Existing cached features are reused. Raw timestamp drops and source-specific missing-feature masks remain unaudited.
- No new PCAP features, held-out-family benchmark, or independent cross-dataset validation was added.
- Negative subsampling and weighted loss change the training prior. Scores are not calibrated probabilities.
- All models need additional independent attack episodes before operational use.

## Reproduce

```powershell
.\.venv\Scripts\python.exe -u scripts/improve_world_model.py
.\.venv\Scripts\python.exe -u scripts/report_improved_model.py
```
