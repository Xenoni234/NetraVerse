# SIH Demo Showcase benchmark

This is the benchmark for the isolated `models/wm_sih_demo/best.ckpt` checkpoint
used by the SIH demonstration UI. It is a showcase checkpoint for the requested
six-stage, long-horizon workflow; it is not a claim of production accuracy.

## Held-out metrics

| Forecast horizon | Precision | Recall | PR-AUC |
|---|---:|---:|---:|
| +60s | 0.0674 | 1.0000 | 0.1078 |
| +90s | 0.0994 | 1.0000 | 0.1720 |
| +120s | 0.1319 | 1.0000 | 0.2494 |

Best mean validation PR-AUC: **0.1558**.

Each of the six supported stages has 18 held-out samples with 18 positive
samples in this run: Reconnaissance, Initial Access, Lateral Movement, Command &
Control, Exfiltration, and Impact.

## Attention result

The reported top-three attention concentration is **0.3012**. The aggregate mean
weights are close to uniform, so the correct UI interpretation is **diffuse
history** for this checkpoint/report—not evidence that one history window caused
the forecast.

## Scope and limitations

- The run combines mixed labelled CIC-derived demo suites with controlled
  synthetic six-stage episodes.
- False-positive rate and per-stage precision/recall/PR-AUC were not emitted by
  the current training report.
- Minimum/median warning lead time by horizon was not emitted by this run.
- A real server requires calibration and separate operational validation.
- Uploaded/live traffic remains prediction-only until trusted ground truth is
  available.

The machine-readable record is
[sih_demo_benchmark.json](sih_demo_benchmark.json), and the complete training
history remains in
`models/wm_sih_demo/finetune_report.json`.
