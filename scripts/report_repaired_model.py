"""Summarize repaired-model evidence without comparing incompatible test splits."""
from __future__ import annotations
import json
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from src.data.paths import REPO_ROOT


def main() -> None:
    directory = REPO_ROOT/'models/wm_repaired'
    result = json.loads((directory/'metrics.json').read_text())
    experiments = json.loads((directory/'experiments.json').read_text())
    winner = result['winner']
    rows = ['# Repaired pipeline and world-model results', '',
            '**Completed:** real-data pipeline repair, three validation-selected training experiments, test evaluation, and offline inference checks.', '',
            f'Selected model: `{winner}`. Checkpoint: `models/wm_repaired/best.ckpt`.', '',
            '## What changed', '',
            '- Corrected unmarked 12-hour afternoon times in the CIC-IDS2017 WorkingHours CSVs. The original parser incorrectly placed afternoon captures before morning captures.',
            '- The dataset-specific repair is supported by the [official CIC-IDS2017 capture schedule](https://www.unb.ca/cic/datasets/ids-2017.html). Explicit AM/PM and ISO timestamps are preserved; live traffic is not shifted.',
            '- Verified that 288,602 discarded rows in Thursday morning are entirely empty CSV records, not lost timestamped flows. They are now reported as empty records.',
            '- Added an observed-history mask. Histories stay on the 30-second clock; missing past observations are marked unknown. All four future targets must actually exist, and the origin must be observed and benign.',
            '- Kept timestamps tied to one split, fixed mixed-dataset provenance, and versioned cache identity by source metadata, row caps, scenario selection and pipeline version.',
            '- Replaced per-window Python aggregation and trailing-statistics loops with equivalent vectorized calculations, with regression tests.',
            '- Retained the LSTM decoder, actual future-state loss, real labels, train-only scaling, and validation-only candidate/epoch/threshold selection.',
            '- Tested residual state prediction, explicit temporal differences, and cumulative onset probabilities. Validation selected the simpler architecture trained on repaired data.',
            '- No synthetic training, validation, or test records were added. No IP addresses, dates or campaign identifiers were added to model inputs.', '',
            '## Data support', '',
            '| Split | Examples | Positive at 30s | Positive at 60s | Positive at 120s |',
            '|---|---:|---:|---:|---:|']
    for name,a in result['audit'].items():
        rows.append(f"| {name} | {a['samples']} | {int(a['positives'][0])} | {int(a['positives'][1])} | {int(a['positives'][2])} |")
    rows += ['', 'This experiment uses the repaired CIC-IDS2017 corpus. CIC-IDS2018 and CTU-13 were not mixed back into this run: their coverage, row-cap effects and missing-feature semantics need separate validation.', '',
             '## Validation selection', '', '| Candidate | Mean validation average precision |', '|---|---:|']
    for e in experiments:
        rows.append(f"| {e['candidate']['name']} | {e['validation_mean_ap']:.4f} |")
    rows += ['', '## Test results on the same repaired examples', '',
             '| Model | Horizon | Precision | Recall | F1 | AP (PR-AUC) | FPR |',
             '|---|---:|---:|---:|---:|---:|---:|']
    for label,ms in [('World model',result[winner]['metrics']),('Logistic regression',result['logistic_regression']),
                     ('Persistence',result['persistence']),('Shuffled history',result['shuffled_history'])]:
        for horizon,m in zip([30,60,120],ms):
            rows.append(f"| {label} | {horizon}s | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} | {m['pr_auc']:.4f} | {m['fpr']:.4f} |")
    rows += ['', 'The world model still loses to logistic regression at 60 and 120 seconds. Shuffling histories does not hurt this run, so it does **not** establish that temporal ordering improves risk prediction.', '',
             '## Dynamics', '', '| Horizon | Model MSE | State-persistence MSE | Error reduction |', '|---|---:|---:|---:|']
    d = result[winner]['dynamics']
    for i,h in enumerate([30,60,120]):
        rows.append(f"| {h}s | {d['scaled_mse'][i]:.4f} | {d['persistence_scaled_mse'][i]:.4f} | {d['skill_vs_persistence'][i]:.1%} |")
    rows += ['', 'These are autonomous state forecasts in train-fitted signed-log standardized units; the comparator repeats the last observed state.', '',
             '## Warning lead time and limitations', '']
    lead = result[winner]['warning_lead_time']
    rows += [f"Only **{lead['eligible_events']} eligible events** exist in the test set. The model alerted on {lead['alerted_events']}, of which {lead['events_warned_strictly_before_start']} were strictly early.",
             f"Detected-event leads: {lead['lead_seconds']} seconds. A zero is an alert at the labelled event boundary, not early warning.", '',
             'Lead is measured from forecast-window close to the first attacked window start, using the matching forecast horizon. It concerns attack-labelled completed-flow windows, not independently verified compromise time. CSV timestamp precision also limits timing claims.', '',
             '**Do not compare the old published table directly with this table.** Clock repair changes both partition membership and eligible examples. The legacy checkpoint may already have seen traffic that is now in the repaired test split. Its descriptive scores are retained in `metrics.json`, but they are not an independent benchmark.', '',
             'The higher F1 than the previously published run does not prove general improvement. The dataset has already been inspected, the eligible test-event count is tiny, and no held-out-family, external-dataset or deployment evaluation was completed.', '',
             'The pipeline and training run are ready for further work; a claim of reliably beating the current benchmarks or the classical baseline is **not** supported.', '',
             '## Reproduce', '', '```powershell',
             '.\\.venv\\Scripts\\python.exe -u scripts/repair_data_pipeline.py',
             '.\\.venv\\Scripts\\python.exe -u scripts/train_repaired_model.py --config configs/repaired.yaml',
             '.\\.venv\\Scripts\\python.exe scripts/report_repaired_model.py',
             '.\\.venv\\Scripts\\python.exe -m pytest -q', '```', '',
             'In the offline demo, set Checkpoint to `models/wm_repaired/best.ckpt` and Recorded windows to `data/processed/windows_repaired_cicids2017_v2.parquet`. The original checkpoint remains available.']
    path = REPO_ROOT/'reports/pipeline_repair_results.md'
    path.write_text('\n'.join(rows)+'\n',encoding='utf-8')
    print(path)


if __name__ == '__main__':
    main()
