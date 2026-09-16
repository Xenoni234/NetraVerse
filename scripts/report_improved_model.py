"""Write a human-readable report and conservative event lead times for a completed run."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts.improve_world_model import warning_lead_times
from src.data import windowing as W
from src.data.paths import REPO_ROOT
from src.eval import splits as S
from src.models.lstm_encoder_decoder import WorldModel


@torch.no_grad()
def original_dynamics(windows: pd.DataFrame, meta: pd.DataFrame, config: dict,
                      reference_scaler: dict) -> list[float]:
    """Score original means in the SAME transformed units as the new model."""
    payload = torch.load(REPO_ROOT/config['baseline_checkpoint'],map_location='cpu',weights_only=False)
    model = WorldModel.from_config(payload['model_config']).eval()
    model.load_state_dict(payload['state_dict'])
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model.to(device)
    lookup = windows.set_index(['campaign_id','entity_id','window_start'])[list(W.MODEL_COLUMNS)]
    def frames(offset: int) -> np.ndarray:
        idx = pd.MultiIndex.from_arrays([meta.campaign_id,meta.entity_id,
              meta.window_start+pd.to_timedelta(offset*W.STRIDE_SECONDS,unit='s')])
        return lookup.reindex(idx).to_numpy(dtype='float32')
    x = np.stack([frames(o) for o in range(1-W.HISTORY_LENGTH,1)],axis=1)
    y = np.stack([frames(o) for o in W.HORIZONS],axis=1)
    truth = W.apply_scaler(y,reference_scaler)[...,:model.config.state_size]
    x = W.apply_scaler(x,payload['scaler'])
    errors = np.zeros(len(W.HORIZONS))
    n = model.config.state_size
    for start in range(0,len(x),256):
        pred = model(torch.from_numpy(x[start:start+256]).to(device))['state_mean'].cpu().numpy()
        raw = pred*payload['scaler']['scale'][:n]+payload['scaler']['center'][:n]
        if payload['scaler']['method'] == 'signed_log':
            raw = np.sign(raw)*np.expm1(np.abs(raw))
        aligned = W.apply_scaler(raw,reference_scaler)
        errors += ((aligned-truth[start:start+256])**2).mean(-1).sum(0)
    return (errors/len(x)).tolist()


def main() -> None:
    directory = REPO_ROOT / 'models/wm_improved'
    config = json.loads((directory/'config.json').read_text())
    report = json.loads((directory/'metrics.json').read_text())
    payload = torch.load(directory/'best.ckpt',map_location='cpu',weights_only=False)
    predictions = np.load(directory/'test_predictions.npz')
    windows = pd.read_parquet(REPO_ROOT/config['cache'])
    if not (directory/'test_meta.parquet').exists():
        print('[report] reconstructing test metadata for event-level lead times',flush=True)
        test = S.chronological_split(windows,config=S.SplitConfig(time_col='window_start'),verbose=False)['test']
        batch = W.build_sequences(test)
        np.testing.assert_array_equal(batch.y_risk,predictions['truth'])
        batch.meta.to_parquet(directory/'test_meta.parquet',index=False)
    meta = pd.read_parquet(directory/'test_meta.parquet')
    report['dynamics']['original_scaled_mse'] = original_dynamics(windows,meta,config,payload['scaler'])
    labels = windows.set_index(['campaign_id','entity_id','window_start']).binary_label
    report['warning_lead_time'] = warning_lead_times(meta,predictions['risk'],np.array(payload['thresholds']),labels)
    (directory/'metrics.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    lines = ['# Corrected world-model experiment','',
             'Validation-selected candidate: **'+report['winner']+'**.', '',
             '**Do not replace wm_final with this candidate for attack alerts.** It improves',
             'state prediction error but regresses on test attack forecasting. Shuffling history',
             'does not reduce its longer-horizon AP, so this run does not establish useful temporal risk learning.', '',
             f'All rows below use the same {len(meta):,} continuous-clock test sequences. Historical',
             'scores over gap-skipping sequences are not directly comparable. This is a',
             'development benchmark on previously inspected data, not an untouched external test.', '',
             '| Model | Horizon | Precision | Recall | F1 | Average precision (PR-AUC) | FPR |',
             '|---|---:|---:|---:|---:|---:|---:|']
    for name in ['original_corrected_test','world_model','logistic_regression','persistence','shuffled_history']:
        for k,m in zip(W.HORIZONS,report[name]):
            lines.append(f"| {name} | {k*30}s | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} | {m['pr_auc']:.4f} | {m['fpr']:.4f} |")
    lines += ['', '## Dynamics', '',
              'MSE is evaluated in the new train-fitted signed-log standardized feature space.',
              'It cannot be compared numerically with the original raw-scaled training NLL.', '',
              '| Horizon | Model MSE | Original model MSE | Persistence MSE | Skill vs persistence |',
              '|---|---:|---:|---:|---:|']
    d = report['dynamics']
    for i,k in enumerate(W.HORIZONS):
        lines.append(f"| {k*30}s | {d['scaled_mse'][i]:.4f} | {d['original_scaled_mse'][i]:.4f} | {d['persistence_scaled_mse'][i]:.4f} | {d['skill_vs_persistence'][i]:.2%} |")
    lead = report['warning_lead_time']
    lines += ['', '## Warning lead time', '',json.dumps(lead,indent=2), '',
              'Lead is measured to the first attacked window start from the forecast window close.',
              'A next-window alert has zero guaranteed lead, not 30 seconds. Only events with',
              'a valid five-minute observed history and four future windows enter this denominator.', '',
              '## Limitations', '',
              '- Training has only 10 / 19 / 26 positive examples at 30 / 60 / 120 seconds.',
              '- All 30-second training positives come from Thursday; validation/test positives from Friday.',
              '- Existing cached features are reused. Raw timestamp drops and source-specific missing-feature masks remain unaudited.',
              '- No new PCAP features, held-out-family benchmark, or independent cross-dataset validation was added.',
              '- Negative subsampling and weighted loss change the training prior. Scores are not calibrated probabilities.',
              '- All models need additional independent attack episodes before operational use.', '',
              '## Reproduce', '', '```powershell',
              '.\\.venv\\Scripts\\python.exe -u scripts/improve_world_model.py',
              '.\\.venv\\Scripts\\python.exe -u scripts/report_improved_model.py', '```']
    destination = REPO_ROOT/'reports/world_model_improvement.md'
    destination.write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(destination)
    print(json.dumps(lead,indent=2))


if __name__ == '__main__':
    main()
