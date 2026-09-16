"""Train and evaluate repaired real-data models; select ONLY on validation AP."""
from __future__ import annotations
import argparse
import json
import sys
import time
from dataclasses import asdict
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from omegaconf import OmegaConf
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts.improve_world_model import epoch, dynamics, thresholds, metrics, subset, warning_lead_times
from scripts.train_world_model import to_loader, predict_probs, set_seed
from src.data import windowing as W
from src.data.paths import REPO_ROOT
from src.models import get_device
from src.models.lstm_encoder_decoder import WorldModel, WorldModelConfig
from src.models.losses import MultiTaskLoss, LossWeights
from src.mitre.stage_mapping import N_STAGES


def main() -> None:
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--config',type=Path,default=REPO_ROOT/'configs/repaired.yaml')
    args = parser.parse_args()
    cfg = OmegaConf.to_container(OmegaConf.load(args.config),resolve=True)
    directory = REPO_ROOT/cfg['output']; directory.mkdir(parents=True,exist_ok=True)
    (directory/'config.json').write_text(json.dumps(cfg,indent=2),encoding='utf-8')
    device = get_device('auto'); torch.set_num_threads(cfg['cpu_threads'])
    set_seed(cfg['seed'])
    seq = {name:W.load_sequences(REPO_ROOT/f"{cfg['sequence_prefix']}_{name}_masked_v2.npz") for name in ('train','val','test')}
    train = seq['train']
    audit = {name:{'samples':len(b.x),'positives':b.y_risk.sum(0).tolist(),
                   'observed_history_fraction':float(b.x[:,:,-1].mean())} for name,b in seq.items()}
    print('[audit]',json.dumps(audit),flush=True)
    (directory/'audit.json').write_text(json.dumps(audit,indent=2),encoding='utf-8')
    scaler = W.fit_scaler(train.x,method='signed_log',mask_tail=len(W.MASK_COLUMNS)+1)
    loaders = {name:to_loader(b,scaler,cfg['batch_size'],name=='train') for name,b in seq.items()}
    windows = pd.read_parquet(REPO_ROOT/cfg['window_cache'])
    labels = windows.set_index(['campaign_id','entity_id','window_start']).binary_label
    normal = train.y_risk.max(1)==0
    for offset in range(W.HISTORY_LENGTH):
        keys = pd.MultiIndex.from_arrays([train.meta.campaign_id,train.meta.entity_id,
                train.meta.window_start-pd.to_timedelta(offset*W.STRIDE_SECONDS,unit='s')])
        # Missing observations may enter supervised training via masks, but do
        # not qualify as known-normal history for benign dynamics pretraining.
        normal &= labels.reindex(keys).fillna(1).to_numpy()==0
    preloader = to_loader(subset(train,np.flatnonzero(normal)),scaler,cfg['batch_size'],True)
    best_score, winner, experiments = -1., None, []
    for candidate in cfg['candidates']:
        set_seed(cfg['seed'])
        model = WorldModel(WorldModelConfig(input_size=train.x.shape[-1],state_size=len(W.STATE_FEATURE_COLUMNS),
                      hidden_size=cfg['hidden_size'],n_stages=N_STAGES,
                      **{k:candidate[k] for k in ('residual_state','temporal_deltas','cumulative_risk')})).to(device)
        opt = torch.optim.AdamW(model.parameters(),lr=cfg['lr'],weight_decay=1e-4)
        pre = MultiTaskLoss(risk_enabled=False,stage_enabled=False).to(device)
        criterion = MultiTaskLoss(LossWeights(state=candidate['state_weight'],risk=2.,stage=.25),pos_weight=cfg['pos_weight']).to(device)
        for ep in range(cfg['pretrain_epochs']):
            print(candidate['name'],'pretrain',ep+1,epoch(model,preloader,pre,opt,device),flush=True)
        local_best, stale, history = -1.,0,[]
        for ep in range(cfg['epochs']):
            start = time.perf_counter()
            losses = epoch(model,loaders['train'],criterion,opt,device)
            p,y,_,_ = predict_probs(model,loaders['val'],device)
            scores = [float(average_precision_score(y[:,i],p[:,i])) for i in range(y.shape[1])]
            score = float(np.mean(scores))
            entry = {'epoch':ep+1,'losses':losses,'val_ap':scores,'seconds':time.perf_counter()-start}
            history.append(entry)
            print(candidate['name'],entry,flush=True)
            if score>local_best:
                local_best,stale = score,0
                payload = {'state_dict':{k:v.detach().cpu().clone() for k,v in model.state_dict().items()},
                           'model_config':asdict(model.config),'scaler':scaler,'feature_names':list(train.feature_names),
                           'thresholds':thresholds(y,p).tolist(),'threshold':float(thresholds(y,p)[0]),
                           'horizons':list(W.HORIZONS),'history_length':W.HISTORY_LENGTH,
                           'sequence_policy':'masked_history_30s','min_observed_history':3,
                           'pipeline_version':'clock-repair-v2','synthetic_training_rows':0,
                           'validation_mean_ap':score,'epoch':ep+1,'candidate':candidate}
                torch.save(payload,directory/f"{candidate['name']}.ckpt")
            else:
                stale+=1
            if stale>=cfg['patience']:
                break
        experiments.append({'candidate':candidate,'validation_mean_ap':local_best,'history':history})
        if local_best>best_score:
            best_score,winner = local_best,candidate['name']
        (directory/'experiments.json').write_text(json.dumps(experiments,indent=2),encoding='utf-8')
    report = {'winner':winner,'audit':audit,'comparison_warning':
              'Legacy wm_final trained with incorrect clocks; it may have seen repaired-test traffic. Its scores are descriptive, not an independent baseline.'}
    predictions = {'truth':seq['test'].y_risk}
    for name in dict.fromkeys(['repaired_baseline',winner]):
        payload = torch.load(directory/f'{name}.ckpt',map_location='cpu',weights_only=False)
        model = WorldModel.from_config(payload['model_config']).to(device)
        model.load_state_dict(payload['state_dict'])
        p,y,_,_ = predict_probs(model,loaders['test'],device)
        cuts = np.array(payload['thresholds'])
        report[name] = {'metrics':metrics(y,p,cuts),'dynamics':dynamics(model,loaders['test'],device),
                        'warning_lead_time':warning_lead_times(seq['test'].meta,p,cuts,labels)}
        predictions[name] = p
        if name == winner:
            torch.save(payload,directory/'best.ckpt')
            shuffled = seq['test'].x.copy()
            rng = np.random.default_rng(cfg['seed'])
            for row in shuffled:
                rng.shuffle(row,axis=0)
            ablation = W.SequenceBatch(shuffled,seq['test'].y_state,y,seq['test'].y_stage,seq['test'].meta)
            sp,_,_,_ = predict_probs(model,to_loader(ablation,scaler,cfg['batch_size'],False),device)
            report['shuffled_history'] = metrics(y,sp,cuts)
    # Classical baseline shares training examples, features and per-horizon calibration.
    x = {name:W.apply_scaler(b.x,scaler).reshape(len(b.x),-1) for name,b in seq.items()}
    lp = np.zeros_like(y); vp = np.zeros_like(seq['val'].y_risk)
    for i in range(y.shape[1]):
        lr = LogisticRegression(max_iter=1500,class_weight='balanced')
        lr.fit(x['train'],train.y_risk[:,i])
        lp[:,i] = lr.predict_proba(x['test'])[:,1]
        vp[:,i] = lr.predict_proba(x['val'])[:,1]
    report['logistic_regression'] = metrics(y,lp,thresholds(seq['val'].y_risk,vp))
    report['persistence'] = metrics(y,np.zeros_like(y),np.full(y.shape[1],.5))
    old = torch.load(REPO_ROOT/'models/wm_final/best.ckpt',map_location='cpu',weights_only=False)
    model = WorldModel.from_config(old['model_config']).to(device); model.load_state_dict(old['state_dict'])
    b = seq['test']
    legacy = W.SequenceBatch(b.x[:,:,:-1],b.y_state[:,:,:-1],b.y_risk,b.y_stage,b.meta)
    op,_,_,_ = predict_probs(model,to_loader(legacy,old['scaler'],cfg['batch_size'],False),device)
    report['legacy_reference_only'] = metrics(y,op,np.full(y.shape[1],old['threshold']))
    predictions['legacy_reference_only'],predictions['logistic_regression'] = op,lp
    np.savez_compressed(directory/'predictions.npz',**predictions)
    seq['test'].meta.to_parquet(directory/'test_meta.parquet',index=False)
    (directory/'metrics.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('[done]',json.dumps(report,indent=2),flush=True)


if __name__ == '__main__':
    main()
