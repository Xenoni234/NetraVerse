"""Reproducible validation-selected experiments with clock-correct forecasts.

Uses an existing window cache; never overwrites the original checkpoint.
Only training negatives are subsampled. Validation/test keep natural prevalence.
"""
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
from sklearn.metrics import average_precision_score, precision_recall_curve

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.train_world_model import set_seed, to_loader, predict_probs
from src.data import windowing as W
from src.data.paths import REPO_ROOT
from src.eval import metrics as M, splits as S
from src.models import get_device
from src.models.lstm_encoder_decoder import WorldModel, WorldModelConfig
from src.models.losses import LossWeights, MultiTaskLoss
from src.mitre.stage_mapping import N_STAGES


def subset(batch: W.SequenceBatch, indices: np.ndarray) -> W.SequenceBatch:
    return W.SequenceBatch(batch.x[indices], batch.y_state[indices], batch.y_risk[indices],
                           batch.y_stage[indices], batch.meta.iloc[indices].reset_index(drop=True),
                           batch.feature_names, batch.future[indices])


def thresholds(y: np.ndarray, p: np.ndarray) -> np.ndarray:
    result = []
    for i in range(y.shape[1]):
        precision, recall, cuts = precision_recall_curve(y[:, i], p[:, i])
        f1 = 2 * precision[:-1] * recall[:-1] / np.maximum(precision[:-1] + recall[:-1], 1e-12)
        result.append(float(cuts[np.argmax(f1)]) if y[:, i].sum() else 1.0)
    return np.array(result)


def metrics(y: np.ndarray, p: np.ndarray, cuts: np.ndarray) -> list[dict]:
    return [M.compute_all_metrics(y[:, i], p[:, i] >= cuts[i], p[:, i], threshold=cuts[i])
            for i in range(y.shape[1])]


def warning_lead_times(meta: pd.DataFrame, risk: np.ndarray, cuts: np.ndarray,
                       labels: pd.Series, horizons: np.ndarray | None = None) -> dict:
    """Lead to first attacked window start, measured from observed window CLOSE.

    Denominator is only events with an eligible continuous-history forecast.
    This does not claim coverage of attacks lacking observable benign history.
    """
    horizon_values = np.asarray(horizons if horizons is not None else W.HORIZONS, dtype=int)
    delay = np.full(len(meta), np.inf)
    for step in range(1, int(horizon_values.max()) + 1):
        idx = pd.MultiIndex.from_arrays([meta.campaign_id, meta.entity_id,
              meta.window_start + pd.to_timedelta(step * W.STRIDE_SECONDS, unit="s")])
        attack = labels.reindex(idx).fillna(0).to_numpy() > 0
        delay[np.isinf(delay) & attack] = step
    eligible = np.isfinite(delay)
    rows = meta.loc[eligible, ["campaign_id", "entity_id", "window_start"]].copy()
    rows["event_start"] = rows.window_start + pd.to_timedelta(delay[eligible] * W.STRIDE_SECONDS, unit="s")
    rows["lead_seconds"] = (delay[eligible] - 1) * W.STRIDE_SECONDS
    rows["alert"] = ((risk[eligible] >= cuts) &
                     (horizon_values[None, :] >= delay[eligible, None])).any(axis=1)
    events = rows.groupby(["campaign_id", "entity_id", "event_start"])
    warned = rows[rows.alert].groupby(["campaign_id", "entity_id", "event_start"]).lead_seconds.max()
    return {"eligible_events": len(events), "alerted_events": len(warned),
            "events_warned_strictly_before_start": int((warned > 0).sum()),
            "lead_seconds": warned.tolist(),
            "median_lead_seconds": float(warned.median()) if len(warned) else None,
            "definition": "Attack-window start minus forecast window close; eligible events only, no sustain requirement"}


def epoch(model: WorldModel, loader, criterion, optimizer, device: torch.device) -> dict:
    model.train()
    totals, count = {}, 0
    for x, state, risk, stage, _ in loader:
        x, state, risk, stage = [v.to(device) for v in (x, state, risk, stage)]
        # Train the same autonomous rollout used at inference: no future labels or
        # teacher-forced attack states can leak into longer-horizon risk heads.
        out = model(x)
        loss, parts = criterion(out, {"state": state[..., :model.config.state_size],
                                      "risk": risk, "stage": stage})
        if not torch.isfinite(loss):
            raise RuntimeError("Non-finite loss; refusing to save an invalid model")
        optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()
        for key, value in parts.items():
            totals[key] = totals.get(key, 0.0) + value * len(x)
        count += len(x)
    return {k: v / count for k, v in totals.items()}


@torch.no_grad()
def dynamics(model: WorldModel, loader, device: torch.device) -> dict:
    model.eval()
    horizon_count = int(model.config.horizons.__len__())
    err = np.zeros(horizon_count)
    persistence = err.copy()
    count = 0
    for x, state, _, _, _ in loader:
        x, state = x.to(device), state.to(device)
        truth = state[..., :model.config.state_size]
        pred = model(x)["state_mean"]
        err += ((pred - truth) ** 2).mean(-1).sum(0).cpu().numpy()
        persistence += ((x[:, -1:, :model.config.state_size] - truth) ** 2).mean(-1).sum(0).cpu().numpy()
        count += len(x)
    return {"scaled_mse": (err / count).tolist(),
            "persistence_scaled_mse": (persistence / count).tolist(),
            "skill_vs_persistence": (1 - err / np.maximum(persistence, 1e-12)).tolist()}


def main() -> None:
    ap = argparse.ArgumentParser(__doc__)
    ap.add_argument("--config", type=Path, default=REPO_ROOT / "configs/train.yaml")
    args = ap.parse_args()
    cfg = OmegaConf.to_container(OmegaConf.load(args.config), resolve=True)["improvement"]
    outdir = REPO_ROOT / cfg["output"]
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "config.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    torch.set_num_threads(cfg["cpu_threads"])
    device = get_device("auto")
    set_seed(cfg["seed"])
    print(f"[start] device={device} output={outdir}", flush=True)
    windows = pd.read_parquet(REPO_ROOT / cfg["cache"])
    parts = S.chronological_split(windows, config=S.SplitConfig(time_col="window_start"))
    S.assert_no_leakage(parts, S.SplitConfig(time_col="window_start"))
    seq = {}
    audit = {}
    for name, frame in parts.items():
        print(f"[prepare] {name}: enforcing 30-second continuity", flush=True)
        seq[name] = W.build_sequences(frame, target="onset")
        b = seq[name]
        counts = b.meta.assign(positive=b.y_risk[:, 0]).groupby("campaign_id")["positive"].agg(["size", "sum"])
        audit[name] = {"sequences": len(b.x), "positives": b.y_risk.sum(0).tolist(),
                       "campaigns": counts.to_dict("index")}
        print(f"[audit] {name}: {audit[name]}", flush=True)
    (outdir / "audit.json").write_text(json.dumps(audit, indent=2), encoding="utf-8")
    del windows, parts
    train = seq["train"]
    if np.any(train.y_risk.sum(0) == 0):
        raise RuntimeError("No training positives at a horizon; data support must be repaired first")
    rng = np.random.default_rng(cfg["seed"])
    positives = np.flatnonzero(train.y_risk.max(1) > 0)
    negatives = np.flatnonzero(train.y_risk.max(1) == 0)
    selected = np.sort(np.r_[positives, rng.choice(negatives, min(len(negatives), cfg["negative_cap"]), replace=False)])
    # Normal pretraining excludes attack states anywhere in the history or rollout:
    # ongoing labels are not in the feature matrix, so use the known window labels.
    # For onset-origin samples, y_risk[-1]==0 guarantees no future attack; exclude
    # prior-attack histories using the window label lookup below.
    cached_labels = pd.read_parquet(REPO_ROOT / cfg["cache"], columns=["campaign_id", "entity_id", "window_start", "binary_label"])
    lookup = cached_labels.set_index(["campaign_id", "entity_id", "window_start"])["binary_label"]
    normal = np.ones(len(train.x), dtype=bool)
    for offset in range(W.HISTORY_LENGTH):
        idx = pd.MultiIndex.from_arrays([train.meta.campaign_id, train.meta.entity_id,
              train.meta.window_start - pd.to_timedelta(offset * W.STRIDE_SECONDS, unit="s")])
        normal &= lookup.reindex(idx).fillna(1).to_numpy() == 0
    normal &= train.y_risk.max(1) == 0
    normal_indices = np.flatnonzero(normal)
    normal_indices = rng.choice(normal_indices, min(len(normal_indices), cfg["pretrain_cap"]), replace=False)
    scaler = W.fit_scaler(train.x, method="signed_log")
    loaders = {name: to_loader(b, scaler, cfg["batch_size"], False) for name, b in seq.items() if name != "train"}
    train_loader = to_loader(subset(train, selected), scaler, cfg["batch_size"], True)
    normal_loader = to_loader(subset(train, normal_indices), scaler, cfg["batch_size"], True)
    print(f"[train] {len(positives)} positive-any-horizon + {len(selected)-len(positives)} negatives; normal pretrain={len(normal_indices)}", flush=True)
    results, winner, best_score = [], None, -1.0
    for candidate in cfg["candidates"]:
        set_seed(cfg["seed"])
        model = WorldModel(WorldModelConfig(input_size=len(W.MODEL_COLUMNS), state_size=len(W.STATE_FEATURE_COLUMNS),
                           hidden_size=cfg["hidden_size"], n_stages=N_STAGES)).to(device)
        optimizer = torch.optim.AdamW(model.parameters(), lr=cfg["lr"], weight_decay=1e-4)
        pre = MultiTaskLoss(risk_enabled=False, stage_enabled=False).to(device)
        crit = MultiTaskLoss(LossWeights(state=candidate["state_weight"], risk=2.0, stage=0.25),
                            pos_weight=candidate["pos_weight"]).to(device)
        for ep in range(cfg["pretrain_epochs"]):
            print(f"[{candidate['name']}] pretrain {ep+1}: {epoch(model, normal_loader, pre, optimizer, device)}", flush=True)
        local_best, history, stale = -1.0, [], 0
        for ep in range(cfg["epochs"]):
            start = time.perf_counter()
            losses = epoch(model, train_loader, crit, optimizer, device)
            p, y, _, _ = predict_probs(model, loaders["val"], device)
            ap_scores = [average_precision_score(y[:, i], p[:, i]) for i in range(y.shape[1])]
            score = float(np.mean(ap_scores))
            row = {"epoch": ep+1, "losses": losses, "val_ap": ap_scores, "seconds": time.perf_counter()-start}
            history.append(row)
            print(f"[{candidate['name']}] {row}", flush=True)
            if score > local_best:
                local_best, stale = score, 0
                payload = {"state_dict": {k: v.detach().cpu().clone() for k,v in model.state_dict().items()},
                           "model_config": asdict(model.config), "scaler": scaler,
                           "feature_names": list(W.MODEL_COLUMNS), "horizons": list(W.HORIZONS),
                           "threshold": float(thresholds(y,p)[0]), "thresholds": thresholds(y,p).tolist(),
                           "history_length": W.HISTORY_LENGTH, "sequence_policy": "strict_30s",
                           "candidate": candidate, "epoch": ep+1, "validation_mean_ap": score}
                torch.save(payload, outdir / f"{candidate['name']}.ckpt")
            else:
                stale += 1
            if stale >= cfg["patience"]:
                break
        results.append({"candidate": candidate, "validation_mean_ap": local_best, "history": history})
        if local_best > best_score:
            best_score, winner = local_best, candidate["name"]
        (outdir / "experiments.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    payload = torch.load(outdir / f"{winner}.ckpt", weights_only=False)
    model.load_state_dict(payload["state_dict"])
    torch.save(payload, outdir / "best.ckpt")
    # Test is evaluated only after selecting the candidate and epoch on validation.
    p, y, _, _ = predict_probs(model, loaders["test"], device)
    report = {"winner": winner, "world_model": metrics(y,p,np.array(payload["thresholds"])),
              "dynamics": dynamics(model, loaders["test"], device),
              "persistence": metrics(y,np.zeros_like(p),np.full(y.shape[1],0.5))}
    report["warning_lead_time"] = warning_lead_times(seq["test"].meta,p,np.array(payload["thresholds"]),lookup)
    seq["test"].meta.to_parquet(outdir / "test_meta.parquet",index=False)
    # Same corrected test examples, original trained checkpoint: comparable labels.
    original = torch.load(REPO_ROOT / cfg["baseline_checkpoint"], weights_only=False, map_location="cpu")
    old = WorldModel.from_config(original["model_config"]).to(device)
    old.load_state_dict(original["state_dict"])
    old_loader = to_loader(seq["test"], original["scaler"], cfg["batch_size"], False)
    op, oy, _, _ = predict_probs(old, old_loader, device)
    report["original_corrected_test"] = metrics(oy,op,np.full(y.shape[1],original["threshold"]))
    xp = W.apply_scaler(train.x[selected],scaler).reshape(len(selected),-1)
    xv = W.apply_scaler(seq["val"].x,scaler).reshape(len(seq["val"].x),-1)
    xt = W.apply_scaler(seq["test"].x,scaler).reshape(len(seq["test"].x),-1)
    lp, lv = np.zeros_like(p), np.zeros_like(seq["val"].y_risk)
    for i in range(y.shape[1]):
        lr = LogisticRegression(max_iter=cfg["lr_max_iter"], class_weight="balanced", solver="lbfgs")
        lr.fit(xp,train.y_risk[selected,i])
        lp[:,i], lv[:,i] = lr.predict_proba(xt)[:,1], lr.predict_proba(xv)[:,1]
    report["logistic_regression"] = metrics(y,lp,thresholds(seq["val"].y_risk,lv))
    # Ordered-versus-shuffled ablation preserves every feature value per history.
    shuffled = seq["test"].x.copy()
    for row in shuffled:
        rng.shuffle(row, axis=0)
    ablation = W.SequenceBatch(shuffled,seq["test"].y_state,y,seq["test"].y_stage,seq["test"].meta)
    sp, _, _, _ = predict_probs(model,to_loader(ablation,scaler,cfg["batch_size"],False),device)
    report["shuffled_history"] = metrics(y,sp,np.array(payload["thresholds"]))
    np.savez_compressed(outdir / "test_predictions.npz", truth=y, risk=p, original=op, logistic=lp)
    (outdir / "metrics.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    print(json.dumps(report,indent=2),flush=True)
    print(f"[done] {outdir / 'best.ckpt'}",flush=True)


if __name__ == "__main__":
    main()
