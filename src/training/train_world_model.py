"""Train the RSSM-lite (+GraphSAGE) world model.

    python -m src.training.train_world_model                    # full model
    python -m src.training.train_world_model --no-gnn --tag nognn   # Phase 5 ablation
    python -m src.training.train_world_model --datasets cic2017 cic2018 --tag cic   # Phase 6 source

Writes models/world_model{_tag}.pt (+ training_config.yaml) and reports/wm_{tag}.json.
"""
from __future__ import annotations

import argparse
import copy
import json
import time

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import average_precision_score
import yaml

from src.features.schema import WINDOW_S
from src.models.rollout import batch_forecast
from src.models.world_model import WorldModel, load_checkpoint, save_checkpoint
from src.training import data as D
from src.training.evaluate import metrics, onset_metrics, pick_threshold, pick_threshold_macro
from src.utils.config import MODELS, REPORTS, world_model_config


def device() -> torch.device:
    return torch.device("cuda" if torch.cuda.is_available() else "cpu")


@torch.no_grad()
def score(model: WorldModel, data: D.SeqData, starts: np.ndarray, history: int, horizon: int,
          batch: int = 8192) -> dict[str, np.ndarray]:
    model.eval()
    dev = next(model.parameters()).device
    fut, now, stf = [], [], []
    for i in range(0, len(starts), batch):
        s = starts[i:i + batch]
        x, nb, _, _ = D.gather(data, s)
        out = batch_forecast(model, torch.as_tensor(x, device=dev), torch.as_tensor(nb, device=dev),
                             history, horizon)
        fut.append(out["future"]); now.append(out["now"]); stf.append(out["stage_future"])
    return {"future": np.concatenate(fut), "now": np.concatenate(now), "stage_future": np.concatenate(stf)}


def evaluate_split(model, data, starts, history, horizon, thr=None, macro: bool = False) -> dict:
    sc = score(model, data, starts, history, horizon)
    rows = starts[:, None] + np.arange(data.T)
    r = data.risk[rows]
    y_future = r[:, history:].max(1)
    y_now = r[:, history - 1]
    hist_attack = r[:, :history].max(1)
    lead = np.where(r[:, history:].any(1), r[:, history:].argmax(1) + 1, 0)
    s_future = sc["future"].max(1)
    if thr is None:
        groups = data.frame["dataset"].to_numpy()[starts]
        thr = pick_threshold_macro(y_future, s_future, groups) if macro else pick_threshold(y_future, s_future)
    return {
        "threshold": thr,
        "forecast_300s": metrics(y_future, s_future, thr),
        "detection_now": metrics(y_now, sc["now"], pick_threshold(y_now, sc["now"])),
        "early_warning": onset_metrics(y_future, y_now, hist_attack, s_future, thr, lead, WINDOW_S),
        "_scores": sc, "_y_future": y_future,
    }


def per_dataset(data, starts, ev, thr, L) -> dict:
    """Forecast + early-warning metrics per source dataset (pooled numbers hide easy datasets)."""
    rows = starts[:, None] + np.arange(data.T)
    r = data.risk[rows]
    ds = data.frame["dataset"].to_numpy()[starts]
    lead = np.where(r[:, L:].any(1), r[:, L:].argmax(1) + 1, 0)
    s = ev["_scores"]["future"].max(1)
    out = {}
    for d in np.unique(ds):
        m = ds == d
        out[str(d)] = {"forecast_300s": metrics(r[m, L:].max(1), s[m], thr),
                       "early_warning": onset_metrics(r[m, L:].max(1), r[m, L - 1], r[m, :L].max(1),
                                                      s[m], thr, lead[m], WINDOW_S)}
    return out


def train(cfg: dict, datasets: list[str], use_gnn: bool, tag: str, epochs: int | None = None) -> dict:
    torch.manual_seed(cfg["seed"]); np.random.seed(cfg["seed"])
    cfg = copy.deepcopy(cfg)
    cfg["model"]["gnn"] = use_gnn
    cfg["data"]["train_datasets"] = datasets
    L, K = cfg["windowing"]["history"], cfg["windowing"]["horizon"]
    tr = cfg["train"]
    t0 = time.time()
    data = D.build(datasets, L, K, capture_norm=cfg["data"].get("capture_norm", False))
    train_starts = D.balance_train(data, data.starts["train"], cfg["data"]["idle_keep"], cfg["seed"])
    rows = train_starts[:, None] + np.arange(data.T)
    pos = data.risk[rows].mean()
    pos_weight = float(min(tr["risk_pos_weight_cap"], (1 - pos) / max(pos, 1e-6)))
    print(f"[data] rows={len(data.x):,} train_seq={len(train_starts):,} (of {len(data.starts['train']):,}) "
          f"val={len(data.starts['val']):,} test={len(data.starts['test']):,} pos_frac={pos:.4f} "
          f"pos_weight={pos_weight:.1f} build={time.time() - t0:.0f}s", flush=True)

    dev = device()
    model = WorldModel(cfg).to(dev)
    opt = torch.optim.AdamW(model.parameters(), lr=tr["lr"], weight_decay=tr["weight_decay"])
    rng = np.random.default_rng(cfg["seed"])
    val_starts = data.starts["val"]
    best, best_state, bad = -1.0, None, 0
    n_ep = epochs or tr["epochs"]
    sched = torch.optim.lr_scheduler.OneCycleLR(opt, max_lr=tr["lr"], total_steps=n_ep * (
        (len(train_starts) + tr["batch"] - 1) // tr["batch"]))
    history = []
    # dataset x (attack / benign) balanced sampling: every group gets equal expected mass
    tr_rows = train_starts[:, None] + np.arange(data.T)
    # group = (dataset, attack-or-benign): every dataset gets equal expected mass per class.
    # (A (dataset, dominant stage) grouping was tried and rejected: lower val macro PR-AUC,
    #  see reports/wm_stagebalanced_rejected.json.)
    tr_attack = data.risk[tr_rows].max(1) > 0
    tr_ds = data.frame["dataset"].to_numpy()[train_starts]
    grp = pd.Series(list(zip(tr_ds, tr_attack)))
    w = 1.0 / grp.map(grp.value_counts()).to_numpy()
    w = w / w.sum()
    pos = float((data.risk[tr_rows].mean(1) * w).sum())       # positive rate under the sampler
    pos_weight = float(min(tr["risk_pos_weight_cap"], (1 - pos) / max(pos, 1e-6)))
    print(f"[sampler] groups={grp.value_counts().to_dict()} pos_frac={pos:.3f} pos_weight={pos_weight:.2f}",
          flush=True)
    onset_boost = tr["onset_boost"]
    val_ds = data.frame["dataset"].to_numpy()[val_starts]
    for ep in range(n_ep):
        model.train()
        perm = rng.choice(train_starts, size=len(train_starts), replace=True, p=w)
        agg, nsteps, te = {}, 0, time.time()
        for i in range(0, len(perm), tr["batch"]):
            x, nb, ry, sy = D.gather(data, perm[i:i + tr["batch"]], cfg["data"]["packet_mask_dropout"], rng)
            onset = (ry[:, :L].max(1) == 0) & (ry[:, L:].max(1) > 0)
            sw = torch.as_tensor(1.0 + onset_boost * onset, dtype=torch.float32, device=dev)
            out = model.loss(torch.as_tensor(x, device=dev), torch.as_tensor(nb, device=dev),
                             torch.as_tensor(ry, device=dev), torch.as_tensor(sy, device=dev),
                             L, K, pos_weight, sw)
            opt.zero_grad(set_to_none=True)
            out["total"].backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), tr["grad_clip"])
            opt.step(); sched.step()
            for k, v in out.items():
                agg[k] = agg.get(k, 0.0) + float(v)
            nsteps += 1
        ev = evaluate_split(model, data, val_starts, L, K)
        f = ev["forecast_300s"]
        s_val = ev["_scores"]["future"].max(1)
        per = [average_precision_score(ev["_y_future"][val_ds == d], s_val[val_ds == d])
               for d in datasets if ev["_y_future"][val_ds == d].sum() > 0]
        macro = float(np.mean(per)) if per else 0.0
        rec = {"epoch": ep + 1, **{k: round(v / nsteps, 4) for k, v in agg.items()},
               "val_pr_auc": f["pr_auc"], "val_macro_pr_auc": round(macro, 4), "val_f1": f["f1"],
               "val_onset_recall": ev["early_warning"].get("early_warning_recall"),
               "sec": round(time.time() - te)}
        history.append(rec)
        print(json.dumps(rec), flush=True)
        if macro > best:
            best, best_state, bad = macro, copy.deepcopy(model.state_dict()), 0
        else:
            bad += 1
            if bad >= tr["patience"]:
                break
    model.load_state_dict(best_state)
    return finalize(model, data, cfg, datasets, use_gnn, tag, pos_weight, history)


def _logit(p):
    p = np.clip(np.asarray(p, dtype=np.float64), 1e-6, 1 - 1e-6)
    return np.log(p / (1 - p))


def fit_calibration(score: np.ndarray, y: np.ndarray) -> dict:
    """Platt scaling on the validation split: p' = sigmoid(a * logit(p) + b).
    Monotone, so ranking metrics and the operating point are unchanged; it only makes the
    displayed probabilities interpretable (the raw risk head is over-confident)."""
    from sklearn.linear_model import LogisticRegression
    lr = LogisticRegression(C=1e3, max_iter=1000).fit(_logit(score)[:, None], y)
    return {"a": float(lr.coef_[0, 0]), "b": float(lr.intercept_[0])}


def apply_calibration(p, calib: dict | None):
    if not calib:
        return p
    return 1 / (1 + np.exp(-(calib["a"] * _logit(p) + calib["b"])))


def finalize(model, data, cfg, datasets, use_gnn, tag, pos_weight, history) -> dict:
    L, K = cfg["windowing"]["history"], cfg["windowing"]["horizon"]
    model = model.to(device())
    val = evaluate_split(model, data, data.starts["val"], L, K, macro=True)
    thr = val["threshold"]
    calib = fit_calibration(val["_scores"]["future"].max(1), val["_y_future"])
    test = evaluate_split(model, data, data.starts["test"], L, K, thr=thr)
    per_ds = per_dataset(data, data.starts["test"], test, thr, L)
    result = {
        "tag": tag, "datasets": datasets, "gnn": use_gnn, "pos_weight": pos_weight,
        "threshold": thr, "threshold_rule": "max mean-F1 over datasets on validation",
        "calibration": calib, "threshold_calibrated": apply_calibration(thr, calib),
        "val": {k: v for k, v in val.items() if not k.startswith("_")},
        "test": {k: v for k, v in test.items() if not k.startswith("_")},
        "test_per_dataset": per_ds, "history": history,
    }
    suffix = "" if tag == "main" else f"_{tag}"
    MODELS.mkdir(exist_ok=True); REPORTS.mkdir(exist_ok=True)
    save_checkpoint(MODELS / f"world_model{suffix}.pt", model.cpu(), data.scaler,
                    {"threshold": thr, "calibration": calib, "metrics": result["test"],
                     "trained_on": datasets})
    with open(MODELS / f"training_config{suffix}.yaml", "w") as fh:
        yaml.safe_dump(cfg, fh, sort_keys=False)
    (REPORTS / f"wm_{tag}.json").write_text(json.dumps(result, indent=2, default=float))
    print(json.dumps({k: result["test"][k] for k in ("forecast_300s", "early_warning")}, default=float))
    for d, m in per_ds.items():
        print(d, json.dumps(m, default=float))
    return result


def eval_only(tag: str) -> dict:
    suffix = "" if tag == "main" else f"_{tag}"
    model, scaler, ck = load_checkpoint(MODELS / f"world_model{suffix}.pt", device())
    cfg = ck["config"]
    L, K = cfg["windowing"]["history"], cfg["windowing"]["horizon"]
    data = D.build(ck["trained_on"], L, K, scaler=scaler)
    prev = json.loads((REPORTS / f"wm_{tag}.json").read_text()) if (REPORTS / f"wm_{tag}.json").exists() else {}
    return finalize(model, data, cfg, ck["trained_on"], cfg["model"]["gnn"], tag,
                    prev.get("pos_weight"), prev.get("history", []))


def main() -> None:
    ap = argparse.ArgumentParser()
    cfg = world_model_config()
    ap.add_argument("--datasets", nargs="+", default=cfg["data"]["train_datasets"])
    ap.add_argument("--no-gnn", action="store_true")
    ap.add_argument("--tag", default="main")
    ap.add_argument("--epochs", type=int, default=None)
    ap.add_argument("--eval-only", action="store_true")
    ap.add_argument("--capture-norm", action="store_true", help="per-capture robust normalisation (R4)")
    a = ap.parse_args()
    if a.capture_norm:
        cfg = copy.deepcopy(cfg)
        cfg["data"]["capture_norm"] = True
    if a.eval_only:
        eval_only(a.tag)
        return
    train(cfg, a.datasets, not a.no_gnn and cfg["model"]["gnn"], a.tag, a.epochs)


if __name__ == "__main__":
    main()
