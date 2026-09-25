"""Phase 6 / R4: real zero-shot cross-dataset test.

Train on dataset A (CIC-IDS2017 + CIC-IDS2018 IP day), then evaluate - with no
fine-tuning, the SOURCE scaler and the SOURCE validation threshold - on every
valid sequence of dataset B (CTU-13, UNSW-NB15). Both the world model and the
logistic-regression baseline are tested the same way.

    python -m src.training.cross_dataset_eval
"""
from __future__ import annotations

import json

import numpy as np

from src.models.baseline_logreg import LogRegBaseline
from src.models.world_model import load_checkpoint
from src.training import data as D
from src.training.evaluate import metrics, onset_metrics, pick_threshold_macro
from src.training.train_world_model import device, evaluate_split, train
from src.utils.config import MODELS, REPORTS, world_model_config
from src.features.schema import WINDOW_S

SOURCE = ["cic2017", "cic2018"]
TARGETS = ["ctu13", "unsw"]


def main() -> None:
    import argparse
    import copy
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture-norm", action="store_true")
    ap.add_argument("--retrain", action="store_true")
    a = ap.parse_args()
    cfg = copy.deepcopy(world_model_config())
    if a.capture_norm:
        cfg["data"]["capture_norm"] = True
    tag = "xsrc_cn" if a.capture_norm else "xsrc"
    L, K = cfg["windowing"]["history"], cfg["windowing"]["horizon"]
    ck_path = MODELS / f"world_model_{tag}.pt"
    if a.retrain or not ck_path.exists():
        train(cfg, SOURCE, cfg["model"]["gnn"], tag)
    model, scaler, ck = load_checkpoint(ck_path, device())
    thr = float(ck["threshold"])

    # baseline on the same source data
    src = D.build(SOURCE, L, K, scaler=scaler)
    tr = D.balance_train(src, src.starts["train"], cfg["data"]["idle_keep"], cfg["seed"])
    rows = tr[:, None] + np.arange(src.T)
    lr = LogRegBaseline(L).fit(src.x[rows[:, :L]], src.risk[rows][:, L:].max(1))
    vr = src.starts["val"][:, None] + np.arange(src.T)
    lr_thr = pick_threshold_macro(src.risk[vr][:, L:].max(1), lr.predict_proba(src.x[vr[:, :L]]),
                                  src.frame["dataset"].to_numpy()[src.starts["val"]])

    out = {"source": SOURCE, "capture_norm": a.capture_norm, "wm_threshold": thr, "lr_threshold": lr_thr, "targets": {}}
    for tgt in TARGETS:
        d = D.build([tgt], L, K, scaler=scaler, all_as="test")
        st = d.starts["test"]
        ev = evaluate_split(model, d, st, L, K, thr=thr)
        r = d.risk[st[:, None] + np.arange(d.T)]
        yf, yn, hist = r[:, L:].max(1), r[:, L - 1], r[:, :L].max(1)
        lead = np.where(r[:, L:].any(1), r[:, L:].argmax(1) + 1, 0)
        s_lr = lr.predict_proba(d.x[(st[:, None] + np.arange(L))])
        out["targets"][tgt] = {
            "world_model": {"forecast_300s": ev["forecast_300s"], "early_warning": ev["early_warning"]},
            "logreg": {"forecast_300s": metrics(yf, s_lr, lr_thr),
                       "early_warning": onset_metrics(yf, yn, hist, s_lr, lr_thr, lead, WINDOW_S)},
            "persistence": {"forecast_300s": metrics(yf, yn, 0.5)},
        }
        print(tgt, json.dumps({k: v["forecast_300s"] for k, v in out["targets"][tgt].items()}, default=float))
    (REPORTS / f"cross_dataset{'_cn' if a.capture_norm else ''}.json").write_text(json.dumps(out, indent=2, default=float))


if __name__ == "__main__":
    main()
