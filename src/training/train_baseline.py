"""Train/evaluate the logistic-regression and persistence baselines on the world model's splits.

    python -m src.training.train_baseline [--datasets ...] [--tag main]

Persistence = "the attack state now continues for the next 300 s" (uses the true
current label - an oracle-ish reference every forecaster must beat on onsets).
"""
from __future__ import annotations

import argparse
import json
import pickle

import numpy as np

from src.features.schema import WINDOW_S
from src.explainability.shap_explainer import explain_baseline
from src.models.baseline_logreg import LogRegBaseline
from src.training import data as D
from src.training.evaluate import metrics, onset_metrics, pick_threshold_macro
from src.utils.config import MODELS, REPORTS, world_model_config


def _xy(data: D.SeqData, starts: np.ndarray, L: int):
    rows = starts[:, None] + np.arange(data.T)
    r = data.risk[rows]
    x = data.x[rows[:, :L]]
    lead = np.where(r[:, L:].any(1), r[:, L:].argmax(1) + 1, 0)
    return x, r[:, L:].max(1), r[:, L - 1], r[:, :L].max(1), lead


def run(datasets: list[str], tag: str) -> dict:
    cfg = world_model_config()
    L, K = cfg["windowing"]["history"], cfg["windowing"]["horizon"]
    data = D.build(datasets, L, K)
    tr = D.balance_train(data, data.starts["train"], cfg["data"]["idle_keep"], cfg["seed"])
    x_tr, y_tr, *_ = _xy(data, tr, L)
    model = LogRegBaseline(L).fit(x_tr, y_tr)

    x_va, y_va, *_ = _xy(data, data.starts["val"], L)
    thr = pick_threshold_macro(y_va, model.predict_proba(x_va),
                               data.frame["dataset"].to_numpy()[data.starts["val"]])
    x_te, y_te, y_now, hist, lead = _xy(data, data.starts["test"], L)
    s_te = model.predict_proba(x_te)

    ds_te = data.frame["dataset"].to_numpy()[data.starts["test"]]
    per = {str(d): {"logreg": metrics(y_te[ds_te == d], s_te[ds_te == d], thr),
                    "persistence": metrics(y_te[ds_te == d], y_now[ds_te == d], 0.5)}
           for d in np.unique(ds_te)}
    res = {
        "tag": tag, "datasets": datasets, "threshold": thr, "test_per_dataset": per,
        "logreg": {"forecast_300s": metrics(y_te, s_te, thr),
                   "early_warning": onset_metrics(y_te, y_now, hist, s_te, thr, lead, WINDOW_S)},
        "persistence": {"forecast_300s": metrics(y_te, y_now, 0.5),
                        "early_warning": onset_metrics(y_te, y_now, hist, y_now, 0.5, lead, WINDOW_S)},
    }
    rng = np.random.default_rng(0)
    bg = x_tr[rng.choice(len(x_tr), min(500, len(x_tr)), replace=False)]
    sm = x_te[rng.choice(len(x_te), min(2000, len(x_te)), replace=False)]
    res["logreg"]["shap_top_features"] = explain_baseline(model, bg, sm)
    suffix = "" if tag == "main" else f"_{tag}"
    with open(MODELS / f"baseline_logreg{suffix}.pkl", "wb") as fh:
        pickle.dump({"model": model, "scaler": data.scaler.to_dict(), "threshold": thr}, fh)
    (REPORTS / f"baseline_{tag}.json").write_text(json.dumps(res, indent=2, default=float))
    print(json.dumps(res, indent=2, default=float))
    return res


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--datasets", nargs="+", default=world_model_config()["data"]["train_datasets"])
    ap.add_argument("--tag", default="main")
    a = ap.parse_args()
    run(a.datasets, a.tag)


if __name__ == "__main__":
    main()
