"""Metrics: precision, recall, F1, FPR, PR-AUC, threshold selection, early-warning lead time."""
from __future__ import annotations

import numpy as np
from sklearn.metrics import average_precision_score, precision_recall_curve


def pick_threshold(y: np.ndarray, score: np.ndarray) -> float:
    """Threshold maximising F1 - chosen on the VALIDATION split only."""
    if y.sum() == 0:
        return 0.5
    p, r, t = precision_recall_curve(y, score)
    f1 = 2 * p * r / np.maximum(p + r, 1e-12)
    i = int(np.nanargmax(f1[:-1])) if len(t) else 0
    return float(t[i]) if len(t) else 0.5


def pick_threshold_macro(y: np.ndarray, score: np.ndarray, groups: np.ndarray) -> float:
    """Threshold maximising the MEAN F1 over source datasets (validation split only).

    A pooled F1 lets the largest/easiest dataset set the operating point; the
    macro criterion gives every dataset an equal say (documented decision, R20).
    """
    cands = np.unique(np.quantile(score[y > 0], np.linspace(0, 1, 101))) if (y > 0).any() else [0.5]
    best, best_t = -1.0, 0.5
    gs = [g for g in np.unique(groups) if (y[groups == g] > 0).any()]
    for t in cands:
        f = []
        for g in gs:
            m = groups == g
            pred = score[m] >= t
            tp = (pred & (y[m] > 0)).sum(); fp = (pred & (y[m] == 0)).sum(); fn = (~pred & (y[m] > 0)).sum()
            f.append(2 * tp / max(2 * tp + fp + fn, 1))
        if np.mean(f) > best:
            best, best_t = float(np.mean(f)), float(t)
    return best_t


def metrics(y: np.ndarray, score: np.ndarray, thr: float) -> dict:
    y = y.astype(bool)
    pred = score >= thr
    tp = int((pred & y).sum()); fp = int((pred & ~y).sum())
    fn = int((~pred & y).sum()); tn = int((~pred & ~y).sum())
    prec = tp / max(tp + fp, 1); rec = tp / max(tp + fn, 1)
    return {
        "precision": round(prec, 4), "recall": round(rec, 4),
        "f1": round(2 * prec * rec / max(prec + rec, 1e-12), 4),
        "fpr": round(fp / max(fp + tn, 1), 5),
        "pr_auc": round(float(average_precision_score(y, score)), 4) if y.any() else None,
        "threshold": round(float(thr), 5), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "positives": int(y.sum()), "n": int(len(y)),
    }


def onset_metrics(y_future: np.ndarray, y_now: np.ndarray, hist_attack: np.ndarray,
                  score: np.ndarray, thr: float, lead_steps: np.ndarray, window_s: int) -> dict:
    """Early warning: sequences whose whole history is benign but an attack starts in the horizon.

    ``lead_steps`` = steps from the current window to the first attack window.
    Recall here is the share of attack onsets flagged *before* the first attack window.
    """
    onset = (y_future > 0) & (hist_attack == 0)
    quiet = (y_future == 0) & (hist_attack == 0)
    if onset.sum() == 0:
        return {"onsets": 0}
    hit = score[onset] >= thr
    leads = lead_steps[onset][hit] * window_s
    return {
        "onsets": int(onset.sum()),
        "early_warning_recall": round(float(hit.mean()), 4),
        "quiet_false_alarm_rate": round(float((score[quiet] >= thr).mean()), 5) if quiet.any() else None,
        "median_lead_s": float(np.median(leads)) if len(leads) else None,
        "mean_lead_s": round(float(np.mean(leads)), 1) if len(leads) else None,
    }
