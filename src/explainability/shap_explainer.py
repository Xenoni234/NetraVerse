"""SHAP attribution for the logistic-regression baseline (FR13). Offline only."""
from __future__ import annotations

import numpy as np
import shap

from src.features.schema import FEATURE_COLUMNS, FEATURE_LABELS


def explain_baseline(model, background: np.ndarray, samples: np.ndarray, top_k: int = 10) -> list[dict]:
    """Global mean |SHAP| per unified feature (summed over the history steps)."""
    flat_bg = model.flatten(background)
    flat_x = model.flatten(samples)
    expl = shap.LinearExplainer(model.clf, flat_bg)
    sv = np.asarray(expl.shap_values(flat_x))                     # [N, L*F]
    per = np.abs(sv).reshape(len(flat_x), model.history, len(FEATURE_COLUMNS)).sum(1).mean(0)
    order = np.argsort(per)[::-1][:top_k]
    return [{"feature": FEATURE_COLUMNS[i], "label": FEATURE_LABELS[FEATURE_COLUMNS[i]],
             "mean_abs_shap": round(float(per[i]), 4)} for i in order]
