"""Integrated-gradients attribution for the world model's forecast (FR12, R5).

Attributes the *forecast* (peak imagined risk over the 300 s horizon) to the
input features of the observed history windows, then sums over time so every
unified feature gets one signed score. The reference input is the all-zero
scaled vector = the training-set average window.
"""
from __future__ import annotations

import numpy as np
import torch
from captum.attr import IntegratedGradients

from src.features.schema import FEATURE_COLUMNS, FEATURE_LABELS
from src.models.world_model import WorldModel

_SKIP = {c for c in FEATURE_COLUMNS if c.endswith("_mask")}


def _forecast_fn(model: WorldModel, horizon: int):
    def f(x: torch.Tensor, nb: torch.Tensor) -> torch.Tensor:
        states, _, _ = model.filter(x, nb, sample=False)
        imag = model.imagine(states[-1], horizon, sample=False)
        return torch.sigmoid(model.decode(imag)["risk_logit"]).max(dim=1).values
    return f


def _fmt(v: float) -> str:
    return f"{v:,.0f}" if abs(v) >= 100 else f"{v:,.2f}"


def explain(model: WorldModel, x_hist: np.ndarray, nb_hist: np.ndarray, raw_last: np.ndarray,
            typical: np.ndarray, horizon: int, top_k: int = 5, n_steps: int = 24) -> list[dict]:
    """x_hist/nb_hist: [N, L, *] scaled inputs. raw_last: [N, F] unscaled last window.
    typical: [F] unscaled training average. Returns top_k drivers per sample."""
    model.eval()
    dev = next(model.parameters()).device
    x = torch.as_tensor(x_hist, dtype=torch.float32, device=dev)
    nb = torch.as_tensor(nb_hist, dtype=torch.float32, device=dev)
    with torch.backends.cudnn.flags(enabled=False):
        ig = IntegratedGradients(_forecast_fn(model, horizon))
        attr = ig.attribute(x, baselines=torch.zeros_like(x), additional_forward_args=(nb,),
                            n_steps=n_steps, internal_batch_size=max(1, 256 // max(1, len(x))) * len(x))
    per = attr.sum(dim=1).detach().cpu().numpy()                    # [N, F]
    out = []
    for i in range(len(per)):
        order = [j for j in np.argsort(-np.abs(per[i])) if FEATURE_COLUMNS[j] not in _SKIP][:top_k]
        items = []
        for j in order:
            name = FEATURE_COLUMNS[j]
            val, base = float(raw_last[i, j]), float(typical[j])
            direction = "raises" if per[i, j] > 0 else "lowers"
            rel = "above" if val > base else "below"
            items.append({
                "feature": name, "label": FEATURE_LABELS[name],
                "attribution": round(float(per[i, j]), 4), "value": round(val, 4),
                "typical": round(base, 4),
                "sentence": f"{FEATURE_LABELS[name].capitalize()} is {_fmt(val)} "
                            f"({rel} the typical {_fmt(base)}), which {direction} the forecast risk.",
            })
        out.append(items)
    return out
