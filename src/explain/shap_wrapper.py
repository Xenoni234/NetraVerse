"""SHAP attributions over the risk head.

Wraps the world model into something SHAP can explain, and reduces the resulting
``(L, F)`` attribution surface into the two views a human actually reads:

* **per-feature** — summed over lags: "which signals drove this?"
* **per-lag** — summed over features: "when did the evidence appear?"

Implementation notes
--------------------
SHAP expects ``f(X) -> scores`` over a 2-D input. Our input is ``(B, L, F)``, so
:func:`make_predict_fn` flattens to ``(B, L*F)`` and reshapes inside — using the
same flattening convention as
:func:`src.models.baseline_lr.flatten_history`, so attributions from the LSTM and
the LR baseline can be compared directly.

Which explainer: ``GradientExplainer`` or ``DeepExplainer`` for the torch model
(fast, gradient-based), ``KernelExplainer`` only as a fallback — kernel SHAP on a
320-dimensional input is far too slow for the demo.

Background set: sample from **benign training windows**, so attributions read as
"relative to normal traffic". Sampling from all windows makes the baseline
partly attack-shaped and quietly shrinks every attribution.

Cost
----
Non-trivial. Precompute explanations for the demo's replay timeline rather than
computing them live on every frame, and cache per ``(entity, window)``.

TODO
----
* [ ] Implement ``RiskExplainer`` around ``shap.GradientExplainer``.
* [ ] Implement ``make_predict_fn`` with the shared flatten convention.
* [ ] Implement ``sample_background`` (benign-only, seeded, size-capped).
* [ ] Implement the per-feature and per-lag reductions.
* [ ] Cache explanations keyed by ``(entity_id, window_start)``.
* [ ] Sanity check: shuffle a high-importance feature and confirm the risk score
      actually moves. If it does not, the attribution is lying.
* [ ] Decide whether to explain risk at a single horizon or all three. Start
      with k=1 (most reliable), and note the choice in the report.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Final, Mapping, Sequence

import numpy as np

if TYPE_CHECKING:
    from torch import nn

#: Background samples drawn for the explainer. Bigger is more faithful, slower.
DEFAULT_BACKGROUND_SIZE: Final[int] = 200

#: Features surfaced in an explanation. More than ~5 stops being an explanation.
DEFAULT_TOP_K: Final[int] = 5


@dataclass(frozen=True)
class RiskAttribution:
    """SHAP attributions for one prediction, in the two useful reductions.

    Attributes:
        values: ``(L, F)`` raw SHAP values over the history window.
        per_feature: ``(F,)`` summed over lags — which signals mattered.
        per_lag: ``(L,)`` summed over features — when the evidence appeared.
        base_value: The explainer's expected output (the "normal traffic" score).
        prediction: The actual risk score being explained.
        feature_names: Names aligned with the feature axis.
        horizon: Which horizon ``k`` this explains.
    """

    values: np.ndarray
    per_feature: np.ndarray
    per_lag: np.ndarray
    base_value: float
    prediction: float
    feature_names: tuple[str, ...]
    horizon: int = 1

    def top_features(self, k: int = DEFAULT_TOP_K) -> list[tuple[str, float]]:
        """The ``k`` largest-magnitude feature attributions, signed.

        Sign matters: a feature can push risk *down*, and saying so is part of
        an honest explanation.
        """
        order = np.argsort(np.abs(self.per_feature))[::-1][:k]
        return [(self.feature_names[i], float(self.per_feature[i])) for i in order]

    def top_lags(self, k: int = 3) -> list[tuple[int, float]]:
        """The ``k`` history lags (0 = oldest window) that mattered most."""
        order = np.argsort(np.abs(self.per_lag))[::-1][:k]
        return [(int(i), float(self.per_lag[i])) for i in order]


def _build_risk_wrapper(model: "nn.Module", horizon_index: int):
    """An nn.Module mapping ``(B, L, F)`` -> risk probability at one horizon ``(B, 1)``.

    SHAP's GradientExplainer needs a tensor->tensor module; the world model
    returns a dict, so we adapt it and select the requested horizon's risk.
    """
    import torch

    class _RiskWrapper(torch.nn.Module):
        def __init__(self, m, hi):
            super().__init__()
            self.m = m
            self.hi = hi

        def forward(self, x):
            out = self.m(x, targets=None, sampling_prob=1.0)  # free-running rollout
            return torch.sigmoid(out["risk_logits"])[:, self.hi : self.hi + 1]

    return _RiskWrapper(model, horizon_index)


class RiskExplainer:
    """SHAP explainer bound to a trained model's risk head.

    Construct once (building the explainer is the expensive part), then call
    :meth:`explain` per sample or :meth:`explain_batch` for the demo timeline.
    """

    def __init__(
        self,
        model: "nn.Module",
        background: np.ndarray,
        *,
        feature_names: Sequence[str],
        horizon: int = 1,
        device: str = "auto",
        explainer_type: str = "gradient",
    ) -> None:
        import shap
        import torch

        from src.models import get_device

        self.device = get_device(device)
        self.horizon = horizon
        self.feature_names = tuple(feature_names)
        self.model = model.to(self.device).eval()
        hs = list(getattr(self.model.config, "horizons", (1, 2, 4)))
        self._hi = hs.index(horizon) if horizon in hs else 0
        self._wrapper = _build_risk_wrapper(self.model, self._hi).to(self.device).eval()
        bg = torch.as_tensor(np.asarray(background, dtype="float32"), device=self.device)
        if explainer_type != "gradient":
            raise ValueError("only 'gradient' (shap.GradientExplainer) is supported here")
        self._explainer = shap.GradientExplainer(self._wrapper, bg)

    def explain(self, x: np.ndarray) -> RiskAttribution:
        """Explain one history window (``(L, F)`` in)."""
        return self.explain_batch(np.asarray(x)[None])[0]

    def explain_batch(self, x: np.ndarray, *, n_samples: int | None = None) -> list[RiskAttribution]:
        """Explain a batch ``(B, L, F)``; used to precompute the demo timeline."""
        import torch

        xt = torch.as_tensor(np.asarray(x, dtype="float32"), device=self.device)
        sv = self._explainer.shap_values(xt)
        if isinstance(sv, list):
            sv = sv[0]
        sv = np.asarray(sv)
        if sv.ndim == 4:                    # (N, L, F, 1) single-output
            sv = sv[..., 0]
        with torch.no_grad():
            preds = self._wrapper(xt).cpu().numpy().reshape(-1)
        out: list[RiskAttribution] = []
        for i in range(sv.shape[0]):
            v = sv[i]                        # (L, F)
            out.append(RiskAttribution(
                values=v, per_feature=v.sum(axis=0), per_lag=v.sum(axis=1),
                base_value=0.0, prediction=float(preds[i]),
                feature_names=self.feature_names, horizon=self.horizon,
            ))
        return out

    def save_cache(self, path: Path) -> Path:
        """Persist precomputed attributions so the demo starts instantly."""
        raise NotImplementedError("Precompute via explain_batch and np.savez in the caller.")


def make_predict_fn(
    model: "nn.Module", *, horizon: int = 1, device: str = "auto"
) -> Callable[[np.ndarray], np.ndarray]:
    """Adapt the world model into the ``f(X_2d) -> risk`` callable SHAP wants.

    Reshapes ``(B, L*F)`` back to ``(B, L, F)`` and returns the risk probability
    at ``horizon`` (used for KernelExplainer-style callers and the LR comparison).
    """
    import torch

    from src.models import get_device

    dev = get_device(device)
    model = model.to(dev).eval()
    hs = list(getattr(model.config, "horizons", (1, 2, 4)))
    hi = hs.index(horizon) if horizon in hs else 0
    fdim = model.config.input_size

    def f(x2d: np.ndarray) -> np.ndarray:
        x = np.asarray(x2d, dtype="float32")
        length = x.shape[1] // fdim
        xt = torch.as_tensor(x.reshape(-1, length, fdim), device=dev)
        with torch.no_grad():
            out = model(xt, targets=None, sampling_prob=1.0)
            return torch.sigmoid(out["risk_logits"]).cpu().numpy()[:, hi]

    return f


def sample_background(
    x: np.ndarray,
    labels: np.ndarray | None = None,
    *,
    size: int = DEFAULT_BACKGROUND_SIZE,
    benign_only: bool = True,
    random_state: int = 1337,
) -> np.ndarray:
    """Sample a background set from TRAIN windows, benign-only by default."""
    x = np.asarray(x, dtype="float32")
    idx = np.arange(len(x))
    if benign_only and labels is not None:
        benign = np.asarray(labels).reshape(-1) < 0.5
        if benign.any():
            idx = idx[benign]
    rng = np.random.default_rng(random_state)
    if len(idx) > size:
        idx = rng.choice(idx, size=size, replace=False)
    return x[idx]


def aggregate_attributions(
    attributions: Sequence[RiskAttribution],
) -> Mapping[str, np.ndarray]:
    """Mean absolute attribution per feature across many samples (global view)."""
    pf = np.stack([a.per_feature for a in attributions])
    return {
        "mean_abs_per_feature": np.abs(pf).mean(axis=0),
        "feature_names": np.array(attributions[0].feature_names),
    }


def perturbation_check(
    model: "nn.Module", x: np.ndarray, feature_index: int, *, n_trials: int = 20
) -> float:
    """Shuffle one feature across the batch and measure the mean risk shift.

    A high-importance feature should move the score; near-zero means the
    attribution is not trustworthy.
    """
    import torch

    from src.models import get_device

    dev = get_device("auto")
    model = model.to(dev).eval()
    xt = torch.as_tensor(np.asarray(x, dtype="float32"), device=dev)
    with torch.no_grad():
        base = torch.sigmoid(model(xt, targets=None, sampling_prob=1.0)["risk_logits"]).cpu().numpy()
    rng = np.random.default_rng(0)
    deltas = []
    for _ in range(n_trials):
        xp = xt.clone()
        perm = rng.permutation(xt.shape[0])
        xp[:, :, feature_index] = xt[torch.as_tensor(perm, device=dev)][:, :, feature_index]
        with torch.no_grad():
            p = torch.sigmoid(model(xp, targets=None, sampling_prob=1.0)["risk_logits"]).cpu().numpy()
        deltas.append(float(np.abs(p - base).mean()))
    return float(np.mean(deltas))


__all__ = [
    "DEFAULT_BACKGROUND_SIZE",
    "DEFAULT_TOP_K",
    "RiskAttribution",
    "RiskExplainer",
    "make_predict_fn",
    "sample_background",
    "aggregate_attributions",
    "perturbation_check",
]
