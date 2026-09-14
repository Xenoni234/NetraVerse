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
        raise NotImplementedError("TODO: argsort |per_feature|, return signed name/value pairs")


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
        horizon: int = 1,
        device: str = "auto",
        explainer_type: str = "gradient",
    ) -> None:
        raise NotImplementedError("TODO: wrap model, build shap.GradientExplainer")

    def explain(self, x: np.ndarray) -> RiskAttribution:
        """Explain one history window (``(L, F)`` in)."""
        raise NotImplementedError("TODO: shap_values -> reshape (L, F) -> reductions")

    def explain_batch(self, x: np.ndarray, *, n_samples: int | None = None) -> list[RiskAttribution]:
        """Explain a batch ``(B, L, F)``; used to precompute the demo timeline."""
        raise NotImplementedError("TODO: batched shap_values, then per-row reduction")

    def save_cache(self, path: Path) -> Path:
        """Persist precomputed attributions so the demo starts instantly."""
        raise NotImplementedError("TODO: npz keyed by (entity_id, window_start)")


def make_predict_fn(
    model: "nn.Module", *, horizon: int = 1, device: str = "auto"
) -> Callable[[np.ndarray], np.ndarray]:
    """Adapt the world model into the ``f(X_2d) -> risk`` callable SHAP wants.

    Reshapes ``(B, L*F)`` back to ``(B, L, F)`` using the same convention as
    :func:`src.models.baseline_lr.flatten_history`, runs the model, and returns
    the risk probability at ``horizon``.
    """
    raise NotImplementedError("TODO: closure that reshapes, runs no_grad forward, returns risk")


def sample_background(
    x: np.ndarray,
    labels: np.ndarray | None = None,
    *,
    size: int = DEFAULT_BACKGROUND_SIZE,
    benign_only: bool = True,
    random_state: int = 1337,
) -> np.ndarray:
    """Sample a background set from TRAIN windows, benign-only by default.

    Args:
        x: ``(N, L, F)`` training histories.
        labels: ``(N,)`` binary attack labels, required when ``benign_only``.
        size: Background size.
        benign_only: Restrict to benign windows so attributions read as
            deviation from normal.
        random_state: Seed, so explanations are reproducible.
    """
    raise NotImplementedError("TODO: filter benign, seeded subsample without replacement")


def aggregate_attributions(
    attributions: Sequence[RiskAttribution],
) -> Mapping[str, np.ndarray]:
    """Mean absolute attribution per feature across many samples.

    The global "which features does this model rely on?" view for the report,
    as opposed to the per-alert local explanation.
    """
    raise NotImplementedError("TODO: stack per_feature, mean of absolute values")


def perturbation_check(
    model: "nn.Module", x: np.ndarray, feature_index: int, *, n_trials: int = 20
) -> float:
    """Verify an attribution by shuffling one feature and measuring the effect.

    If shuffling a supposedly high-importance feature does not move the risk
    score, the attribution is not trustworthy. Cheap insurance against shipping
    a confident, wrong explanation.
    """
    raise NotImplementedError("TODO: permute the feature across the batch, measure risk delta")


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
