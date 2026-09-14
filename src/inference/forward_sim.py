"""K-step forward simulation — rolling the world model into the future.

Given ``L=10`` windows of history, unroll the decoder free-running for ``n_steps``,
feeding each predicted state back in as the next input. Out comes a simulated
trajectory: a predicted feature vector, risk probability and ATT&CK stage for
every step ahead.

::

    history (L, F) -> encoder -> h
    for k in 1..n_steps:
        h, out   = decoder(x_prev, h)
        x_hat_k  = state_head(out, x_prev)
        r_hat_k  = sigmoid(risk_head(out))
        s_hat_k  = softmax(stage_head(out))
        x_prev   = x_hat_k          # <- free running, no ground truth

Error compounds with depth — that is inherent, and it is exactly why training
uses scheduled sampling. Two practical consequences:

1. Do not simulate far past the horizons the model was trained on. ``K`` tops
   out at 4; simulating 20 steps produces a confident-looking fantasy. Guard it
   with ``MAX_SIMULATION_STEPS`` and warn past ``max(K)``.
2. Always show the uncertainty band from :mod:`src.inference.uncertainty`
   alongside the point forecast. A widening band is the honest signal that the
   simulation is losing touch.

TODO
----
* [ ] Implement ``simulate`` (batched, ``no_grad``, device-agnostic).
* [ ] Implement ``simulate_single`` for the demo's per-host inspection view.
* [ ] Implement ``SimulationResult.to_frame`` for plotting and for the dashboard.
* [ ] Clamp simulated states to physically sensible ranges — fractions in [0,1],
      counts non-negative — otherwise the rollout can drift somewhere impossible
      and the recursion amplifies it.
* [ ] Inverse-transform the scaler so the demo can show real units (bytes/s,
      distinct ports) rather than z-scores.
* [ ] Implement ``first_crossing`` (first step where risk exceeds a threshold,
      sustained), which is the quantity lead time is computed from.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, Mapping, Sequence

import numpy as np

if TYPE_CHECKING:
    import pandas as pd
    import torch
    from torch import nn

#: Hard cap on simulation depth. Beyond max(K) the model is extrapolating past
#: anything it was trained on; beyond this it is making things up.
MAX_SIMULATION_STEPS: Final[int] = 12


@dataclass(frozen=True)
class SimulationResult:
    """A simulated future for a batch of entities.

    Attributes:
        states: ``(B, n_steps, F)`` predicted feature vectors.
        risk: ``(B, n_steps)`` predicted attack probability in ``[0, 1]``.
        stage_probs: ``(B, n_steps, n_stages)`` stage distribution.
        stage: ``(B, n_steps)`` argmax stage id.
        steps: Step indices ``1..n_steps``.
        seconds_ahead: ``steps * stride_seconds`` — what the demo actually shows.
        meta: Optional per-row entity / campaign / window_start identifiers.
    """

    states: np.ndarray
    risk: np.ndarray
    stage_probs: np.ndarray
    stage: np.ndarray
    steps: np.ndarray
    seconds_ahead: np.ndarray
    meta: "pd.DataFrame | None" = None

    def to_frame(self) -> "pd.DataFrame":
        """Long-format frame (one row per entity-step) for plotting and export."""
        raise NotImplementedError("TODO: melt arrays into a tidy frame with meta joined")

    def at_horizon(self, k: int) -> Mapping[str, np.ndarray]:
        """Slice the result at a single horizon ``k``."""
        raise NotImplementedError("TODO: index step k-1 across every array")


def simulate(
    model: "nn.Module",
    history: np.ndarray,
    *,
    n_steps: int = 4,
    stride_seconds: int = 10,
    device: str = "auto",
    scaler_state: Mapping[str, Any] | None = None,
    clamp: bool = True,
    meta: "pd.DataFrame | None" = None,
) -> SimulationResult:
    """Roll the world model forward for a batch of histories.

    Args:
        model: Trained :class:`~src.models.lstm_encoder_decoder.WorldModel`.
        history: ``(B, L, F)`` scaled history.
        n_steps: Steps to simulate; warns above ``max(K)``, refuses above
            :data:`MAX_SIMULATION_STEPS`.
        stride_seconds: Used to convert steps into seconds-ahead.
        device: ``auto`` / ``cpu`` / ``cuda``.
        scaler_state: When given, states are inverse-transformed into real units.
        clamp: Apply :func:`clamp_state` at each step.
        meta: Optional identifiers carried through to the result.

    Returns:
        A :class:`SimulationResult`.
    """
    raise NotImplementedError("TODO: eval + no_grad rollout, clamp per step, assemble result")


def simulate_single(
    model: "nn.Module", history: np.ndarray, **kwargs: Any
) -> SimulationResult:
    """Convenience wrapper for one entity (``(L, F)`` in, batch of 1 out)."""
    raise NotImplementedError("TODO: add batch dim, delegate to simulate, squeeze")


def clamp_state(state: np.ndarray) -> np.ndarray:
    """Project a simulated state back into physically possible ranges.

    Counts non-negative; fraction features into ``[0, 1]``; entropies into
    ``[0, 1]``. Without this, a small overshoot early in the rollout feeds back
    and compounds into nonsense.
    """
    raise NotImplementedError("TODO: per-feature-group clipping via FEATURE_COLUMNS names")


def first_crossing(
    risk: np.ndarray, threshold: float = 0.5, *, sustain: int = 2
) -> np.ndarray:
    """First step at which risk crosses ``threshold`` for ``sustain`` steps.

    Args:
        risk: ``(B, n_steps)`` predicted probabilities.
        threshold: Decision threshold (from the checkpoint, not hard-coded).
        sustain: Consecutive steps required, to suppress single-window flicker.

    Returns:
        ``(B,)`` int array of step indices, ``-1`` where no crossing occurs.
        This is the raw quantity that :mod:`src.eval.metrics` turns into lead time.
    """
    raise NotImplementedError("TODO: rolling AND over the threshold mask, argmax first True")


def inverse_transform_states(
    states: np.ndarray, scaler_state: Mapping[str, Any]
) -> np.ndarray:
    """Undo the feature scaler so the demo can plot real units."""
    raise NotImplementedError("TODO: states * scale + center, matching windowing.apply_scaler")


__all__ = [
    "MAX_SIMULATION_STEPS",
    "SimulationResult",
    "simulate",
    "simulate_single",
    "clamp_state",
    "first_crossing",
    "inverse_transform_states",
]
