"""The persistence baseline: "the next window looks exactly like this one".

The null model, and a surprisingly strong one. Network traffic is highly
autocorrelated at a 10 s stride, so predicting ``x_hat_{t+k} = x_t`` gets a good
state-MSE and predicting ``r_hat_{t+k} = is_attack(t)`` gets a good F1 on long
attacks. If the world model cannot beat this, it has learned nothing about
*dynamics* — it has learned to copy.

Required by DESIGN.md section 6.5. Report it in every results table.

Has no parameters and needs no training. It is written against the same
interface as the real model so the eval harness can treat them interchangeably.

TODO
----
* [ ] Implement ``predict`` returning the same triple as the world model.
* [ ] Implement ``predict_risk`` with the "carry the current label forward"
      rule, and a variant that carries the current *predicted* risk from an
      upstream detector instead, for a fairer comparison.
* [ ] Implement ``drift_persistence`` (linear extrapolation of the last
      difference) as a slightly stronger second null model.
* [ ] Confirm it satisfies the ``Forecaster`` protocol the harness expects.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import numpy as np


@dataclass(frozen=True)
class PersistenceBaseline:
    """Parameter-free forecaster that repeats the most recent observation.

    Attributes:
        horizons: Horizons to emit, matching the LOCKED ``K = (1, 2, 4)``.
        drift: If True, extrapolate the last first-difference instead of
            holding the last value flat.
    """

    horizons: tuple[int, ...] = (1, 2, 4)
    drift: bool = False

    def fit(self, x: np.ndarray, y_risk: np.ndarray | None = None) -> "PersistenceBaseline":
        """No-op. Present so the harness can call ``fit`` uniformly."""
        raise NotImplementedError("TODO: return self; nothing to fit")

    def predict(
        self, x: np.ndarray
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Forecast state, risk and stage from a history batch.

        Args:
            x: ``(N, L, F)`` float32 history.

        Returns:
            ``(y_state, y_risk, y_stage)`` with shapes ``(N, |K|, F)``,
            ``(N, |K|)`` and ``(N, |K|)``.
        """
        raise NotImplementedError("TODO: tile x[:, -1] across horizons (or add drift)")

    def predict_state(self, x: np.ndarray) -> np.ndarray:
        """``(N, |K|, F)`` — the last observed feature vector, repeated."""
        raise NotImplementedError("TODO: broadcast x[:, -1, :] over len(horizons)")

    def predict_risk(
        self, x: np.ndarray, current_risk: np.ndarray | None = None
    ) -> np.ndarray:
        """``(N, |K|)`` — carry the current attack indicator forward.

        Args:
            x: History batch, used only for its shape.
            current_risk: Optional ``(N,)`` current risk (ground-truth label or
                an upstream detector's score). When ``None``, emits zeros, which
                makes this a trivial "never alert" baseline — note which variant
                a results table used.
        """
        raise NotImplementedError("TODO: broadcast current_risk over the horizons")

    def predict_stage(
        self, x: np.ndarray, current_stage: np.ndarray | None = None
    ) -> np.ndarray:
        """``(N, |K|)`` int64 — carry the current ATT&CK stage forward."""
        raise NotImplementedError("TODO: broadcast current_stage, default BENIGN (0)")


def drift_persistence(x: np.ndarray, horizons: Sequence[int]) -> np.ndarray:
    """Linear extrapolation: ``x_{t+k} = x_t + k * (x_t - x_{t-1})``.

    A stronger null model than flat persistence, and a fairer bar for the world
    model, since it at least knows the state is moving.
    """
    raise NotImplementedError("TODO: last difference times horizon, added to the last value")


__all__ = ["PersistenceBaseline", "drift_persistence"]
