"""Validation-only probability calibration for forecast heads."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True)
class HorizonCalibrator:
    """Piecewise-linear calibration maps fitted on validation predictions."""

    probabilities: tuple[tuple[float, ...], ...]
    observed_rates: tuple[tuple[float, ...], ...]

    def to_dict(self) -> dict:
        return {"probabilities": [list(v) for v in self.probabilities],
                "observed_rates": [list(v) for v in self.observed_rates]}

    @classmethod
    def from_dict(cls, value: dict) -> "HorizonCalibrator":
        return cls(tuple(tuple(float(x) for x in v) for v in value["probabilities"]),
                   tuple(tuple(float(x) for x in v) for v in value["observed_rates"]))

    def transform(self, probabilities: np.ndarray) -> np.ndarray:
        values = np.asarray(probabilities, dtype="float64")
        out = np.empty_like(values)
        for h in range(values.shape[1]):
            out[:, h] = np.interp(values[:, h], self.probabilities[h], self.observed_rates[h])
        return np.clip(out, 0.0, 1.0)


def fit_calibrator(y_true: np.ndarray, y_prob: np.ndarray, *, bins: int = 10) -> HorizonCalibrator:
    """Fit quantile-binned calibration maps without touching test data."""
    y = np.asarray(y_true).astype(float)
    p = np.asarray(y_prob).astype(float)
    if y.shape != p.shape or y.ndim != 2:
        raise ValueError("y_true and y_prob must be two-dimensional and equal-shaped")
    probability_maps, rate_maps = [], []
    for h in range(y.shape[1]):
        order = np.argsort(p[:, h], kind="mergesort")
        chunks = np.array_split(order, min(bins, len(order)))
        means = [(float(p[idx, h].mean()), float(y[idx, h].mean())) for idx in chunks if len(idx)]
        means.sort()
        probability_maps.append(tuple([0.0] + [m[0] for m in means] + [1.0]))
        rate_maps.append(tuple([means[0][1] if means else 0.0] + [m[1] for m in means] +
                               [means[-1][1] if means else 0.0]))
    return HorizonCalibrator(tuple(probability_maps), tuple(rate_maps))


__all__ = ["HorizonCalibrator", "fit_calibrator"]
