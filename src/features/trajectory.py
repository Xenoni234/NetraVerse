"""Derivative / velocity features — how fast the network state is changing.

Levels tell you where a host is; derivatives tell you where it is heading. An
attack ramp-up is often visible as acceleration in fan-out or byte rate several
windows before either crosses an absolute threshold, and that head start is
exactly the lead time this project is judged on.

Contributes the two LOCKED trajectory features:
``d_bytes_per_sec_dt`` and ``d_fanout_dt``.

Numerical notes
---------------
* Use a **backward** difference (``x_t - x_{t-1}``), never a centred one — a
  centred difference reads ``x_{t+1}`` and leaks the future.
* Divide by the actual elapsed time, not the nominal stride: entities go silent,
  and pretending a 5-minute gap was 10 s produces a fake spike.
* The first window of every entity has no derivative. Emit 0.0, not NaN.
* Consider log1p-ing heavy-tailed levels before differencing so the derivative
  measures *relative* change; a 10 MB/s jump means something different on a
  backbone link than on a printer.

TODO
----
* [ ] Implement ``add_trajectory_features`` (the two LOCKED columns).
* [ ] Implement ``first_difference`` with true elapsed-time denominators.
* [ ] Implement ``rolling_slope`` (least-squares slope over the last n windows)
      as a less noisy alternative, and A/B it against the plain difference.
* [ ] Implement ``ewma_acceleration`` (second derivative, smoothed) — candidate
      feature for schema v1.1 if the ablation shows it helps.
* [ ] DECIDE: log1p before differencing? Test on the exploration notebook and
      record the answer in DESIGN.md.
* [ ] Assert no group's derivative is computed across a campaign boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Sequence

import numpy as np
import pandas as pd

#: Features this module contributes to the LOCKED schema.
TRAJECTORY_FEATURE_COLUMNS: Final[tuple[str, ...]] = (
    "d_bytes_per_sec_dt",
    "d_fanout_dt",
)

#: Source columns the two derivatives are taken of.
DERIVATIVE_SOURCES: Final[dict[str, str]] = {
    "d_bytes_per_sec_dt": "bytes_per_sec",
    "d_fanout_dt": "n_distinct_dst_ip",
}

#: Emitted for the first window of an entity, where no derivative exists.
NO_HISTORY_VALUE: Final[float] = 0.0

#: Elapsed-time gap beyond which the previous window is treated as unrelated.
MAX_GAP_SECONDS: Final[float] = 300.0


@dataclass(frozen=True)
class TrajectoryConfig:
    """Trajectory feature parameters."""

    use_log1p: bool = True
    method: str = "difference"  # difference | rolling_slope
    slope_window: int = 3
    max_gap_seconds: float = MAX_GAP_SECONDS


def add_trajectory_features(
    windows: pd.DataFrame, config: TrajectoryConfig | None = None
) -> pd.DataFrame:
    """Append :data:`TRAJECTORY_FEATURE_COLUMNS` to a windowed feature frame.

    Args:
        windows: Per-entity, per-window features, sorted by ``window_start``
            within each ``entity_id``.
        config: Differencing method and options.

    Returns:
        A copy of ``windows`` with the two derivative columns added, finite and
        ``float32``.
    """
    raise NotImplementedError("TODO: per-entity backward differences over DERIVATIVE_SOURCES")


def first_difference(
    values: pd.Series,
    timestamps: pd.Series,
    *,
    use_log1p: bool = True,
    max_gap_seconds: float = MAX_GAP_SECONDS,
) -> pd.Series:
    """Backward difference per unit of *actual* elapsed time.

    ``(f(x_t) - f(x_{t-1})) / (t - t_{-1})``, where ``f`` is ``log1p`` when
    ``use_log1p``. Gaps longer than ``max_gap_seconds`` reset to
    :data:`NO_HISTORY_VALUE` rather than producing a fabricated spike.
    """
    raise NotImplementedError("TODO: diff / elapsed seconds, with gap and first-row handling")


def rolling_slope(
    values: pd.Series, timestamps: pd.Series, *, window: int = 3
) -> pd.Series:
    """Least-squares slope over the trailing ``window`` observations.

    Less jumpy than a single difference; costs ``window - 1`` extra windows of
    warm-up. Trailing only — must not read future windows.
    """
    raise NotImplementedError("TODO: trailing OLS slope, vectorised where possible")


def ewma_acceleration(
    velocity: pd.Series, *, halflife_windows: float = 3.0
) -> pd.Series:
    """Smoothed second derivative — is the ramp itself steepening?

    Candidate for schema v1.1; not in the LOCKED 32 yet.
    """
    raise NotImplementedError("TODO: ewm over the difference of velocity")


def assert_no_cross_group_derivatives(
    windows: pd.DataFrame,
    derivative_columns: Sequence[str] = TRAJECTORY_FEATURE_COLUMNS,
    *,
    entity_col: str = "entity_id",
    campaign_col: str = "campaign_id",
) -> None:
    """Assert the first row of every (entity, campaign) group has no derivative.

    Guards the most likely bug in this module: a ``diff()`` applied to the whole
    frame instead of per group, quietly differencing across host boundaries.
    """
    raise NotImplementedError("TODO: check first row per group equals NO_HISTORY_VALUE")


__all__ = [
    "TRAJECTORY_FEATURE_COLUMNS",
    "DERIVATIVE_SOURCES",
    "NO_HISTORY_VALUE",
    "MAX_GAP_SECONDS",
    "TrajectoryConfig",
    "add_trajectory_features",
    "first_difference",
    "rolling_slope",
    "ewma_acceleration",
    "assert_no_cross_group_derivatives",
]
