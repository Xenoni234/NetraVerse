"""Per-host and peer-group behavioural baselines.

Raw volume is a poor attack signal: a busy mail server pushing 200 MB in 30 s is
normal; a printer doing the same is not. This module turns absolute features
into *deviation from that host's own normality* and *deviation from its peers*,
which is what the model actually needs to generalise across networks.

Two baselines
-------------
**Per-host (temporal).** A trailing rolling median and IQR of each host's own
recent behaviour, over ``baseline_window_minutes``. Answers: "is this host
behaving unlike itself?"

**Peer-group (spatial).** The median and IQR across hosts in the same peer group
(default: same /24 subnet) within the same window. Answers: "is this host
behaving unlike its neighbours right now?"

Both feed the two LOCKED baseline features:
``zscore_bytes_vs_host_baseline`` and ``zscore_fanout_vs_peergroup``.

Causality
---------
The per-host baseline MUST be trailing and MUST exclude the current window —
otherwise an attack contaminates the baseline it is being compared against, and
the z-score silently shrinks. Use ``closed="left"`` on the rolling window.

Cold start
----------
A host with too little history has no baseline. Emit 0.0 (no evidence of
deviation) rather than a large spurious z-score, and expose the count so the
demo can label such hosts "insufficient history".

TODO
----
* [ ] Implement ``fit_host_baselines`` (trailing rolling median/IQR per entity).
* [ ] Implement ``fit_peergroup_baselines`` (cross-sectional per window+group).
* [ ] Implement ``robust_zscore`` using median/IQR, not mean/std — one DDoS
      window would wreck a mean-based baseline.
* [ ] Implement ``peer_group_key`` for subnet_24 / subnet_16 / role-based groups.
* [ ] DECIDE: should baselines be fit on train-only data and frozen, or computed
      online at inference? Online is more realistic; frozen is more reproducible.
      Record the decision in DESIGN.md.
* [ ] Handle the cold-start case explicitly and test it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

import numpy as np
import pandas as pd

#: Minimum trailing windows before a per-host baseline is trusted.
MIN_HISTORY_WINDOWS: Final[int] = 6

#: Value emitted when no baseline is available (cold start).
COLD_START_ZSCORE: Final[float] = 0.0

#: Features this module contributes to the LOCKED schema.
BASELINE_FEATURE_COLUMNS: Final[tuple[str, ...]] = (
    "zscore_bytes_vs_host_baseline",
    "zscore_fanout_vs_peergroup",
)


@dataclass(frozen=True)
class BaselineConfig:
    """Baseline computation parameters, normally from a config YAML."""

    baseline_window_minutes: int = 30
    peer_group_key: str = "subnet_24"  # subnet_24 | subnet_16 | role
    min_history_windows: int = MIN_HISTORY_WINDOWS
    exclude_current_window: bool = True  # non-negotiable for causality


def add_baseline_features(
    windows: pd.DataFrame, config: BaselineConfig | None = None
) -> pd.DataFrame:
    """Append :data:`BASELINE_FEATURE_COLUMNS` to a windowed feature frame.

    Args:
        windows: Per-entity, per-window features from
            :func:`src.features.extractor.extract_frame_features`.
        config: Baseline parameters.

    Returns:
        A copy of ``windows`` with the two baseline z-score columns added.
    """
    raise NotImplementedError("TODO: host baseline + peer baseline -> two z-scores")


def fit_host_baselines(
    windows: pd.DataFrame,
    columns: tuple[str, ...],
    *,
    config: BaselineConfig | None = None,
    entity_col: str = "entity_id",
) -> pd.DataFrame:
    """Trailing per-host median and IQR for each column in ``columns``.

    Must use a time-based rolling window with ``closed="left"`` so the current
    window never contributes to its own baseline.
    """
    raise NotImplementedError("TODO: groupby(entity).rolling(time, closed='left') median/IQR")


def fit_peergroup_baselines(
    windows: pd.DataFrame,
    columns: tuple[str, ...],
    *,
    config: BaselineConfig | None = None,
    window_col: str = "window_start",
) -> pd.DataFrame:
    """Cross-sectional median and IQR across peers within each window.

    Excludes the host itself from its own peer statistics (leave-one-out), so a
    single dominant host cannot define the normality it is measured against.
    """
    raise NotImplementedError("TODO: groupby(window, peer_group) leave-one-out median/IQR")


def robust_zscore(
    value: pd.Series | np.ndarray,
    center: pd.Series | np.ndarray,
    scale: pd.Series | np.ndarray,
    *,
    cold_start_mask: pd.Series | np.ndarray | None = None,
) -> pd.Series | np.ndarray:
    """``(value - median) / IQR``, clipped and cold-start-safe.

    Uses median/IQR rather than mean/std so a single extreme window cannot
    destroy the baseline. Where ``scale`` is zero or ``cold_start_mask`` is set,
    returns :data:`COLD_START_ZSCORE`.
    """
    raise NotImplementedError("TODO: robust z-score with zero-scale and cold-start handling")


def peer_group_key(entity_ids: pd.Series, method: str = "subnet_24") -> pd.Series:
    """Derive the peer-group label for each entity.

    ``subnet_24`` truncates an IPv4 address to its first three octets;
    ``subnet_16`` to two; ``role`` looks up an operator-supplied asset table
    (not available for the public datasets — falls back to ``subnet_24``).
    """
    raise NotImplementedError("TODO: IP truncation; validate non-IPv4 entity ids")


def baseline_state_dict(windows: pd.DataFrame) -> dict[str, np.ndarray]:
    """Export fitted baseline statistics for saving into a checkpoint.

    Needed if we go with frozen (train-fit) baselines rather than online ones —
    see the open decision in the module TODO.
    """
    raise NotImplementedError("TODO: serialise per-entity and per-group statistics")


__all__ = [
    "MIN_HISTORY_WINDOWS",
    "COLD_START_ZSCORE",
    "BASELINE_FEATURE_COLUMNS",
    "BaselineConfig",
    "add_baseline_features",
    "fit_host_baselines",
    "fit_peergroup_baselines",
    "robust_zscore",
    "peer_group_key",
    "baseline_state_dict",
]
