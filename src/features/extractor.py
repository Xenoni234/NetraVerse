"""Flow-level feature extraction for a single (entity, window) group.

Produces the first 28 of the LOCKED 32 features (DESIGN.md section 2.2) from
unified flow records; the remaining 4 come from :mod:`src.features.baselines`
and :mod:`src.features.trajectory`.

Feature groups computed here
----------------------------
volume        ``n_flows``, ``n_pkts_fwd/bwd``, ``bytes_fwd/bwd``, ``bytes_ratio_fwd_bwd``
rate          ``flows_per_sec``, ``pkts_per_sec``, ``bytes_per_sec``, ``mean_flow_duration_s``
fan-out       distinct dst IP / dst port / src port, plus Shannon entropies
protocol mix  ``frac_tcp``, ``frac_udp``, ``frac_icmp``, ``frac_other``
flag health   ``frac_syn``, ``frac_syn_ack``, ``frac_rst``, ``frac_fin``, ``failed_conn_ratio``
shape         ``mean_pkt_size``, ``std_pkt_size``, ``mean_iat_s``, ``std_iat_s``

Why these: a port scan shows up as fan-out + entropy + ``failed_conn_ratio``
spiking while bytes stay flat; a DoS shows up as rate + ``frac_syn``; C2
beaconing shows up as low ``std_iat_s`` with small, regular packets. The feature
set is chosen so each stage of the kill chain has a signature.

TODO
----
* [ ] Implement ``extract_window_features`` (single group -> feature dict).
* [ ] Implement ``extract_frame_features`` (vectorised groupby over all windows).
* [ ] Implement ``shannon_entropy`` with a normalised (0..1) variant.
* [ ] Define ``failed_conn_ratio`` precisely per dataset (CIC has flag counts;
      CTU-13 only has flow state strings) and document the fallback.
* [ ] Guard every division by zero — an empty window must yield 0.0, not NaN.
* [ ] Benchmark: target < 60 s per capture day on a laptop.
"""

from __future__ import annotations

from typing import Final, Mapping, Sequence

import numpy as np
import pandas as pd

#: Features this module is responsible for, in FEATURE_COLUMNS order.
FLOW_FEATURE_COLUMNS: Final[tuple[str, ...]] = (
    "n_flows",
    "n_pkts_fwd",
    "n_pkts_bwd",
    "bytes_fwd",
    "bytes_bwd",
    "bytes_ratio_fwd_bwd",
    "flows_per_sec",
    "pkts_per_sec",
    "bytes_per_sec",
    "mean_flow_duration_s",
    "n_distinct_dst_ip",
    "n_distinct_dst_port",
    "n_distinct_src_port",
    "dst_port_entropy",
    "dst_ip_entropy",
    "frac_tcp",
    "frac_udp",
    "frac_icmp",
    "frac_other",
    "frac_syn",
    "frac_syn_ack",
    "frac_rst",
    "frac_fin",
    "failed_conn_ratio",
    "mean_pkt_size",
    "std_pkt_size",
    "mean_iat_s",
    "std_iat_s",
)

#: Value substituted for any undefined ratio (empty window, zero denominator).
SAFE_DEFAULT: Final[float] = 0.0


def extract_frame_features(
    flows: pd.DataFrame,
    *,
    window_seconds: int = 30,
    entity_col: str = "entity_id",
    window_col: str = "window_start",
) -> pd.DataFrame:
    """Vectorised extraction over every ``(entity, window)`` group.

    This is the hot path — prefer a single ``groupby().agg()`` with named
    aggregations over ``apply`` with a Python callable.

    Args:
        flows: Unified flow records, already assigned to windows.
        window_seconds: Window span, used for the rate denominators.
        entity_col: Grouping key for the monitored entity.
        window_col: Grouping key for the window bucket.

    Returns:
        One row per group, with :data:`FLOW_FEATURE_COLUMNS` plus the index
        columns, all ``float32`` and finite.
    """
    raise NotImplementedError("TODO: named groupby aggregations, then derived ratios")


def extract_window_features(
    group: pd.DataFrame, *, window_seconds: int = 30
) -> Mapping[str, float]:
    """Compute :data:`FLOW_FEATURE_COLUMNS` for one window of one entity.

    Reference implementation — correct and readable, used by tests to validate
    the fast vectorised path in :func:`extract_frame_features`.
    """
    raise NotImplementedError("TODO: the readable reference implementation")


def shannon_entropy(
    values: Sequence[object] | pd.Series | np.ndarray, *, normalise: bool = True
) -> float:
    """Shannon entropy of a categorical column (dst port, dst IP).

    Args:
        values: Observed categories in the window.
        normalise: Divide by ``log2(n_distinct)`` so the result sits in ``[0, 1]``
            and does not implicitly encode volume.

    Returns:
        Entropy, or :data:`SAFE_DEFAULT` for an empty or single-valued input.
    """
    raise NotImplementedError("TODO: value_counts -> probabilities -> -sum(p log2 p)")


def safe_divide(
    numerator: float | np.ndarray, denominator: float | np.ndarray, default: float = SAFE_DEFAULT
) -> float | np.ndarray:
    """Division that returns ``default`` instead of inf/NaN on a zero divisor."""
    raise NotImplementedError("TODO: np.divide with where= and a fill value")


def failed_connection_ratio(group: pd.DataFrame) -> float:
    """Fraction of flows that look like failed connection attempts.

    Primary definition (CIC / UNSW): flows with SYN but no SYN-ACK, plus flows
    ending in RST, over total TCP flows. Fallback (CTU-13): flow-state strings
    containing ``S0``/``REJ``/``RSTO``. Document whichever is used.
    """
    raise NotImplementedError("TODO: dataset-aware definition with a documented fallback")


def assert_feature_sanity(features: pd.DataFrame) -> None:
    """Fail loudly on NaN/inf, negative counts, or fractions outside ``[0, 1]``.

    Cheap insurance: a silent NaN here becomes a silently dead neuron later.
    """
    raise NotImplementedError("TODO: range and finiteness assertions with column names")


__all__ = [
    "FLOW_FEATURE_COLUMNS",
    "SAFE_DEFAULT",
    "extract_frame_features",
    "extract_window_features",
    "shannon_entropy",
    "safe_divide",
    "failed_connection_ratio",
    "assert_feature_sanity",
]
