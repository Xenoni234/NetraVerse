"""The unified schema, and the per-dataset mappings onto it.

This module is the contract between "four messy public datasets" and everything
else. If a column is not defined here, no other module may use it.

Two schemas live here:

``UNIFIED_FLOW_COLUMNS``
    Per-flow record, after harmonising CIC / UNSW / CTU column names.

``FLOW_FEATURE_COLUMNS``
    The numeric per-flow features a model may consume, in FIXED order. Index
    ``i`` always means ``FLOW_FEATURE_COLUMNS[i]``.

Feature count is **derived, not decreed** (CLAUDE.md §4, resolved). The 19
flow-level features here are the per-flow columns CIC supplies directly; the
per-host **state** vector the model consumes is built in
:mod:`src.data.windowing` (``MODEL_COLUMNS``: aggregates + behavioural + masks),
and ``input_size`` is read from that, not hard-coded.

Leakage policy
--------------
:data:`LEAK_COLUMNS` are dropped before any model sees them, for two reasons:

*Identifier leakage.* ``Flow ID``, ``Src IP`` and ``Dst IP`` identify the
testbed's fixed attacker machines. A model given them learns "traffic from
18.219.211.138 is an attack", which is memorisation of one lab network and
transfers to nothing.

*Temporal leakage.* ``Timestamp`` is a near-perfect attack predictor in these
captures, because each attack was executed in a scheduled block. Keeping it
would let logistic regression read the clock instead of the traffic.

``Dst Port`` is dropped **by default** and this is a judgement call, not an
obvious one: it is a legitimate real-world feature, but in CIC-IDS2018 each
attack targets one fixed port (SSH brute force on 22, and so on), so it acts as
a near-label. Keeping it inflates F1 into the 0.95+ range, which the project
brief correctly identifies as a leakage signature. Set
``drop_dst_port=False`` to measure the difference — and report both numbers if
you do.
"""

from __future__ import annotations

from typing import Final, Mapping, Sequence

import pandas as pd

from src.data.paths import DatasetName

#: Bump on ANY change to the feature lists below.
SCHEMA_VERSION: Final[str] = "1.2.0-packet-derived"

# --------------------------------------------------------------------------- #
# Unified per-flow schema
# --------------------------------------------------------------------------- #

#: Identity / bookkeeping columns. Carried alongside features, never fed to a model.
INDEX_COLUMNS: Final[tuple[str, ...]] = (
    "timestamp",
    "dataset",
    "campaign_id",
)

#: Numeric per-flow features, in FIXED order. These are the 19 that CIC-IDS2018
#: supplies directly; behavioural and packet features are added by src.features.
FLOW_FEATURE_COLUMNS: Final[tuple[str, ...]] = (
    # duration / rate (4)
    "flow_duration",
    "packets_per_second",
    "bytes_per_second",
    "fwd_bwd_ratio",
    # volume (4)
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    # inter-arrival timing (3)
    "iat_mean",
    "iat_std",
    "iat_max",
    # TCP flag counts (6)
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "urg_count",
    # packet shape (2)
    "pkt_len_mean",
    "pkt_len_std",
    # packet-level, from the CSV's CICFlowMeter stats (9): packet shape per
    # direction, TCP window size, directional inter-arrival timing, active/idle
    # session timing. These expose the timing & sequencing the PS asks packet-level
    # features to capture (slow-scan / beaconing shape). (Header-length and
    # min-segment-size columns are dropped: CIC-IDS2017 ships them with a
    # CICFlowMeter signed-overflow bug — negative/absurd values.)
    "fwd_pkt_len_mean",
    "bwd_pkt_len_mean",
    "pkt_len_var",
    "fwd_iat_mean",
    "bwd_iat_mean",
    "init_win_fwd",
    "init_win_bwd",
    "active_mean",
    "idle_mean",
)

N_FLOW_FEATURES: Final[int] = len(FLOW_FEATURE_COLUMNS)

#: Behavioural features, computed over sliding windows by :mod:`src.features`.
BEHAVIORAL_FEATURE_COLUMNS: Final[tuple[str, ...]] = (
    "dst_port_entropy",
    "new_peer_count",
    "off_hours_ratio",
    "fan_out_count",
    "baseline_deviation",
    "trajectory_velocity",
)

#: Packet-level features from PCAP via TShark, when available.
PACKET_FEATURE_COLUMNS: Final[tuple[str, ...]] = (
    "ttl_mean",
    "ttl_variance",
    "tcp_window_mean",
    "tcp_window_std",
    "fragment_flag_count",
    "payload_size_mean",
    "payload_size_std",
    "retransmission_count",
)

#: Label columns produced by :mod:`src.data.labeller`.
LABEL_COLUMNS: Final[tuple[str, ...]] = (
    "binary_label",
    "attack_family",
    "attt_stage",
    "distance_to_attack",
)

UNIFIED_FLOW_COLUMNS: Final[tuple[str, ...]] = (
    INDEX_COLUMNS + ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")
    + FLOW_FEATURE_COLUMNS + ("label_raw",)
)

# --------------------------------------------------------------------------- #
# Leakage policy
# --------------------------------------------------------------------------- #

#: Dropped before any model sees them. See the module docstring for why.
LEAK_COLUMNS: Final[tuple[str, ...]] = (
    "Flow ID",
    "Src IP",
    "Dst IP",
    "Src Port",
    "Timestamp",
    "timestamp",
    "label_raw",
    "Label",
    "dataset",
    "campaign_id",
    "src_ip",
    "dst_ip",
    "src_port",
)

#: Dropped by default, kept only with ``drop_dst_port=False``. Judgement call.
SEMI_LEAK_COLUMNS: Final[tuple[str, ...]] = ("dst_port", "Dst Port", "protocol", "Protocol")

# --------------------------------------------------------------------------- #
# CIC-IDS2018 -> unified column map
# --------------------------------------------------------------------------- #

#: Source column name -> unified name. Keys match the CSV headers verbatim
#: after whitespace stripping.
CICIDS2018_COLUMN_MAP: Final[Mapping[str, str]] = {
    # identity
    "Timestamp": "timestamp",
    "Flow ID": "flow_id",
    "Src IP": "src_ip",
    "Dst IP": "dst_ip",
    "Src Port": "src_port",
    "Dst Port": "dst_port",
    "Protocol": "protocol",
    "Label": "label_raw",
    # duration / rate
    "Flow Duration": "flow_duration",
    "Flow Pkts/s": "packets_per_second",
    "Flow Byts/s": "bytes_per_second",
    "Down/Up Ratio": "fwd_bwd_ratio",
    # volume
    "Tot Fwd Pkts": "fwd_packets",
    "Tot Bwd Pkts": "bwd_packets",
    "TotLen Fwd Pkts": "fwd_bytes",
    "TotLen Bwd Pkts": "bwd_bytes",
    # inter-arrival timing
    "Flow IAT Mean": "iat_mean",
    "Flow IAT Std": "iat_std",
    "Flow IAT Max": "iat_max",
    # TCP flag counts
    "SYN Flag Cnt": "syn_count",
    "ACK Flag Cnt": "ack_count",
    "FIN Flag Cnt": "fin_count",
    "RST Flag Cnt": "rst_count",
    "PSH Flag Cnt": "psh_count",
    "URG Flag Cnt": "urg_count",
    # packet shape
    "Pkt Len Mean": "pkt_len_mean",
    "Pkt Len Std": "pkt_len_std",
    # packet-level (CICFlowMeter v3 names)
    "Fwd Pkt Len Mean": "fwd_pkt_len_mean",
    "Bwd Pkt Len Mean": "bwd_pkt_len_mean",
    "Pkt Len Var": "pkt_len_var",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Bwd IAT Mean": "bwd_iat_mean",
    "Init Fwd Win Byts": "init_win_fwd",
    "Init Bwd Win Byts": "init_win_bwd",
    "Active Mean": "active_mean",
    "Idle Mean": "idle_mean",
}

#: CIC-IDS2017 (TrafficLabelling variant) source column name -> unified name.
#: Different from 2018: "Total Fwd Packets" not "Tot Fwd Pkts", "Flow Bytes/s" not
#: "Flow Byts/s", etc. This variant carries Source/Destination IP + Timestamp + Label,
#: which is what makes per-host forecasting possible (the MachineLearningCVE variant
#: has no Timestamp and is unusable here).
CICIDS2017_COLUMN_MAP: Final[Mapping[str, str]] = {
    # identity
    "Flow ID": "flow_id",
    "Source IP": "src_ip",
    "Source Port": "src_port",
    "Destination IP": "dst_ip",
    "Destination Port": "dst_port",
    "Protocol": "protocol",
    "Timestamp": "timestamp",
    "Label": "label_raw",
    # duration / rate
    "Flow Duration": "flow_duration",
    "Flow Packets/s": "packets_per_second",
    "Flow Bytes/s": "bytes_per_second",
    "Down/Up Ratio": "fwd_bwd_ratio",
    # volume
    "Total Fwd Packets": "fwd_packets",
    "Total Backward Packets": "bwd_packets",
    "Total Length of Fwd Packets": "fwd_bytes",
    "Total Length of Bwd Packets": "bwd_bytes",
    # inter-arrival timing
    "Flow IAT Mean": "iat_mean",
    "Flow IAT Std": "iat_std",
    "Flow IAT Max": "iat_max",
    # TCP flag counts
    "SYN Flag Count": "syn_count",
    "ACK Flag Count": "ack_count",
    "FIN Flag Count": "fin_count",
    "RST Flag Count": "rst_count",
    "PSH Flag Count": "psh_count",
    "URG Flag Count": "urg_count",
    # packet shape
    "Packet Length Mean": "pkt_len_mean",
    "Packet Length Std": "pkt_len_std",
    # packet-level (CICFlowMeter v2 / 2017 names)
    "Fwd Packet Length Mean": "fwd_pkt_len_mean",
    "Bwd Packet Length Mean": "bwd_pkt_len_mean",
    "Packet Length Variance": "pkt_len_var",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Bwd IAT Mean": "bwd_iat_mean",
    "Init_Win_bytes_forward": "init_win_fwd",
    "Init_Win_bytes_backward": "init_win_bwd",
    "Active Mean": "active_mean",
    "Idle Mean": "idle_mean",
}

#: CTU-13 (original Stratosphere binetflow) -> unified. The binetflow lacks
#: per-flag counts, IAT stats and a fwd/bwd packet split, so those unified
#: features are filled with 0 by :func:`to_unified` (fan-out, ports, volume,
#: rate and entropy — the recon-ramp signals — are all available).
CTU13_COLUMN_MAP: Final[Mapping[str, str]] = {
    "StartTime": "timestamp",
    "SrcAddr": "src_ip",
    "DstAddr": "dst_ip",
    "Sport": "src_port",
    "Dport": "dst_port",
    "Proto": "protocol",
    "Dur": "flow_duration",       # converted to microseconds in the loader
    "TotPkts": "fwd_packets",     # no direction split in binetflow
    "SrcBytes": "fwd_bytes",
    "Label": "label_raw",
    # bwd_bytes is derived (TotBytes - SrcBytes) in the loader, already unified-named
}

# The UNSW loader converts the source fields into the canonical feature names.
UNSW_NB15_COLUMN_MAP: Final[Mapping[str, str]] = {
    column: column for column in UNIFIED_FLOW_COLUMNS
}

COLUMN_MAPS: Final[Mapping[str, Mapping[str, str]]] = {
    "cicids2017": CICIDS2017_COLUMN_MAP,
    "cicids2018": CICIDS2018_COLUMN_MAP,
    "ctu13": CTU13_COLUMN_MAP,
    "unsw_nb15": UNSW_NB15_COLUMN_MAP,
}


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def to_unified(frame: pd.DataFrame, dataset: DatasetName = "cicids2018") -> pd.DataFrame:
    """Map a raw loader frame onto the unified schema.

    Renames via :data:`COLUMN_MAPS`, keeps the index and feature columns, and
    drops everything else.

    Raises:
        ValueError: if a required feature column is missing after renaming, with
            the missing names listed.
    """
    if dataset not in COLUMN_MAPS:
        raise NotImplementedError(f"No column map for {dataset!r} yet")

    work = frame.copy()
    work.columns = [str(c).strip() for c in work.columns]

    # A loader may already have produced a canonical column (e.g. `timestamp`,
    # parsed and tz-aware) while the raw source column it derives from
    # (`Timestamp`, a naive string) is still present. Renaming would then create
    # two columns of the same name and every later sort or select would fail.
    # Prefer the loader's canonical column and drop the raw source.
    column_map = dict(COLUMN_MAPS[dataset])
    redundant = [
        source
        for source, target in column_map.items()
        if source != target and source in work.columns and target in work.columns
    ]
    if redundant:
        work = work.drop(columns=redundant)

    work = work.rename(columns=column_map)

    if work.columns.duplicated().any():
        dupes = work.columns[work.columns.duplicated()].unique().tolist()
        raise ValueError(f"{dataset}: duplicate columns after renaming: {dupes}")

    missing = [c for c in FLOW_FEATURE_COLUMNS if c not in work.columns]
    if missing:
        # CTU-13 binetflow genuinely lacks flag/IAT/pkt-len columns — fill with 0
        # (a documented gap, not a bug). Other datasets must supply all features.
        if dataset == "ctu13":
            import logging
            logging.getLogger(__name__).info(
                "ctu13: filling %d unavailable flow features with 0: %s", len(missing), missing)
            for c in missing:
                work[c] = 0.0
        else:
            raise ValueError(
                f"{dataset}: missing {len(missing)} feature column(s) after renaming: {missing}. "
                f"Available columns: {sorted(work.columns)[:25]}..."
            )

    keep = [c for c in UNIFIED_FLOW_COLUMNS if c in work.columns]
    return work.loc[:, keep].copy()


def model_feature_columns(*, drop_dst_port: bool = True) -> tuple[str, ...]:
    """The feature columns a model is allowed to consume.

    Args:
        drop_dst_port: Drop ``dst_port`` and ``protocol``. Default True — see the
            module docstring on why these behave as near-labels in CIC-IDS2018.
    """
    cols = list(FLOW_FEATURE_COLUMNS)
    if not drop_dst_port:
        cols += ["dst_port", "protocol"]
    return tuple(cols)


def select_features(
    frame: pd.DataFrame, *, drop_dst_port: bool = True
) -> tuple[pd.DataFrame, list[str]]:
    """Return the model-visible feature matrix and the dropped-column list.

    Every column in :data:`LEAK_COLUMNS` is removed, and
    :data:`SEMI_LEAK_COLUMNS` too unless ``drop_dst_port=False``.
    """
    wanted = [c for c in model_feature_columns(drop_dst_port=drop_dst_port) if c in frame.columns]
    dropped = [c for c in frame.columns if c not in wanted]
    return frame.loc[:, wanted].copy(), dropped


def clean_features(frame: pd.DataFrame, *, fill_value: float = 0.0) -> tuple[pd.DataFrame, dict]:
    """Make a feature matrix finite and float32, reporting what was changed.

    CIC-IDS2018 carries genuine infinities (zero-duration flows divided into a
    rate) and NaNs. Both are replaced with ``fill_value`` **after** counting, so
    the report says how much of the matrix was imputed rather than hiding it.

    Returns:
        ``(clean_frame, report)`` where report carries per-column non-finite
        counts and the overall imputed fraction.
    """
    import numpy as np

    numeric = frame.apply(pd.to_numeric, errors="coerce").astype("float64")
    nonfinite = ~np.isfinite(numeric.to_numpy())
    per_col = dict(zip(numeric.columns, nonfinite.sum(axis=0).tolist()))
    total = int(nonfinite.sum())

    cleaned = numeric.replace([np.inf, -np.inf], np.nan).fillna(fill_value).astype("float32")
    report = {
        "n_cells": int(numeric.size),
        "n_nonfinite": total,
        "imputed_fraction": (total / numeric.size) if numeric.size else 0.0,
        "per_column_nonfinite": {k: int(v) for k, v in per_col.items() if v},
        "fill_value": fill_value,
    }
    return cleaned, report


def validate_features(frame: pd.DataFrame, *, strict: bool = True) -> None:
    """Assert a feature matrix is finite and numeric.

    A NaN reaching a model is the most common silent bug in this pipeline.
    """
    import numpy as np

    non_numeric = [c for c in frame.columns if not pd.api.types.is_numeric_dtype(frame[c])]
    if non_numeric:
        raise TypeError(f"Non-numeric feature columns: {non_numeric}")
    bad = ~np.isfinite(frame.to_numpy(dtype="float64"))
    if bad.any():
        cols = frame.columns[bad.any(axis=0)].tolist()
        raise ValueError(f"Non-finite values remain in: {cols}")
    if strict and frame.empty:
        raise ValueError("Feature matrix is empty")


def feature_index(name: str) -> int:
    """Return the tensor index of feature ``name``."""
    try:
        return FLOW_FEATURE_COLUMNS.index(name)
    except ValueError:
        raise KeyError(f"{name!r} is not a flow feature; known: {FLOW_FEATURE_COLUMNS}") from None


__all__ = [
    "SCHEMA_VERSION",
    "INDEX_COLUMNS",
    "FLOW_FEATURE_COLUMNS",
    "N_FLOW_FEATURES",
    "BEHAVIORAL_FEATURE_COLUMNS",
    "PACKET_FEATURE_COLUMNS",
    "LABEL_COLUMNS",
    "UNIFIED_FLOW_COLUMNS",
    "LEAK_COLUMNS",
    "SEMI_LEAK_COLUMNS",
    "CICIDS2017_COLUMN_MAP",
    "CICIDS2018_COLUMN_MAP",
    "CTU13_COLUMN_MAP",
    "UNSW_NB15_COLUMN_MAP",
    "COLUMN_MAPS",
    "to_unified",
    "model_feature_columns",
    "select_features",
    "clean_features",
    "validate_features",
    "feature_index",
]
