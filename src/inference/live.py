"""Live-flow ingestion for the server test.

Turns CICFlowMeter output (from the capture agent on the Tailscale server) into
the unified per-flow frame the pipeline expects, then per-host 30 s windows.

Handles the realities of live capture:
- **No `Label`** — live traffic is unlabelled; we inject placeholder labels so
  `build_windows` runs (the forecast risk is what matters; ground truth for
  lead-time comes from the operator's known attack-launch time).
- **Header variants** — CICFlowMeter versions differ ("Src IP" vs "Source IP",
  etc.); we auto-detect whichever unified column map fits best.
- **Missing features** — any flow feature the tool doesn't emit is filled with 0
  (same policy as CTU-13), so the model always gets its full input width.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from src.data import windowing as W
from src.data import labeller as _lab
from src.data.loaders import _parse_timestamps  # reuse the tz-aware parser
from src.data.unified_schema import (
    CICIDS2017_COLUMN_MAP,
    CICIDS2018_COLUMN_MAP,
    FLOW_FEATURE_COLUMNS,
)

#: Python `cicflowmeter` (pip) emits snake_case columns, in microseconds like CIC.
#: Mapping them lets us skip the finicky Java CICFlowMeter build on the server.
CICFLOWMETER_PY_COLUMN_MAP = {
    "src_ip": "src_ip", "dst_ip": "dst_ip", "src_port": "src_port",
    "dst_port": "dst_port", "protocol": "protocol", "timestamp": "timestamp",
    "flow_duration": "flow_duration",
    "flow_pkts_s": "packets_per_second", "flow_byts_s": "bytes_per_second",
    "down_up_ratio": "fwd_bwd_ratio",
    "tot_fwd_pkts": "fwd_packets", "tot_bwd_pkts": "bwd_packets",
    "totlen_fwd_pkts": "fwd_bytes", "totlen_bwd_pkts": "bwd_bytes",
    "flow_iat_mean": "iat_mean", "flow_iat_std": "iat_std", "flow_iat_max": "iat_max",
    "syn_flag_cnt": "syn_count", "ack_flag_cnt": "ack_count", "fin_flag_cnt": "fin_count",
    "rst_flag_cnt": "rst_count", "psh_flag_cnt": "psh_count", "urg_flag_cnt": "urg_count",
    "pkt_len_mean": "pkt_len_mean", "pkt_len_std": "pkt_len_std",
    "fwd_pkt_len_mean": "fwd_pkt_len_mean",
    "bwd_pkt_len_mean": "bwd_pkt_len_mean",
    "pkt_len_var": "pkt_len_var",
    "fwd_iat_mean": "fwd_iat_mean",
    "bwd_iat_mean": "bwd_iat_mean",
    "init_fwd_win_byts": "init_win_fwd",
    "init_bwd_win_byts": "init_win_bwd",
    "active_mean": "active_mean",
    "idle_mean": "idle_mean",
}

# Java CICFlowMeter 4.x emits a different spelling from both CIC-IDS2017 and
# the Python package.  In particular it uses ``Src IP`` (not ``Source IP``)
# and singular packet-counter names.  Keep this map explicit so live captures
# retain per-host identity and the packet-derived features used by the model.
CICFLOWMETER_JAVA_COLUMN_MAP = {
    "Flow ID": "flow_id", "Src IP": "src_ip", "Src Port": "src_port",
    "Dst IP": "dst_ip", "Dst Port": "dst_port", "Protocol": "protocol",
    "Timestamp": "timestamp",
    "Flow Duration": "flow_duration",
    "Total Fwd Packet": "fwd_packets", "Total Bwd packets": "bwd_packets",
    "Total Length of Fwd Packet": "fwd_bytes",
    "Total Length of Bwd Packet": "bwd_bytes",
    "Fwd Packet Length Mean": "fwd_pkt_len_mean",
    "Bwd Packet Length Mean": "bwd_pkt_len_mean",
    "Flow Bytes/s": "bytes_per_second", "Flow Packets/s": "packets_per_second",
    "Flow IAT Mean": "iat_mean", "Flow IAT Std": "iat_std",
    "Flow IAT Max": "iat_max",
    "Fwd IAT Mean": "fwd_iat_mean", "Bwd IAT Mean": "bwd_iat_mean",
    "SYN Flag Count": "syn_count", "ACK Flag Count": "ack_count",
    "FIN Flag Count": "fin_count", "RST Flag Count": "rst_count",
    "PSH Flag Count": "psh_count", "URG Flag Count": "urg_count",
    "Packet Length Mean": "pkt_len_mean", "Packet Length Std": "pkt_len_std",
    "Packet Length Variance": "pkt_len_var",
    "FWD Init Win Bytes": "init_win_fwd", "Bwd Init Win Bytes": "init_win_bwd",
    "Down/Up Ratio": "fwd_bwd_ratio",
    "Active Mean": "active_mean", "Idle Mean": "idle_mean",
}

_CANDIDATE_MAPS = {
    "cicflowmeter_java": CICFLOWMETER_JAVA_COLUMN_MAP,
    "cicids2017": CICIDS2017_COLUMN_MAP,
    "cicids2018": CICIDS2018_COLUMN_MAP,
    "cicflowmeter_py": CICFLOWMETER_PY_COLUMN_MAP,
}


def _detect_map(columns: list[str]) -> tuple[str, dict]:
    """Pick the column map whose source names best match these (stripped) headers."""
    cols = {c.strip() for c in columns}
    best, best_name, best_hits = None, None, -1
    for name, cmap in _CANDIDATE_MAPS.items():
        hits = sum(1 for src in cmap if src in cols)
        if hits > best_hits:
            best, best_name, best_hits = cmap, name, hits
    return best_name, best


def load_live_flows(
    path: Path | str, *, campaign_id: str = "live", return_report: bool = False,
    preserve_labels: bool = False,
):
    """Read CICFlowMeter CSV(s) into a unified flow frame.

    Cleans the uploaded/live capture before it reaches the model: drops fully-empty
    rows and exact-duplicate flows, coerces features to numeric, imputes non-finite
    values (inf/NaN -> 0), and drops rows with an unparseable timestamp or missing
    source IP. With ``return_report=True`` it also returns a plain dict of what it
    cleaned (row counts per step), for display in the demo.

    Args:
        path: a CICFlowMeter CSV file, or a directory of them.
        campaign_id: label for this capture session.
        return_report: when True, return ``(frame, report)`` instead of just the frame.

    Returns:
        Unified flow frame ready for :func:`src.data.windowing.build_windows`, or
        ``(frame, report)`` when ``return_report``.
    """
    path = Path(path)
    files = sorted(path.glob("*.csv")) if path.is_dir() else [path]
    if not files:
        raise FileNotFoundError(f"No CICFlowMeter CSVs found at {path}")

    frames = []
    for f in files:
        # on_bad_lines="skip": a live capture's last row may be mid-write
        df = pd.read_csv(f, low_memory=False, on_bad_lines="skip")
        df.columns = [str(c).strip() for c in df.columns]
        df = df.loc[:, ~pd.Index(df.columns).duplicated()]
        frames.append(df)
    raw = pd.concat(frames, ignore_index=True)
    report = {"rows_read": int(len(raw))}
    label_source = next((c for c in raw.columns if str(c).strip().lower() in
                         {"label", "attack_cat", "attack_category"}), None)

    # drop fully-empty rows (all cells NaN) - a common trailing-record artefact
    empty_mask = raw.isna().all(axis=1)
    report["empty_dropped"] = int(empty_mask.sum())
    raw = raw.loc[~empty_mask]

    name, cmap = _detect_map(list(raw.columns))
    hits = sum(1 for src in cmap if src in set(raw.columns))
    if hits < 6:
        raise ValueError(
            f"CICFlowMeter headers don't match a known map (best={name}, {hits} hits). "
            f"Columns seen: {sorted(raw.columns)[:20]}. Confirm the CICFlowMeter version."
        )

    work = raw.rename(columns=dict(cmap))
    # drop any duplicate unified names created by the rename
    work = work.loc[:, ~pd.Index(work.columns).duplicated()]

    # drop exact-duplicate flow rows
    before = len(work)
    work = work.drop_duplicates()
    report["duplicates_dropped"] = int(before - len(work))

    # numeric coercion for features; fill any feature the tool didn't emit with 0
    for col in FLOW_FEATURE_COLUMNS:
        if col in work.columns:
            work[col] = pd.to_numeric(work[col], errors="coerce")
        else:
            work[col] = 0.0
    feat = work[list(FLOW_FEATURE_COLUMNS)]
    nonfinite = int((~np.isfinite(feat.to_numpy(dtype="float64"))).sum())
    report["nonfinite_imputed"] = nonfinite
    report["nonfinite_pct"] = round(100.0 * nonfinite / max(feat.size, 1), 3)
    work[list(FLOW_FEATURE_COLUMNS)] = feat.replace([np.inf, -np.inf], np.nan).fillna(0.0)

    if "timestamp" not in work.columns:
        raise ValueError("Live flows have no Timestamp column; CICFlowMeter must emit one.")
    work["timestamp"] = _parse_timestamps(work["timestamp"])
    before = len(work)
    work = work[work["timestamp"].notna()].copy()
    report["bad_timestamp_dropped"] = int(before - len(work))

    if "src_ip" not in work.columns:
        raise ValueError(
            "Live flows have no source IP — per-host forecasting needs it. Ensure "
            "CICFlowMeter emits Src IP (run it on the raw interface, not an aggregated feed)."
        )
    before = len(work)
    work = work[work["src_ip"].notna()].copy()
    report["missing_src_ip_dropped"] = int(before - len(work))

    work["campaign_id"] = campaign_id
    work["dataset"] = name
    if preserve_labels and label_source is not None:
        # Labelled CIC-IDS2017 uploads use the project's canonical vocabulary.
        # Keep raw labels for auditability, then derive binary/stage labels using
        # the same path used by the training datasets.
        work["label_raw"] = raw.loc[work.index, label_source].astype("string").str.strip().to_numpy()
        work = _lab.label_frame(work, dataset="cicids2017", campaign_col="campaign_id",
                                 add_distance=True, strict=True, verbose=False)
        report["ground_truth"] = True
        report["label_column"] = label_source
        report["label_families"] = sorted(work["attack_family"].dropna().unique().tolist())
    else:
        # placeholders so build_windows runs on unlabelled live data
        work["binary_label"] = np.int8(0)
        work["attt_stage"] = np.int64(0)
        report["ground_truth"] = False
    out = work.sort_values("timestamp", kind="mergesort").reset_index(drop=True)
    report["flows_kept"] = int(len(out))
    report["column_map"] = name
    return (out, report) if return_report else out


def live_windows(
    path: Path | str, *, campaign_id: str = "live", entity_granularity: str = "src_ip",
    target_hosts: set[str] | None = None,
) -> pd.DataFrame:
    """Convenience: live flows -> per-host 30 s state windows (ready to forecast)."""
    flows = load_live_flows(path, campaign_id=campaign_id)
    windows = W.build_windows(flows, W.WindowConfig(entity_granularity=entity_granularity))
    if target_hosts:
        wanted = {str(host) for host in target_hosts}
        windows = windows.loc[windows["entity_id"].astype(str).isin(wanted)].copy()
    return windows


__all__ = ["load_live_flows", "live_windows"]
