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
from src.data.loaders import _parse_timestamps  # reuse the tz-aware parser
from src.data.unified_schema import (
    CICIDS2017_COLUMN_MAP,
    CICIDS2018_COLUMN_MAP,
    FLOW_FEATURE_COLUMNS,
)

_CANDIDATE_MAPS = {"cicids2017": CICIDS2017_COLUMN_MAP, "cicids2018": CICIDS2018_COLUMN_MAP}


def _detect_map(columns: list[str]) -> tuple[str, dict]:
    """Pick the column map whose source names best match these (stripped) headers."""
    cols = {c.strip() for c in columns}
    best, best_name, best_hits = None, None, -1
    for name, cmap in _CANDIDATE_MAPS.items():
        hits = sum(1 for src in cmap if src in cols)
        if hits > best_hits:
            best, best_name, best_hits = cmap, name, hits
    return best_name, best


def load_live_flows(path: Path | str, *, campaign_id: str = "live") -> pd.DataFrame:
    """Read CICFlowMeter CSV(s) into a unified, unlabelled flow frame.

    Args:
        path: a CICFlowMeter CSV file, or a directory of them.
        campaign_id: label for this capture session.

    Returns:
        Unified flow frame (timestamp, src_ip, dst_ip, dst_port, protocol, the
        flow features, + placeholder binary_label/attt_stage) ready for
        :func:`src.data.windowing.build_windows`.
    """
    path = Path(path)
    files = sorted(path.glob("*.csv")) if path.is_dir() else [path]
    if not files:
        raise FileNotFoundError(f"No CICFlowMeter CSVs found at {path}")

    frames = []
    for f in files:
        df = pd.read_csv(f, low_memory=False)
        df.columns = [str(c).strip() for c in df.columns]
        df = df.loc[:, ~pd.Index(df.columns).duplicated()]
        frames.append(df)
    raw = pd.concat(frames, ignore_index=True)

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

    # numeric coercion for features; fill any feature the tool didn't emit with 0
    for col in FLOW_FEATURE_COLUMNS:
        if col in work.columns:
            work[col] = pd.to_numeric(work[col], errors="coerce")
        else:
            work[col] = 0.0
    work[list(FLOW_FEATURE_COLUMNS)] = (
        work[list(FLOW_FEATURE_COLUMNS)].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    )

    if "timestamp" not in work.columns:
        raise ValueError("Live flows have no Timestamp column; CICFlowMeter must emit one.")
    work["timestamp"] = _parse_timestamps(work["timestamp"])
    work = work[work["timestamp"].notna()].copy()

    if "src_ip" not in work.columns:
        raise ValueError(
            "Live flows have no source IP — per-host forecasting needs it. Ensure "
            "CICFlowMeter emits Src IP (run it on the raw interface, not an aggregated feed)."
        )

    work["campaign_id"] = campaign_id
    work["dataset"] = name
    # placeholders so build_windows runs on unlabelled live data
    work["binary_label"] = np.int8(0)
    work["attt_stage"] = np.int64(0)
    return work.sort_values("timestamp", kind="mergesort").reset_index(drop=True)


def live_windows(path: Path | str, *, campaign_id: str = "live") -> pd.DataFrame:
    """Convenience: live flows -> per-host 30 s state windows (ready to forecast)."""
    flows = load_live_flows(path, campaign_id=campaign_id)
    return W.build_windows(flows)


__all__ = ["load_live_flows", "live_windows"]
