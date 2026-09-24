"""Model-driven counterfactual: "if this decision were applied, what happens?"

The decision theater's edge is showing that a containment action *would have*
prevented the attack — computed by the world model, not scripted. The mechanism
is high-fidelity: take the raw flows, **edit them at the accept-point** as the
chosen action would (e.g. block_source_ip = drop that attacker's flows from the
cut onward), **re-window**, and **re-forecast**. All derived features (fan-out,
entropy, rates) are recomputed honestly, so the mitigated risk curve is a real
model output.

Reuses `build_windows` (`src/data/windowing.py`) and
`Forecaster.forecast_host_timeline` (`src/inference/engine.py`) unchanged — no
model changes, no retraining.
"""

from __future__ import annotations

from typing import Any

import pandas as pd

from src.data.windowing import WindowConfig, build_windows

#: How the six supported actions edit the flow stream after the cut-point.
#: block/isolate = remove the offending flows entirely; rate_limit = down-sample.
_DROP_SOURCE = {"block_source_ip", "isolate_host", "restrict_east_west"}
_DROP_DEST = {"block_destination_ip", "block_attack_port"}


def apply_decision(
    flows: pd.DataFrame,
    action_type: str,
    cut_ts: pd.Timestamp,
    target_ip: str,
    *,
    target_port: int | None = None,
) -> pd.DataFrame:
    """Return the flow rows as they would be **after** the decision is enforced.

    Only flows at/after ``cut_ts`` are affected (containment starts when the
    operator approves; earlier flows already happened).
    """
    if flows.empty or not target_ip:
        return flows
    work = flows.copy()
    ts = pd.to_datetime(work["timestamp"], utc=True, errors="coerce")
    after = ts >= pd.Timestamp(cut_ts)
    tip = str(target_ip)
    src = work["src_ip"].astype(str) if "src_ip" in work else pd.Series("", index=work.index)
    dst = work["dst_ip"].astype(str) if "dst_ip" in work else pd.Series("", index=work.index)

    if action_type in _DROP_SOURCE:
        drop = after & (src == tip)
        if action_type == "restrict_east_west":  # only internal (east-west) flows
            drop &= dst.str.startswith(("192.168.", "10.", "172.16.", "172.17.", "172.18."))
        return work.loc[~drop].reset_index(drop=True)

    if action_type in _DROP_DEST:
        drop = after & (dst == tip)
        if action_type == "block_attack_port" and target_port and "dst_port" in work:
            drop &= work["dst_port"].astype("float").fillna(-1).astype(int) == int(target_port)
        return work.loc[~drop].reset_index(drop=True)

    if action_type == "rate_limit":
        # keep every 5th flow of the throttled source after the cut (~80% cut)
        throttled = work.loc[after & (src == tip)]
        keep = throttled.index[::5]
        drop_idx = throttled.index.difference(keep)
        return work.drop(index=drop_idx).reset_index(drop=True)

    return work  # unknown action -> no change


def mitigated_timeline(
    flows: pd.DataFrame,
    host: str,
    action_type: str,
    cut_ts: pd.Timestamp,
    fc: Any,
    *,
    target_ip: str,
    target_port: int | None = None,
    entity_granularity: str = "src_ip",
    mc_samples: int = 0,
) -> pd.DataFrame:
    """Re-forecast ``host``'s risk timeline as if the decision were applied.

    Returns the same shape as ``forecast_host_timeline`` (rows per origin window
    with ``risk_k*``). Empty when the host has no remaining flows (fully
    contained) — the caller renders that as a flat, benign (risk≈0) tail.
    """
    edited = apply_decision(flows, action_type, cut_ts, target_ip, target_port=target_port)
    if edited.empty:
        return pd.DataFrame()
    if "campaign_id" not in edited.columns:
        edited = edited.assign(campaign_id="counterfactual")
    windows = build_windows(edited, WindowConfig(entity_granularity=entity_granularity))
    hw = windows.loc[windows["entity_id"].astype(str) == str(host)]
    if hw.empty:
        return pd.DataFrame()
    return fc.forecast_host_timeline(hw, mc_samples=mc_samples)


def compare_timelines(
    baseline: pd.DataFrame,
    mitigated: pd.DataFrame,
    *,
    threshold: float,
    cut_ts: "pd.Timestamp | None" = None,
    horizon_col: str = "risk_k4",
) -> dict[str, Any]:
    """Align baseline vs mitigated risk by window and summarize the FUTURE impact.

    Containment starts at ``cut_ts``: windows *before* it are unchanged history;
    windows *at/after* it carry the mitigated risk (~0 when the attacker is fully
    contained and thus has no remaining windows). "Prevented" and the peak
    before/after are measured over the **post-cut** windows only — the pre-cut
    peak already happened and can't be undone, so including it would hide the
    prevention.
    """
    def _series(df: pd.DataFrame) -> dict[str, float]:
        if df is None or df.empty or horizon_col not in df:
            return {}
        d = df.sort_values("window_start")
        return {str(w): float(r) for w, r in zip(d["window_start"], d[horizon_col])}

    base = _series(baseline)
    mit = _series(mitigated)
    windows = sorted(set(base) | set(mit))
    cut = pd.Timestamp(cut_ts) if cut_ts is not None else None

    baseline_arr, mitigated_arr = [], []
    post_base, post_mit = [], []
    for w in windows:
        b = base.get(w, 0.0)
        is_post = cut is None or pd.Timestamp(w) >= cut
        m = mit.get(w, 0.0) if is_post else b  # unchanged history before the cut
        baseline_arr.append({"window_start": w, "risk": round(b, 6)})
        mitigated_arr.append({"window_start": w, "risk": round(m, 6)})
        if is_post:
            post_base.append(b)
            post_mit.append(m)

    peak_before = round(max(post_base, default=0.0), 6)   # what the attack WOULD reach
    peak_after = round(max(post_mit, default=0.0), 6)      # what happens with the action
    return {
        "baseline": baseline_arr,
        "mitigated": mitigated_arr,
        "peak_before": peak_before,
        "peak_after": peak_after,
        "risk_drop": round(max(0.0, peak_before - peak_after), 6),
        "prevented": bool(peak_after < float(threshold)),
        "threshold": round(float(threshold), 6),
        "cut_window": None if cut is None else str(cut),
        "horizon": horizon_col,
    }


__all__ = ["apply_decision", "mitigated_timeline", "compare_timelines"]
