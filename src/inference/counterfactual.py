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

from src.data.windowing import (
    MASK_COLUMNS,
    MODEL_COLUMNS,
    STATE_FEATURE_COLUMNS,
    WindowConfig,
    build_windows,
)

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

    Returns one row per origin window (``risk_k*``), the **same length** as the
    baseline so the mitigated curve is fully calculated end-to-end — never a
    zero-filled gap.

    The window timeline is kept intact and only the **post-cut** windows are
    rewritten to reflect the decision:

    * traffic that survives the action (e.g. the 20 % kept by ``rate_limit``) is
      re-derived from the edited flows — a genuine reduced-load feature vector;
    * traffic that the action removes entirely (``block_source_ip`` /
      ``isolate_host`` …) leaves the host **quiet** (a no-activity state), not
      absent. Re-forecasting that sequence lets the model decay the risk
      gradually to its own benign floor as the attack scrolls out of the 10-window
      history — a real, calculated drop, not an imposed 0.
    """
    work = flows.copy()
    if "campaign_id" not in work.columns:
        work = work.assign(campaign_id="counterfactual")
    cfg = WindowConfig(entity_granularity=entity_granularity)
    base_all = build_windows(work, cfg)
    base = (base_all.loc[base_all["entity_id"].astype(str) == str(host)]
            .sort_values("window_start").reset_index(drop=True))
    if base.empty:
        return pd.DataFrame()
    if action_type == "noop":
        return fc.forecast_host_timeline(base, mc_samples=mc_samples)

    edited = apply_decision(work, action_type, cut_ts, target_ip, target_port=target_port)
    edit_all = build_windows(edited, cfg) if not edited.empty else base.iloc[0:0]
    edit = (edit_all.loc[edit_all["entity_id"].astype(str) == str(host)]
            .drop_duplicates("window_start").set_index("window_start"))

    cut = pd.Timestamp(cut_ts)
    mit = base.copy()
    post = pd.to_datetime(mit["window_start"], utc=True) >= cut
    keeps = mit["window_start"].isin(edit.index)
    feat_cols = [c for c in MODEL_COLUMNS if c in mit.columns and c in edit.columns]

    reduced = post & keeps          # action throttled but did not remove the host
    if reduced.any() and feat_cols:
        aligned = edit.reindex(mit.loc[reduced, "window_start"])
        for c in feat_cols:
            mit.loc[reduced, c] = aligned[c].to_numpy()

    removed = post & ~keeps          # action removed the host's traffic -> quiet host
    if removed.any():
        for c in STATE_FEATURE_COLUMNS:
            if c in mit.columns:
                mit.loc[removed, c] = 0.0
        for c in MASK_COLUMNS:       # a quiet window is observed-benign, not warmup
            if c in mit.columns:
                mit.loc[removed, c] = 1.0

    return fc.forecast_host_timeline(mit, mc_samples=mc_samples)


def compare_timelines(
    baseline: pd.DataFrame,
    mitigated: pd.DataFrame,
    *,
    threshold: float,
    cut_ts: "pd.Timestamp | None" = None,
    horizon_col: str = "risk_k4",
    settle_ts: "pd.Timestamp | None" = None,
) -> dict[str, Any]:
    """Align baseline vs mitigated risk by window and summarize the FUTURE impact.

    Containment starts at ``cut_ts``: windows *before* it are unchanged history.
    ``peak_before`` (what the attack would have reached) is the max baseline risk
    over the **post-cut** windows.

    Judging whether the action worked needs care because the forecast lags the
    block: for one history-length (~5 min) after the cut, origin windows still
    forecast from *pre-block* history and stay elevated even though the attacker's
    traffic has already stopped. Those transition windows don't reflect the
    post-block reality, so ``peak_after`` and ``prevented`` are measured over the
    **settled** region (windows at/after ``settle_ts``). If the attacker has no
    flows left to reach the settled region, the attack is contained (peak_after
    0). ``settle_ts`` defaults to ``cut_ts`` (no transition allowance) for
    backward compatibility; callers pass ``cut + history_length·30s``.
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
    settle = pd.Timestamp(settle_ts) if settle_ts is not None else cut

    baseline_arr, mitigated_arr = [], []
    post_base, settled_mit = [], []
    for w in windows:
        b = base.get(w, 0.0)
        wt = pd.Timestamp(w)
        is_post = cut is None or wt >= cut
        m = mit.get(w, 0.0) if is_post else b  # unchanged history before the cut
        baseline_arr.append({"window_start": w, "risk": round(b, 6)})
        mitigated_arr.append({"window_start": w, "risk": round(m, 6)})
        if is_post:
            post_base.append(b)
            if settle is None or wt >= settle:
                settled_mit.append(m)

    peak_before = round(max(post_base, default=0.0), 6)   # what the attack WOULD reach
    # Settled post-block risk. No settled windows => the attacker was fully cut
    # off before the forecast could settle => contained (0).
    peak_after = round(max(settled_mit, default=0.0), 6)
    return {
        "baseline": baseline_arr,
        "mitigated": mitigated_arr,
        "peak_before": peak_before,
        "peak_after": peak_after,
        "risk_drop": round(max(0.0, peak_before - peak_after), 6),
        "prevented": bool(peak_after < float(threshold)),
        "threshold": round(float(threshold), 6),
        "cut_window": None if cut is None else str(cut),
        "settle_window": None if settle is None else str(settle),
        "horizon": horizon_col,
    }


__all__ = ["apply_decision", "mitigated_timeline", "compare_timelines"]
