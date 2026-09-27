"""Counterfactual "what-if" engine (FR16, R17).

An action is modelled by its effect on the observation stream: the flows the
rule would drop (or throttle) are removed from the traffic from the decision
time onward. Then the SAME fusion + world model run again:

* ``projected``: the latent state is re-filtered over the history whose most
  recent window reflects the action, and the same prior ``rollout()`` runs 300 s
  ahead - the forward curve shown right after the decision;
* ``continuation``: for recorded traffic we also replay every later window with
  the action applied, so the timeline continues with the mitigated reality.

Reject = no change ("cost of inaction" branch).
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from src.decision.rule_engine import Action

KEEP_FRACTION = 0.1


def _involves(flows: pd.DataFrame, ip: str | None) -> pd.Series:
    if not ip:
        return pd.Series(False, index=flows.index)
    return (flows["src_ip"] == ip) | (flows["dst_ip"] == ip)


def affected_mask(flows: pd.DataFrame, action: Action) -> pd.Series:
    """Rows the action drops (before throttling selection)."""
    k = action.kind
    if k in ("block_source", "isolate_host"):
        return _involves(flows, action.target)
    if k == "block_pair":
        m = (((flows["src_ip"] == action.target) & (flows["dst_ip"] == action.peer))
             | ((flows["src_ip"] == action.peer) & (flows["dst_ip"] == action.target)))
        if action.port:
            m &= (flows["dport"] == action.port) | (flows["sport"] == action.port)
        return m
    if k == "rate_limit":
        return _involves(flows, action.target)
    if k == "block_egress":
        peers = set(action.peers or ([action.peer] if action.peer else []))
        return (flows["src_ip"] == action.target) & flows["dst_ip"].isin(peers)
    if k == "throttle_egress":
        return flows["src_ip"] == action.target
    return pd.Series(False, index=flows.index)


def apply_to_flows(flows: pd.DataFrame, action: Action, t_from: float) -> pd.DataFrame:
    """Canonical flow table as it would have looked with ``action`` in force from ``t_from``."""
    if action.kind == "monitor":
        return flows
    hit = affected_mask(flows, action) & (flows["ts_end"] >= t_from)
    if action.kind in ("rate_limit", "throttle_egress"):
        idx = np.flatnonzero(hit.to_numpy())
        keep = idx[:: int(round(1 / KEEP_FRACTION))]       # deterministic 1-in-10 survivors
        hit.iloc[keep] = False
    return flows[~hit.to_numpy()].reset_index(drop=True)


def delta(before: list[float], after: list[float]) -> dict:
    b, a = float(np.max(before)), float(np.max(after))
    return {"peak_before": round(b, 4), "peak_after": round(a, 4),
            "absolute_change": round(a - b, 4),
            "relative_change": round((a - b) / b, 4) if b > 0 else 0.0}
