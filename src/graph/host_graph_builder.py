"""Host graph (FR5/FR19): hosts = nodes, flows = edges - static per file, incremental live.

Also derives attacker / victim roles from MODEL OUTPUT plus observed traffic
direction (FR20, R14) - nothing is hardcoded:

* a host whose forecast risk crosses the threshold is *alerting*;
* an alerting host that mostly *initiates* flows is the attacker, and the hosts
  it sends the most flows to are its victims;
* an alerting host that mostly *receives* flows is a victim, and its heaviest
  inbound peer is marked as the attacker.
"""
from __future__ import annotations

import networkx as nx
import numpy as np
import pandas as pd

from src.mitre.stage_mapper import map_stage

LOOKBACK = 3   # windows of traffic used to decide direction


def build_graph(flows: pd.DataFrame, hosts: list[str] | None = None) -> nx.DiGraph:
    g = nx.DiGraph()
    agg = flows.groupby(["src_ip", "dst_ip"]).agg(flows=("ts_end", "size"),
                                                  bytes=("fwd_bytes", "sum")).reset_index()
    if hosts is not None:
        hs = set(hosts)
        agg = agg[agg["src_ip"].isin(hs) & agg["dst_ip"].isin(hs)]
    for r in agg.itertuples(index=False):
        g.add_edge(r.src_ip, r.dst_ip, flows=int(r.flows), bytes=float(r.bytes))
    return g


class IncrementalGraph:
    """Live mode: edges accumulate window by window (FR21)."""

    def __init__(self):
        self.g = nx.DiGraph()

    def update(self, flows: pd.DataFrame) -> None:
        for (s, d), n in flows.groupby(["src_ip", "dst_ip"]).size().items():
            if self.g.has_edge(s, d):
                self.g[s][d]["flows"] += int(n)
            else:
                self.g.add_edge(s, d, flows=int(n))


def roles_at(edges: pd.DataFrame, window: int, risk: dict, threshold: float,
             focus: str | None = None) -> dict:
    e = edges[(edges["window"] <= window) & (edges["window"] > window - LOOKBACK)] if edges is not None \
        and len(edges) else pd.DataFrame(columns=["a", "b", "window", "flows"])
    out_f = e.groupby("a")["flows"].sum()
    in_f = e.groupby("b")["flows"].sum()
    alerting = {h for h, r in risk.items() if r >= threshold}
    if focus:
        alerting.add(focus)
    roles: dict = {"_victims_of": {}}
    attackers: dict[str, list[str]] = {}
    victims: dict[str, str] = {}
    for h in sorted(alerting, key=lambda k: -risk.get(k, 0)):
        o, i = float(out_f.get(h, 0)), float(in_f.get(h, 0))
        if o >= i:
            tgt = e[e["a"] == h].groupby("b")["flows"].sum().sort_values(ascending=False)
            attackers[h] = tgt.head(3).index.tolist()
        else:
            src = e[e["b"] == h].groupby("a")["flows"].sum().sort_values(ascending=False)
            atk = src.index[0] if len(src) else None
            victims[h] = atk
            if atk is not None:
                attackers.setdefault(atk, [])
                if h not in attackers[atk]:
                    attackers[atk].append(h)
    for atk, vs in attackers.items():
        roles[atk] = {"role": "attacker", "victims": vs}
        roles["_victims_of"][atk] = vs
        for v in vs:
            if v not in attackers:
                roles[v] = {"role": "victim", "attacker": atk}
    for v, atk in victims.items():
        if v not in attackers:
            roles[v] = {"role": "victim", "attacker": atk}
    return roles


def topology_snapshot(frame: pd.DataFrame, edges: pd.DataFrame, window: int, risk: dict, stage_p: dict,
                      roles: dict, threshold: float, mitigated: set, max_nodes: int = 60) -> dict:
    upto = frame[frame["window"] <= window]
    vol = (upto.groupby("host")["out_flows"].sum() + upto.groupby("host")["in_flows"].sum()).sort_values(
        ascending=False)
    vol = vol[vol > 0]
    keep = [h for h in roles if not h.startswith("_")]
    for h in vol.index:
        if len(keep) >= max_nodes:
            break
        if h not in keep:
            keep.append(h)
    ks = set(keep)
    now = frame[frame["window"] == window].set_index("host")
    nodes = []
    for h in keep:
        r = float(risk.get(h, 0.0))
        role = roles.get(h, {}).get("role", "normal")
        if h in mitigated:
            role = "mitigated"
        sp = stage_p.get(h)
        stg = map_stage(r, sp, threshold) if sp is not None else 0
        nodes.append({"id": h, "risk": round(r, 4), "stage": int(stg), "role": role,
                      "alerting": bool(r >= threshold),
                      "flows_now": int(now["out_flows"].get(h, 0) + now["in_flows"].get(h, 0)) if h in now.index else 0,
                      "flows_total": int(vol.get(h, 0))})
    e = edges[(edges["window"] <= window) & edges["a"].isin(ks) & edges["b"].isin(ks)] if edges is not None \
        and len(edges) else pd.DataFrame(columns=["a", "b", "window", "flows"])
    und = e.assign(u=np.where(e["a"] < e["b"], e["a"], e["b"]), v=np.where(e["a"] < e["b"], e["b"], e["a"]))
    tot = und.groupby(["u", "v"])["flows"].sum()
    act = und[und["window"] > window - LOOKBACK].groupby(["u", "v"])["flows"].sum()
    atk_pairs = {(a, v) for a, info in roles.items() if not a.startswith("_") and info.get("role") == "attacker"
                 for v in info.get("victims", [])}
    edges_out = []
    for (u, v), n in tot.items():
        a_now = int(act.get((u, v), 0))
        hot = a_now > 0 and ((u, v) in atk_pairs or (v, u) in atk_pairs)
        cut = hot and (u in mitigated or v in mitigated)
        edges_out.append({"a": u, "b": v, "flows": int(n), "active": a_now, "hot": bool(hot and not cut)})
    return {"nodes": nodes, "edges": edges_out, "window": int(window)}
