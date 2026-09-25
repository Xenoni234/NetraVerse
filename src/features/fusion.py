"""Feature Fusion Layer - the single place CSV, PCAP and live traffic become model input.

    from_csv(path)            -> FeatureMatrix
    from_pcap(path)           -> FeatureMatrix
    from_live_window(flows)   -> FeatureMatrix

All three produce a canonical flow table (``schema.FLOW_COLUMNS``) and then go
through the same ``windowize`` -> identical columns, ordering and semantics (R6).
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import polars as pl

from src.features import schema as S
from src.features.flow_features import load_flows
from src.mitre.mitre_lookup import label_to_stage

SEGMENT_GAP_WINDOWS = 10
TARGETED_STAGES = (1, 2, 3, 6)   # recon, initial access, lateral movement, impact: dst is the victim   # >10 idle minutes network-wide starts a new capture segment


# ---------------------------------------------------------------- entity selection
def select_hosts(flows: pd.DataFrame, min_flows: int = 20, max_hosts: int | None = 200,
                 hosts: list[str] | None = None) -> list[str]:
    """Hosts that get a timeline. Label-agnostic: purely by traffic activity."""
    if hosts is not None:
        return list(hosts)
    counts = pd.concat([flows["src_ip"], flows["dst_ip"]]).value_counts()
    counts = counts[counts >= min_flows]
    if max_hosts:
        counts = counts.head(max_hosts)
    return counts.index.tolist()


def _entropy_expr() -> pl.Expr:
    p = pl.col("n") / pl.col("n").sum()
    return (-(p * p.log(2))).sum()


# ---------------------------------------------------------------- core windowing
def windowize(flows: pd.DataFrame, window_s: int = S.WINDOW_S, hosts: list[str] | None = None,
              min_flows: int = 20, max_hosts: int | None = 200, t0: float | None = None,
              densify: bool = True, source: str = "unknown") -> S.FeatureMatrix:
    """Canonical flows -> per-host windowed FeatureMatrix (+ labels if present)."""
    if flows is None or len(flows) == 0:
        raise ValueError("No flows to window.")
    labelled = bool((flows["label"].astype(str).str.len() > 0).any())
    ents = select_hosts(flows, min_flows=min_flows, max_hosts=max_hosts, hosts=hosts)
    if not ents:
        raise ValueError("No host has enough traffic to build a timeline "
                         f"(need >= {min_flows} flows).")
    if t0 is None:
        t0 = float(np.floor(flows["ts_end"].min() / window_s) * window_s)

    stage_of = {lab: label_to_stage(lab) for lab in flows["label"].unique()} if labelled else {}
    f = pl.from_pandas(flows).with_columns(
        ((pl.col("ts_end") - t0) // window_s).cast(pl.Int64).alias("window"),
        (pl.col("fwd_pkts") + pl.col("bwd_pkts")).alias("pkts"),
        (pl.col("fwd_bytes") + pl.col("bwd_bytes")).alias("bytes"),
        (pl.col("ts_end") - pl.col("ts_start")).alias("dur"),
        ((pl.col("bwd_pkts") <= 0) | (pl.col("rst") > 0)).cast(pl.Float64).alias("failed"),
        ((pl.col("fwd_pkts") + pl.col("bwd_pkts")) <= 3).cast(pl.Float64).alias("small"),
        pl.col("label").replace_strict(stage_of, default=0, return_dtype=pl.Int64).alias("stage")
        if labelled else pl.lit(0, dtype=pl.Int64).alias("stage"),
    )
    ent_s = pl.Series("h", ents)
    out = f.filter(pl.col("src_ip").is_in(ent_s.implode())).rename({"src_ip": "host"})
    inn = f.filter(pl.col("dst_ip").is_in(ent_s.implode())).rename({"dst_ip": "host"})

    # ---- outbound behaviour
    first_seen = out.group_by(["host", "dst_ip"]).agg(pl.col("window").min().alias("first_w"))
    new_peers = (first_seen.group_by(["host", "first_w"]).len()
                 .rename({"first_w": "window", "len": "out_new_peers"}))
    ent = (out.group_by(["host", "window", "dport"]).len().rename({"len": "n"})
           .group_by(["host", "window"]).agg(_entropy_expr().alias("out_dport_entropy")))
    o = out.group_by(["host", "window"]).agg(
        pl.len().alias("out_flows"),
        pl.col("pkts").sum().alias("out_pkts"),
        pl.col("bytes").sum().alias("out_bytes"),
        pl.col("dst_ip").n_unique().alias("out_distinct_dst"),
        pl.col("dport").n_unique().alias("out_distinct_dport"),
        pl.col("failed").mean().alias("out_failed_ratio"),
        pl.col("small").mean().alias("out_small_flow_ratio"),
        pl.col("syn").cast(pl.Float64).mean().alias("out_syn_ratio"),
        pl.col("dur").mean().alias("out_mean_dur"),
        (pl.col("bytes").sum() / pl.col("pkts").sum().clip(lower_bound=1)).alias("out_mean_pkt_size"),
        (pl.col("bwd_bytes").sum() / (pl.col("fwd_bytes").sum() + 1)).alias("out_bwd_fwd_ratio"),
        (pl.col("proto") == "tcp").cast(pl.Float64).mean().alias("out_tcp_frac"),
        (pl.col("proto") == "udp").cast(pl.Float64).mean().alias("out_udp_frac"),
        (pl.col("proto") == "icmp").cast(pl.Float64).mean().alias("out_icmp_frac"),
        (pl.col("dport") < 1024).cast(pl.Float64).mean().alias("out_wellknown_port_frac"),
        (pl.col("stage") > 0).sum().alias("_atk_out"),
    )
    o = o.join(ent, on=["host", "window"], how="left").join(new_peers, on=["host", "window"], how="left")

    # ---- inbound exposure
    i = inn.group_by(["host", "window"]).agg(
        pl.len().alias("in_flows"),
        pl.col("pkts").sum().alias("in_pkts"),
        pl.col("bytes").sum().alias("in_bytes"),
        pl.col("src_ip").n_unique().alias("in_distinct_src"),
        pl.col("dport").n_unique().alias("in_distinct_dport"),
        pl.col("failed").mean().alias("in_failed_ratio"),
        pl.col("small").mean().alias("in_small_flow_ratio"),
        pl.col("syn").cast(pl.Float64).mean().alias("in_syn_ratio"),
        pl.col("stage").is_in(pl.Series(TARGETED_STAGES).implode()).sum().alias("_atk_in"),
    )

    # ---- packet-level (both directions; NaN-aware -> masks)
    both = pl.concat([out.select(["host", "window", "ttl", "tcp_win", "retrans", "fwd_pkts"]),
                      inn.select(["host", "window", "ttl", "tcp_win", "retrans", "fwd_pkts"])])
    both = both.with_columns([pl.col(c).fill_nan(None) for c in ("ttl", "tcp_win", "retrans")])
    pk = both.group_by(["host", "window"]).agg(
        pl.col("ttl").mean().alias("ttl_mean"),
        pl.col("tcp_win").mean().alias("tcp_win_mean"),
        (pl.col("retrans").sum() / pl.col("fwd_pkts").filter(pl.col("retrans").is_not_null())
         .sum().clip(lower_bound=1)).alias("retrans_rate"),
        pl.col("retrans").is_not_null().any().alias("_has_retrans"),
    )

    # ---- labels: dominant attack stage of flows touching the host
    lab_parts = []
    if labelled:
        atk = pl.concat([
            f.filter((pl.col("stage") > 0) & pl.col("src_ip").is_in(ent_s.implode())).select(
                pl.col("src_ip").alias("host"), "window", "stage", "label"),
            # destination side counts only where the destination IS the target; for C2 and
            # exfiltration the destination is attacker infrastructure (DNS, C2 server, drop site)
            f.filter((pl.col("stage").is_in(pl.Series(TARGETED_STAGES).implode())) & pl.col("dst_ip").is_in(ent_s.implode())).select(
                pl.col("dst_ip").alias("host"), "window", "stage", "label"),
        ])
        lab = (atk.group_by(["host", "window", "stage", "label"]).len()
               .sort("len", descending=True)
               .group_by(["host", "window"]).agg(pl.col("stage").first(), pl.col("label").first()))
        lab_parts.append(lab)

    keys = pl.concat([o.select(["host", "window"]), i.select(["host", "window"])]).unique()
    fr = (keys.join(o, on=["host", "window"], how="left")
          .join(i, on=["host", "window"], how="left")
          .join(pk, on=["host", "window"], how="left"))
    if lab_parts:
        fr = fr.join(lab_parts[0], on=["host", "window"], how="left")
    df = fr.to_pandas()

    # ---- segments (contiguous capture periods) + densify idle windows
    active_w = np.sort(f["window"].unique().to_numpy())
    seg_break = np.r_[True, np.diff(active_w) > SEGMENT_GAP_WINDOWS]
    seg_id = np.cumsum(seg_break) - 1
    seg_start = active_w[seg_break]
    seg_end = pd.Series(active_w).groupby(seg_id).max().to_numpy()
    df["segment"] = np.searchsorted(seg_start, df["window"].to_numpy(), side="right") - 1

    if densify:
        present = df[["host", "segment"]].drop_duplicates()
        grids = [pd.DataFrame({"host": h, "segment": s,
                               "window": np.arange(seg_start[s], seg_end[s] + 1)})
                 for h, s in present.itertuples(index=False)]
        grid = pd.concat(grids, ignore_index=True)
        df = grid.merge(df.drop(columns=["segment"]), on=["host", "window"], how="left")

    df["t"] = t0 + df["window"].astype(float) * window_s
    for c in S.PACKET_FEATURES:
        df[f"{c}_mask"] = df[c].notna().astype(np.float32)
    df["retrans_rate_mask"] = df.pop("_has_retrans").fillna(False).astype(np.float32) \
        if "_has_retrans" in df else df["retrans_rate_mask"]
    df[S.FEATURE_COLUMNS] = df[S.FEATURE_COLUMNS].astype(float).fillna(0.0)

    if labelled:
        df["stage"] = df["stage"].fillna(0).astype(int)
        df["label"] = df["label"].fillna("BENIGN")
        a_out, a_in = df["_atk_out"].fillna(0), df["_atk_in"].fillna(0)
        df["attack_out"] = ((df["stage"] > 0) & (a_out >= a_in) & (a_out > 0)).astype(int)
    df = df.drop(columns=[c for c in ("_atk_out", "_atk_in") if c in df.columns])
    cols = S.INDEX_COLUMNS + S.FEATURE_COLUMNS + (S.LABEL_COLUMNS if labelled else [])
    df = df[cols].sort_values(["host", "window"]).reset_index(drop=True)

    # ---- host-graph edges per window (entity <-> entity), for the GNN layer
    edges = (f.filter(pl.col("src_ip").is_in(ent_s.implode()) & pl.col("dst_ip").is_in(ent_s.implode())
                      & (pl.col("src_ip") != pl.col("dst_ip")))
             .group_by(["src_ip", "dst_ip", "window"]).len()
             .rename({"src_ip": "a", "dst_ip": "b", "len": "flows"}).to_pandas())

    return S.FeatureMatrix(frame=df, flows=flows, edges=edges, labelled=labelled, source=source,
                           meta={"t0": t0, "window_s": window_s, "hosts": ents,
                                 "n_flows": int(len(flows))})


# ---------------------------------------------------------------- public entry points
def from_csv(path: str | Path, **kw) -> S.FeatureMatrix:
    flows, fmt = load_flows(Path(path))
    fm = windowize(flows, source=f"csv:{fmt}", **kw)
    fm.meta["format"] = fmt
    return fm


def from_pcap(path: str | Path, **kw) -> S.FeatureMatrix:
    from src.features.packet_features import pcap_to_flows
    flows = pcap_to_flows(Path(path))
    if len(flows) == 0:
        raise ValueError("The capture contains no IP flows.")
    kw.setdefault("min_flows", 3)
    fm = windowize(flows, source="pcap", **kw)
    fm.meta["format"] = "pcap"
    return fm


def from_live_window(flows: pd.DataFrame, **kw) -> S.FeatureMatrix:
    """Flows assembled by the live sniffer over the buffered windows."""
    kw.setdefault("min_flows", 3)
    return windowize(flows, source="live", **kw)


def from_file(path: str | Path, **kw) -> S.FeatureMatrix:
    p = Path(path)
    if p.suffix.lower() in (".pcap", ".pcapng", ".cap"):
        return from_pcap(p, **kw)
    return from_csv(p, **kw)
