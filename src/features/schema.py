"""Canonical schemas shared by every ingestion path (rules.md R6).

Two layers:

1. ``FLOW_COLUMNS`` - one row per bidirectional flow. CSV loaders, the Scapy PCAP
   assembler and the live sniffer all emit exactly this table.
2. ``FEATURE_COLUMNS`` - one row per (host, 60 s window). Built from the flow
   table by ``fusion.windowize`` and the only thing the model ever sees.

Nothing identity-like (IP, port number as identity, timestamp, capture id) is a
model input; those only index the rows.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd

WINDOW_S = 60          # one world-model step = 60 s of traffic
HISTORY_L = 10         # windows of history the encoder filters over (10 min)
HORIZON_K = 5          # rollout steps -> 5 x 60 s = 300 s forecast horizon (FR8)

# ---------------------------------------------------------------- flow layer
FLOW_COLUMNS: dict[str, str] = {
    "ts_start": "float64",   # epoch seconds
    "ts_end": "float64",     # epoch seconds; a flow belongs to the window containing its END
    "src_ip": "str",
    "dst_ip": "str",
    "sport": "int64",
    "dport": "int64",
    "proto": "str",          # tcp | udp | icmp | other
    "fwd_pkts": "float64",
    "bwd_pkts": "float64",
    "fwd_bytes": "float64",
    "bwd_bytes": "float64",
    "syn": "int8",           # SYN seen
    "rst": "int8",           # RST seen
    "fin": "int8",           # FIN seen
    # packet-level (PCAP/live exact; some datasets partial; NaN = not observed)
    "ttl": "float64",
    "tcp_win": "float64",
    "retrans": "float64",
    "label": "str",          # raw dataset label ("" when unlabelled)
}

# ---------------------------------------------------------------- window layer
# Counts are log1p-transformed before scaling (see fusion.windowize).
OUT_FEATURES = [
    "out_flows", "out_pkts", "out_bytes",
    "out_distinct_dst", "out_distinct_dport", "out_dport_entropy",
    "out_new_peers", "out_failed_ratio", "out_small_flow_ratio", "out_syn_ratio",
    "out_mean_dur", "out_mean_pkt_size", "out_bwd_fwd_ratio",
    "out_tcp_frac", "out_udp_frac", "out_icmp_frac", "out_wellknown_port_frac",
]
IN_FEATURES = [
    "in_flows", "in_pkts", "in_bytes",
    "in_distinct_src", "in_distinct_dport", "in_failed_ratio", "in_small_flow_ratio",
    "in_syn_ratio",
]
PACKET_FEATURES = ["ttl_mean", "tcp_win_mean", "retrans_rate"]
MASK_FEATURES = [f"{c}_mask" for c in PACKET_FEATURES]

FEATURE_COLUMNS: list[str] = OUT_FEATURES + IN_FEATURES + PACKET_FEATURES + MASK_FEATURES
N_FEATURES = len(FEATURE_COLUMNS)

# columns that get log1p before standardisation (heavy-tailed counts)
LOG_FEATURES = {
    "out_flows", "out_pkts", "out_bytes", "out_distinct_dst", "out_distinct_dport",
    "out_new_peers", "out_mean_dur", "out_mean_pkt_size", "out_bwd_fwd_ratio",
    "in_flows", "in_pkts", "in_bytes", "in_distinct_src", "in_distinct_dport",
    "ttl_mean", "tcp_win_mean",
}

# human-readable names for explanations (R5 / FR12)
FEATURE_LABELS: dict[str, str] = {
    "out_flows": "outbound connections", "out_pkts": "outbound packets", "out_bytes": "outbound bytes",
    "out_distinct_dst": "distinct destinations contacted (fan-out)",
    "out_distinct_dport": "distinct destination ports probed",
    "out_dport_entropy": "destination-port entropy",
    "out_new_peers": "never-before-seen peers",
    "out_failed_ratio": "share of failed/unanswered outbound connections",
    "out_small_flow_ratio": "share of tiny (<=3 packet) outbound flows",
    "out_syn_ratio": "share of outbound flows with SYN",
    "out_mean_dur": "mean outbound flow duration",
    "out_mean_pkt_size": "mean outbound packet size",
    "out_bwd_fwd_ratio": "response/request byte ratio",
    "out_tcp_frac": "TCP share of outbound flows", "out_udp_frac": "UDP share of outbound flows",
    "out_icmp_frac": "ICMP share of outbound flows",
    "out_wellknown_port_frac": "share of flows to well-known service ports",
    "in_flows": "inbound connections", "in_pkts": "inbound packets", "in_bytes": "inbound bytes",
    "in_distinct_src": "distinct inbound sources",
    "in_distinct_dport": "distinct local ports targeted",
    "in_failed_ratio": "share of failed inbound connections",
    "in_small_flow_ratio": "share of tiny inbound flows",
    "in_syn_ratio": "share of inbound flows with SYN",
    "ttl_mean": "mean packet TTL", "tcp_win_mean": "mean TCP window size",
    "retrans_rate": "retransmission rate",
    "ttl_mean_mask": "TTL observed", "tcp_win_mean_mask": "TCP window observed",
    "retrans_rate_mask": "retransmissions observed",
}

INDEX_COLUMNS = ["host", "segment", "window", "t"]          # t = window start epoch s
LABEL_COLUMNS = ["label", "stage", "attack_out"]           # attack_out: host initiated attack flows


@dataclass
class FeatureMatrix:
    """Per-host windowed features - the single contract between ingestion and model.

    ``frame`` holds INDEX_COLUMNS + FEATURE_COLUMNS (+ LABEL_COLUMNS when the
    source carried labels) + neighbour aggregates for the GNN layer.
    ``flows`` keeps the canonical flow table so counterfactual interventions can
    be replayed exactly and the topology can be drawn.
    """

    frame: pd.DataFrame
    flows: pd.DataFrame | None = None
    edges: pd.DataFrame | None = None       # (a, b, window, flows) host-graph edges per window
    labelled: bool = False
    source: str = "unknown"
    meta: dict = field(default_factory=dict)

    @property
    def hosts(self) -> list[str]:
        return sorted(self.frame["host"].unique().tolist())

    def host_frame(self, host: str) -> pd.DataFrame:
        return self.frame[self.frame["host"] == host].sort_values("window")

    def values(self, df: pd.DataFrame | None = None) -> np.ndarray:
        df = self.frame if df is None else df
        return df[FEATURE_COLUMNS].to_numpy(np.float32)
