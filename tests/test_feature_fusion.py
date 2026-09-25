"""R6: CSV, PCAP and live inputs resolve to the identical feature schema."""
from pathlib import Path

import numpy as np
import pandas as pd

from src.features import schema as S
from src.features.fusion import from_csv, from_live_window, from_pcap, windowize
from src.features.packet_features import pcap_to_flows

FIX = Path(__file__).parent / "fixtures"


def _cic_csv(tmp_path: Path) -> Path:
    head = (" Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, Flow Duration,"
            " Total Fwd Packets, Total Backward Packets,Total Length of Fwd Packets, Total Length of Bwd Packets,"
            " FIN Flag Count, SYN Flag Count, RST Flag Count,Init_Win_bytes_forward, Label")
    rows = []
    for i in range(60):
        m = 30 + i // 10
        rows.append(f"192.168.10.5,{40000 + i},192.168.10.50,{20 + i % 7},6,5/7/2017 9:{m:02d},"
                    f"{1000 * (i + 1)},3,2,120,80,0,1,0,8192,{'PortScan' if i > 40 else 'BENIGN'}")
    p = tmp_path / "cic.csv"
    p.write_text(head + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
    return p


def test_csv_and_pcap_share_schema(tmp_path):
    fm_csv = from_csv(_cic_csv(tmp_path), min_flows=1)
    fm_pcap = from_pcap(FIX / "http.pcap", min_flows=1)
    cols = S.INDEX_COLUMNS + S.FEATURE_COLUMNS
    assert fm_csv.frame.columns.tolist()[: len(cols)] == cols
    assert fm_pcap.frame.columns.tolist()[: len(cols)] == cols
    assert fm_csv.values().shape[1] == fm_pcap.values().shape[1] == S.N_FEATURES


def test_live_path_matches_pcap_path():
    flows = pcap_to_flows(FIX / "http.pcap")
    a = from_pcap(FIX / "http.pcap", min_flows=1).frame
    b = from_live_window(flows, min_flows=1).frame
    pd.testing.assert_frame_equal(a[S.FEATURE_COLUMNS].reset_index(drop=True),
                                  b[S.FEATURE_COLUMNS].reset_index(drop=True))


def test_packet_features_masked_for_csv(tmp_path):
    fm = from_csv(_cic_csv(tmp_path), min_flows=1)
    assert (fm.frame["ttl_mean_mask"] == 0).all()          # flow CSVs carry no TTL
    fm2 = from_pcap(FIX / "http.pcap", min_flows=1)
    assert (fm2.frame["ttl_mean_mask"] == 1).any()


def test_flows_assigned_by_end_time_and_labels(tmp_path):
    fm = from_csv(_cic_csv(tmp_path), min_flows=1)
    assert fm.labelled
    assert set(fm.frame["stage"].unique()) <= {0, 1}
    assert fm.frame.loc[fm.frame["host"] == "192.168.10.5", "stage"].max() == 1    # scanner labelled


def test_windowize_densifies_idle_windows():
    t = 1_000_000.0
    flows = pd.DataFrame({
        "ts_start": [t, t + 300], "ts_end": [t + 1, t + 301], "src_ip": ["10.0.0.1"] * 2,
        "dst_ip": ["10.0.0.2"] * 2, "sport": [1, 2], "dport": [80, 80], "proto": ["tcp"] * 2,
        "fwd_pkts": [3, 3], "bwd_pkts": [2, 2], "fwd_bytes": [100, 100], "bwd_bytes": [50, 50],
        "syn": [1, 1], "rst": [0, 0], "fin": [1, 1], "ttl": [np.nan] * 2, "tcp_win": [np.nan] * 2,
        "retrans": [np.nan] * 2, "label": ["", ""]})
    fm = windowize(flows, min_flows=1)
    h = fm.host_frame("10.0.0.1")
    assert len(h) == 6 and h["out_flows"].sum() == 2
