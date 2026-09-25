"""Lab labelling: schedule windows -> labelled flows -> same windowize as every dataset."""
from pathlib import Path

from src.features.packet_features import pcap_to_flows
from src.features.fusion import windowize
from src.training.lab_dataset import label_flows

FIX = Path(__file__).parent / "fixtures" / "http.pcap"


def test_schedule_labels_only_attacker_flows_in_window():
    flows = pcap_to_flows(FIX)
    t0, t1 = flows["ts_end"].min() - 1, flows["ts_end"].max() + 1
    sched = [{"label": "PortScan", "attacker": "145.254.160.237", "targets": ["216.239.59.99"],
              "start": t0, "end": t1}]
    out = label_flows(flows, sched)
    hit = out[out["label"] == "PortScan"]
    assert len(hit) > 0
    assert (hit["src_ip"] == "145.254.160.237").all() and (hit["dst_ip"] == "216.239.59.99").all()
    assert (out.loc[out["dst_ip"] != "216.239.59.99", "label"] == "BENIGN").all()
    fm = windowize(out, min_flows=1)
    assert fm.labelled and fm.frame["stage"].max() == 1          # PortScan -> RECONNAISSANCE
