"""Phase 11 / R4 targeted retraining: turn YOUR lab captures into a labelled dataset.

Inputs (under data/raw/lab/):
  *.pcap / *.pcapng        captures recorded on the sensor (tcpdump / the live sensor)
  schedule.jsonl           one JSON object per attack stage, written by
                           demo/attack_scripts/run_sequence.sh:
                           {"label": "PortScan", "attacker": "192.168.0.227",
                            "targets": ["192.168.0.101"], "start": 1790000000.0, "end": 1790000300.0}

A flow is labelled with the stage's attack label when it was initiated by the
attacker towards one of the targets (any target if none listed) and ends inside
[start, end + grace]. Everything else is BENIGN. The labelled flows then go
through the SAME fusion.windowize as every other dataset (R6), producing
data/processed/lab.windows.parquet / lab.edges.parquet, which train_world_model
picks up when "lab" is listed in data.train_datasets.

    python -m src.training.lab_dataset            # build
    python -m src.training.lab_dataset --stats    # just show what the schedule labels
"""
from __future__ import annotations

import argparse
import json

import pandas as pd

from src.features.fusion import windowize
from src.features.packet_features import pcap_to_flows
from src.utils.config import PROCESSED, RAW, world_model_config

LAB = RAW / "lab"
GRACE_S = 30


def load_schedule() -> list[dict]:
    p = LAB / "schedule.jsonl"
    if not p.exists():
        raise FileNotFoundError(f"{p} not found - run demo/attack_scripts/run_sequence.sh with "
                                "NV_LAB_SCHEDULE pointing there while recording.")
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]


def label_flows(flows: pd.DataFrame, schedule: list[dict]) -> pd.DataFrame:
    flows = flows.copy()
    flows["label"] = "BENIGN"
    for s in schedule:
        m = (flows["src_ip"] == s["attacker"]) & (flows["ts_end"] >= s["start"]) & \
            (flows["ts_end"] <= s["end"] + GRACE_S)
        if s.get("targets"):
            m &= flows["dst_ip"].isin(s["targets"])
        flows.loc[m, "label"] = s["label"]
    return flows


def build() -> dict:
    caps = sorted(list(LAB.glob("*.pcap")) + list(LAB.glob("*.pcapng")))
    if not caps:
        raise FileNotFoundError(f"No captures in {LAB}")
    schedule = load_schedule()
    w = world_model_config()["windowing"]
    frames, edges, stats = [], [], []
    for cap in caps:
        flows = label_flows(pcap_to_flows(cap), schedule)
        fm = windowize(flows, window_s=w["window_s"], min_flows=5, max_hosts=w["max_hosts"], source="lab")
        df = fm.frame
        df.insert(0, "capture", cap.stem)
        df.insert(0, "dataset", "lab")
        frames.append(df)
        edges.append(fm.edges.assign(dataset="lab", capture=cap.stem))
        stats.append({"capture": cap.name, "flows": len(flows),
                      "labels": flows["label"].value_counts().to_dict(),
                      "hosts": int(df["host"].nunique()), "attack_windows": int((df["stage"] > 0).sum())})
    PROCESSED.mkdir(parents=True, exist_ok=True)
    pd.concat(frames, ignore_index=True).to_parquet(PROCESSED / "lab.windows.parquet", index=False)
    pd.concat(edges, ignore_index=True).to_parquet(PROCESSED / "lab.edges.parquet", index=False)
    out = {"dataset": "lab", "captures": stats, "schedule_entries": len(schedule)}
    (PROCESSED / "lab.stats.json").write_text(json.dumps(out, indent=2, default=str))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stats", action="store_true")
    a = ap.parse_args()
    if a.stats:
        sch = load_schedule()
        for s in sch:
            print(f"{s['label']:<14} {s['attacker']} -> {','.join(s.get('targets') or ['*'])} "
                  f"{s['end'] - s['start']:.0f}s")
        return
    print(json.dumps(build(), indent=2, default=str))


if __name__ == "__main__":
    main()
