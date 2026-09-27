"""Held-out early-warning check: does the model forecast the compromise DURING reconnaissance?

Runs the trained model over a lab capture the model never trained on (data/raw/lab_test/),
and for the victim/attacker host reports, per 60 s window, the forecast compromise-risk and
the first alert relative to the first actual brute-force (compromise) window -> lead time.

    python -m src.training.eval_leadtime --ckpt models/world_model_lab.pt --host 192.168.0.201
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from src.api.service import Engine, Service
from src.features.fusion import windowize
from src.features.packet_features import pcap_to_flows
from src.training.lab_dataset import label_flows
from src.utils.config import RAW


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ckpt", default="models/world_model_lab.pt")
    ap.add_argument("--dir", default=str(RAW / "lab_test"))
    ap.add_argument("--host", default="192.168.0.201")
    ap.add_argument("--clock-offset", type=float, default=4.3)
    a = ap.parse_args()

    d = Path(a.dir)
    sched = [json.loads(l) for l in (d / "schedule.jsonl").read_text().splitlines() if l.strip()]
    caps = sorted(list(d.glob("*.pcap")) + list(d.glob("*.pcapng")))
    flows = label_flows(pcap_to_flows(caps[0]), sched, a.clock_offset)
    fm = windowize(flows, window_s=60, min_flows=5, max_hosts=150, source="lab_test")

    svc = Service(Engine(ckpt=a.ckpt))
    thr = svc.E.threshold
    a_ = svc.analyze(fm, filename="lab_test")
    if a.host not in {h for h in fm.frame["host"].unique()}:
        hosts = fm.frame.groupby("host").size().sort_values(ascending=False)
        print("host not found; busiest hosts:", hosts.head(5).to_dict())
        return
    tl = svc.timeline(a_, a.host)
    stage = tl["truth_stage"]                       # labelled stage per window (0 benign,1 recon,2 brute)
    risk = tl["risk"]                                # forecast P(compromise within 300 s)
    ws = tl["window_s"]

    print(f"host {a.host} | threshold {thr:.3f} | window {ws}s")
    print("win  truth        forecast_risk  alert")
    for i, (s, r) in enumerate(zip(stage, risk)):
        name = {0: "benign", 1: "RECON", 2: "BRUTE", 3: "lateral"}.get(int(s), str(s))
        print(f"{i:3d}  {name:11s}  {r:6.1%}        {'<<< ALERT' if r >= thr else ''}")

    stage = np.array(stage); risk = np.array(risk)
    first_brute = next((i for i, s in enumerate(stage) if s == 2), None)
    first_alert = next((i for i, r in enumerate(risk) if r >= thr), None)
    print("\n=== lead time ===")
    if first_brute is None:
        print("no brute-force (compromise) window labelled in this capture.")
    elif first_alert is None:
        print(f"first compromise at window {first_brute}; model never alerted.")
    else:
        lead = (first_brute - first_alert) * ws
        recon_at_alert = stage[first_alert] == 1
        print(f"first alert:      window {first_alert}  (labelled: "
              f"{'RECON' if recon_at_alert else int(stage[first_alert])})")
        print(f"first compromise: window {first_brute}  (BRUTE)")
        print(f"LEAD TIME: {lead:+d} s  -> " +
              ("forecast DURING reconnaissance, before the compromise" if lead > 0 and recon_at_alert
               else "detected at/after compromise onset" if lead <= 0 else "alerted early"))


if __name__ == "__main__":
    main()
