"""Assemble ONE big multi-attack demo scenario from REAL captures (rules R1/R2: no synthetic
feature rows). Several real attacks are placed on distinct attacker/victim IPs and overlapping
times so the dashboard shows a whole campaign at once - mitigate one attack on camera and the
others keep running.

What is real and what is only re-indexed:
  * Every flow's FEATURES (packets, bytes, ports, flags, timing) are copied verbatim from a real
    capture. Nothing is fabricated or scaled.
  * Only the row INDEX is changed: attacker/victim IPs are relabelled and timestamps are shifted
    onto one shared timeline. IPs and absolute time are NOT model inputs (src/features/schema.py
    indexes rows by them), so the model sees exactly the real traffic; the re-indexing just lets
    several independent real attacks share one replay, exactly like demo/make_samples.py slices.

    python -m demo.make_demo_scenario

Writes:
  demo/samples/netraverse_campaign.csv        (canonical FLOW_COLUMNS - load_flows auto-detects it)
  demo/fallback_pcap/netraverse_campaign.pcap  (real lab packets, time-shifted, multi-attacker)
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

from src.features.flow_features import load_flows
from src.features.packet_features import pcap_to_flows
from src.features.schema import FLOW_COLUMNS
from src.mitre.mitre_lookup import label_to_stage
from src.training.lab_dataset import label_flows
from src.utils.config import RAW, ROOT

OUT_CSV = ROOT / "demo" / "samples" / "netraverse_campaign.csv"
OUT_PCAP = ROOT / "demo" / "fallback_pcap" / "netraverse_campaign.pcap"
SAMPLES = ROOT / "demo" / "samples"

# Each real attack becomes one campaign on its own attacker/victim, staggered so they overlap.
# start_min = when this attack's first malicious flow lands on the shared 0-min timeline.
def _lab_flows(dirname: str) -> pd.DataFrame:
    """Own-device recon -> SSH brute, labelled from the capture's schedule (real aggressive recon
    the model fires on, so it is the early-warning precursor for every composed kill-chain)."""
    d = RAW / dirname
    sched = [json.loads(l) for l in (d / "schedule.jsonl").read_text().splitlines() if l.strip()]
    caps = sorted(d.glob("session*.pcap")) or sorted(d.glob("*.pcap"))   # the attack capture, not benign baseline
    return label_flows(pcap_to_flows(caps[0]), sched, clock_offset=4.3)


def _cic(name: str) -> pd.DataFrame:
    return load_flows(SAMPLES / name)[0]


def _dominant_pair(f: pd.DataFrame, mask) -> tuple[str, str]:
    atk = f[mask]
    src = atk["src_ip"].value_counts().idxmax()
    dst = atk[atk["src_ip"] == src]["dst_ip"].value_counts().idxmax()
    return src, dst


def _slice(flows: pd.DataFrame, mask, attacker: str, victim: str, start_min: float,
           lead_in_min: float, span_min: float) -> pd.DataFrame:
    """Cut the flows around ``mask`` (the attack), rebase so the first masked flow lands at
    ``start_min``, and relabel the dominant attacker/victim to demo IPs. Real rows only."""
    f = flows.copy()
    src, dst = _dominant_pair(f, mask)
    keep = f[(f["src_ip"].isin([src, dst])) | (f["dst_ip"].isin([src, dst]))].copy()
    t_atk = f[mask]["ts_start"].min()
    keep = keep[(keep["ts_start"] >= t_atk - lead_in_min * 60) & (keep["ts_start"] <= t_atk + span_min * 60)]
    shift = start_min * 60 - t_atk
    keep["ts_start"] += shift
    keep["ts_end"] += shift
    keep["src_ip"] = keep["src_ip"].replace({src: attacker, dst: victim})
    keep["dst_ip"] = keep["dst_ip"].replace({src: attacker, dst: victim})
    return keep[list(FLOW_COLUMNS)]


def _stage(f: pd.DataFrame):
    return f["label"].map(label_to_stage)


def _kill_chain(recon: pd.DataFrame, comp: pd.DataFrame, comp_mask, attacker: str, victim: str,
                start_min: float, recon_min: float = 5.0, gap_min: float = 2.0) -> pd.DataFrame:
    """Compose a real recon precursor + a real (different) compromise onto one victim so the model
    forecasts the break-in DURING the scan. Both halves are real traffic; only IPs/time are set."""
    r = _slice(recon, _stage(recon) == 1, attacker, victim, start_min, lead_in_min=0.5, span_min=recon_min)
    c = _slice(comp, comp_mask, attacker, victim, start_min + recon_min + gap_min, lead_in_min=0.5, span_min=12)
    return pd.concat([r, c], ignore_index=True)


def _make_pcap() -> None:
    """Real lab packets, replayed as TWO concurrent attackers so a block on one still leaves the
    other running. Packet payloads/sizes/flags are untouched; only src/dst IP (row index) and the
    timestamp are changed, then checksums are recomputed on write."""
    import scapy.layers.inet  # noqa: F401
    import scapy.layers.l2  # noqa: F401
    from scapy.utils import PcapReader, wrpcap

    src = sorted((RAW / "lab_test").glob("session*.pcap")) or sorted((RAW / "lab_test").glob("*.pcap"))
    if not src:
        print("  ! no lab pcap for the demo capture, skipping"); return
    with PcapReader(str(src[0])) as rd:
        pkts = [p for i, p in enumerate(rd) if i < 20000]
    t0 = min(float(p.time) for p in pkts)       # packets are not strictly time-ordered on the wire
    # attacker A = real .227->.201 relabelled; attacker B = the same real packets, a second IP,
    # shifted +90 s so the two campaigns overlap on the victim.
    def rewrite(remap: dict, extra_shift: float):
        res = []
        for p in pkts:                                   # pkts stays pristine; work on copies
            q = p.copy()
            if q.haslayer("IP"):
                ip = q["IP"]
                ip.src = remap.get(ip.src, ip.src); ip.dst = remap.get(ip.dst, ip.dst)
                del ip.chksum, ip.len
                if q.haslayer("TCP"):
                    del q["TCP"].chksum
            q.time = float(p.time) - t0 + 1_700_000_000 + extra_shift
            res.append(q)
        return res

    out = rewrite({"192.168.0.227": "10.13.37.5", "192.168.0.201": "10.20.0.11"}, 0)
    out += rewrite({"192.168.0.227": "10.13.37.6", "192.168.0.201": "10.20.0.12"}, 90)
    out.sort(key=lambda p: float(p.time))
    OUT_PCAP.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(OUT_PCAP), out)
    dur = (float(out[-1].time) - float(out[0].time)) / 60
    print(f"\nPCAP -> {OUT_PCAP}  ({len(out):,} packets, 2 attackers, {dur:.0f} min)")


def main() -> None:
    base = 1_700_000_000.0                      # arbitrary shared epoch origin for the demo timeline
    lab4 = _lab_flows("lab_test")               # real recon -> SSH brute (session4)
    lab5 = _lab_flows("lab")                    # real recon -> SSH brute (session5, 4 cycles)
    ftp = _cic("cic2017_bruteforce_tuesday.csv")
    dos = _cic("cic2017_dos_wednesday.csv")

    # Each campaign has a recon precursor so the model forecasts the compromise DURING the scan.
    # 1-2 are native lab kill-chains; 3-4 compose real lab recon + a real (different) CIC compromise.
    episodes = [
        ("recon->SSH brute (lab-4)", _slice(lab4, _stage(lab4) >= 1, "10.13.37.5", "10.20.0.11",
                                            start_min=10, lead_in_min=1, span_min=16)),
        ("recon->SSH brute (lab-5)", _slice(lab5, _stage(lab5) >= 1, "10.13.37.6", "10.20.0.12",
                                            start_min=9, lead_in_min=1, span_min=16)),
        ("recon->FTP brute (chain)", _kill_chain(lab4, ftp, ftp["label"].str.contains("Patator"),
                                                 "10.13.37.7", "10.20.0.13", start_min=12)),
        ("recon->DoS (chain)", _kill_chain(lab5, dos, dos["label"].str.contains("DoS"),
                                           "10.13.37.8", "10.20.0.14", start_min=14)),
    ]

    parts = []
    for name, ep in episodes:
        if ep.empty:
            print(f"  ! {name}: no attack flows found, skipped")
            continue
        ep = ep.copy()
        ep["ts_start"] += base
        ep["ts_end"] += base
        parts.append(ep)
        stg = ep["label"].map(label_to_stage)
        print(f"  {name:26s} flows={len(ep):6d}  recon={int((stg == 1).sum()):4d}  "
              f"compromise={int((stg >= 2).sum()):5d}")

    df = pd.concat(parts, ignore_index=True).sort_values("ts_end").reset_index(drop=True)
    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    df[list(FLOW_COLUMNS)].to_csv(OUT_CSV, index=False)
    dur = (df["ts_end"].max() - df["ts_start"].min()) / 60
    print(f"\nCSV -> {OUT_CSV}  ({len(df):,} flows, {df['src_ip'].nunique()} hosts, {dur:.0f} min)")
    _make_pcap()


if __name__ == "__main__":
    main()
