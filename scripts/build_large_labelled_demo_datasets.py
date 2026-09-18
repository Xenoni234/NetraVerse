"""Build large labelled CICFlowMeter-compatible demo uploads.

These files are deterministic demo/evaluation bundles assembled from the local
CIC-IDS2017 TrafficLabelling data. Each file contains a long BENIGN prefix,
one attack family, and a BENIGN suffix. Timestamps are rewritten into one
continuous UTC timeline so the upload path can build consecutive 30-second
windows and measure onset/lead time honestly.

Run from the model repository:
    .venv/Scripts/python.exe scripts/build_large_labelled_demo_datasets.py
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data/raw/CIC-IDS2017/TrafficLabelling"
OUT = ROOT / "demo/large_labelled"
ROWS = 220_000
# Keep a substantial benign run-up while accommodating the DDoS source file,
# whose attack rows occupy most of the available records.
PRE = 80_000
SEED = 20260918

SPECS = [
    ("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", "portscan", "portscan_recon_220k.csv"),
    ("Tuesday-WorkingHours.pcap_ISCX.csv", "ftp-patator", "ftp_patator_initial_access_220k.csv"),
    ("Tuesday-WorkingHours.pcap_ISCX.csv", "ssh-patator", "ssh_patator_initial_access_220k.csv"),
    ("Friday-WorkingHours-Morning.pcap_ISCX.csv", "bot", "botnet_c2_220k.csv"),
    ("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", "ddos", "ddos_impact_220k.csv"),
    ("Wednesday-workingHours.pcap_ISCX.csv", "dos hulk", "dos_hulk_impact_220k.csv"),
    ("Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv", "infiltration", "infiltration_lateral_220k.csv"),
    ("Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv", "web attack", "web_attack_initial_access_220k.csv"),
]


def _label_col(columns) -> str:
    return next(c for c in columns if str(c).strip().lower() == "label")


def build_one(source: Path, keyword: str, output: Path, seed: int) -> dict:
    df = pd.read_csv(source, encoding="latin-1", low_memory=False, on_bad_lines="skip")
    label = _label_col(df.columns)
    labels = df[label].astype("string").str.strip()
    attack = labels.str.contains(keyword, case=False, na=False)
    attack_rows = df.loc[attack].reset_index(drop=True)
    benign_rows = df.loc[~attack].reset_index(drop=True)
    if attack_rows.empty:
        raise ValueError(f"No rows matching {keyword!r} in {source.name}")
    if len(benign_rows) < PRE:
        raise ValueError(f"Only {len(benign_rows):,} benign rows available; need {PRE:,}")

    # Keep enough attack records to preserve the family signature, while making
    # every file the same manageable size. Rare attacks get all their records.
    attack_n = min(len(attack_rows), ROWS - PRE - 20_000)
    post_n = ROWS - PRE - attack_n
    rng = np.random.default_rng(seed)
    pre = benign_rows.iloc[:PRE].copy()
    if len(attack_rows) > attack_n:
        attack = attack_rows.iloc[:attack_n].copy()
    else:
        attack = attack_rows.copy()
    post_pool = benign_rows.iloc[PRE:].copy()
    if len(post_pool) < post_n:
        post_pool = benign_rows.copy()
    post = post_pool.iloc[:post_n].copy()
    out = pd.concat([pre, attack, post], ignore_index=True)

    # Give every row a unique, monotonic timestamp. This creates many complete
    # 30-second windows while preserving the exact label transition.
    start = pd.Timestamp("2026-09-18T00:00:00Z")
    jitter = rng.integers(0, 250, size=len(out), dtype=np.int64)
    offsets_ms = np.arange(len(out), dtype=np.int64) * 250 + jitter
    offsets_ms = np.maximum.accumulate(offsets_ms)
    ts = start + pd.to_timedelta(offsets_ms, unit="ms")
    out[label] = out[label].astype(str).str.strip()
    out["Timestamp"] = ts.strftime("%Y-%m-%d %H:%M:%S.%f")
    output.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(output, index=False)
    attack_start = PRE
    attack_end = PRE + attack_n
    return {
        "file": output.name,
        "rows": int(len(out)),
        "attack_rows": int(attack_n),
        "benign_rows": int(len(out) - attack_n),
        "attack_label": keyword,
        "attack_start_row": attack_start,
        "attack_end_row": attack_end,
        "start_time": ts[0].isoformat(),
        "attack_start_time": ts[attack_start].isoformat(),
        "attack_end_time": ts[attack_end - 1].isoformat(),
        "source": source.name,
    }


def main() -> None:
    results = []
    for i, (source, keyword, filename) in enumerate(SPECS):
        results.append(build_one(RAW / source, keyword, OUT / filename, SEED + i))
    manifest = {
        "kind": "labelled_demo_uploads",
        "rows_per_file": ROWS,
        "window_seconds": 30,
        "ground_truth": "CIC-IDS2017 Label column preserved; attack interval begins after the benign prefix",
        "warning": "Derived demo/evaluation files, not newly captured traffic. Use only for local testing.",
        "datasets": results,
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
