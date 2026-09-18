"""Build mixed, labelled attack-forecasting demo uploads.

Each output contains all supported CIC-IDS2017 attack families in separate
episodes on one synthetic demo host. Every episode begins with a labelled
BENIGN precursor whose traffic features ramp toward the attack signature, then
transitions to the source dataset's real attack label. This is deliberately a
forecasting fixture, not a claim that the precursor is ground-truth malicious.

Run:
    .venv/Scripts/python.exe scripts/build_mixed_labelled_demo_datasets.py
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data/raw/CIC-IDS2017/TrafficLabelling"
OUT = ROOT / "demo/mixed_labelled"
ROWS = 220_000
# Keep each labelled attack episode aligned with the model's temporal training
# distribution: 960 rows at 250 ms is four minutes of sustained attack after a
# 120-second benign precursor.  The file is still padded to 220k rows with
# benign context so uploads remain large, but attacks are not one 80-minute tail.
ATTACK_ROWS_PER_EPISODE = 960
# 250 ms row cadence => 480 rows is a 120-second observable ramp.
PRECURSOR_ROWS = 480
SEED = 90210

SOURCES = {
    "portscan": ("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", "portscan"),
    "ftp_patator": ("Tuesday-WorkingHours.pcap_ISCX.csv", "ftp-patator"),
    "ssh_patator": ("Tuesday-WorkingHours.pcap_ISCX.csv", "ssh-patator"),
    "bot": ("Friday-WorkingHours-Morning.pcap_ISCX.csv", "bot"),
    "ddos": ("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", "ddos"),
    "dos_hulk": ("Wednesday-workingHours.pcap_ISCX.csv", "dos hulk"),
    "infiltration": ("Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv", "infiltration"),
    "web_attack": ("Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv", "web attack"),
}

ORDERS = {
    "mixed_attack_suite_a_220k.csv": ["portscan", "ftp_patator", "ssh_patator", "bot", "ddos", "dos_hulk", "infiltration", "web_attack"],
    "mixed_attack_suite_b_220k.csv": ["web_attack", "bot", "portscan", "ssh_patator", "dos_hulk", "ftp_patator", "infiltration", "ddos"],
    "mixed_attack_suite_c_220k.csv": ["infiltration", "ddos", "ftp_patator", "portscan", "web_attack", "dos_hulk", "bot", "ssh_patator"],
}


def _label_col(columns: pd.Index) -> str:
    return next(c for c in columns if str(c).strip().lower() == "label")


def _load_pools() -> dict[str, tuple[pd.DataFrame, pd.DataFrame]]:
    pools = {}
    for key, (filename, keyword) in SOURCES.items():
        df = pd.read_csv(RAW / filename, encoding="latin-1", low_memory=False, on_bad_lines="skip")
        label = _label_col(df.columns)
        labels = df[label].astype("string").str.strip()
        attack = df.loc[labels.str.contains(keyword, case=False, na=False)].reset_index(drop=True)
        benign = df.loc[~labels.str.contains(keyword, case=False, na=False)].reset_index(drop=True)
        if attack.empty or len(benign) < 8_000:
            raise ValueError(f"Insufficient rows for {key}: attack={len(attack):,}, benign={len(benign):,}")
        pools[key] = (attack, benign)
        print(f"loaded {key}: attack={len(attack):,}, benign={len(benign):,}")
    return pools


def _rewrite_identity(frame: pd.DataFrame, label: str) -> pd.DataFrame:
    out = frame.copy()
    columns = {str(c).strip().lower(): c for c in out.columns}
    for key in ("source ip", "src ip", "src_ip"):
        if key in columns:
            out[columns[key]] = "10.250.0.10"
            break
    if label:
        out[_label_col(out.columns)] = label
    return out


def _make_precursor(attack: pd.DataFrame, label_col: str, rng: np.random.Generator) -> pd.DataFrame:
    precursor = attack.iloc[:PRECURSOR_ROWS].copy()
    n = len(precursor)
    # A gradual, lower-intensity version of the attack signature. The labels
    # remain BENIGN until the verified attack transition below.
    scale = np.linspace(0.35, 0.95, n, dtype=np.float64)
    excluded = {label_col, "Timestamp", " Flow ID", "Flow ID"}
    for col in precursor.columns:
        if col in excluded or any(token in str(col).lower() for token in ("ip", "port", "protocol")):
            continue
        numeric = pd.to_numeric(precursor[col], errors="coerce")
        if numeric.notna().mean() < 0.8:
            continue
        values = numeric.to_numpy(dtype=np.float64)
        values = np.nan_to_num(values, nan=0.0, posinf=0.0, neginf=0.0)
        values *= scale
        values += rng.normal(0.0, np.maximum(np.abs(values) * 0.01, 1e-6), size=n)
        precursor[col] = np.maximum(values, 0.0)
    precursor[label_col] = "BENIGN"
    return precursor


def build_suite(name: str, order: list[str], pools: dict[str, tuple[pd.DataFrame, pd.DataFrame]], seed: int) -> dict:
    rng = np.random.default_rng(seed)
    label_col = _label_col(next(iter(pools.values()))[0].columns)
    chunks: list[pd.DataFrame] = []
    metadata = []

    # Initial benign context, then each episode has a 120s precursor and a
    # four-minute labelled attack, with benign recovery context between stages.
    first_benign = pools[order[0]][1].iloc[:20_000].copy()
    chunks.append(_rewrite_identity(first_benign, "BENIGN"))
    for i, key in enumerate(order):
        attack, benign = pools[key]
        chosen = attack.iloc[np.arange(ATTACK_ROWS_PER_EPISODE) % len(attack)].copy()
        precursor = _make_precursor(chosen, label_col, rng)
        verified = chosen.iloc[PRECURSOR_ROWS:].copy()
        chunks.extend([_rewrite_identity(precursor, "BENIGN"), _rewrite_identity(verified, "")])
        metadata.append({"family": key, "precursor_rows": PRECURSOR_ROWS,
                         "labelled_attack_rows": len(verified)})
        if i < len(order) - 1:
            gap = pools[order[(i + 1) % len(order)]][1].iloc[:5_000].copy()
            chunks.append(_rewrite_identity(gap, "BENIGN"))
    out = pd.concat(chunks, ignore_index=True)
    if len(out) < ROWS:
        pool = pools[order[0]][1]
        tail = pool.iloc[np.arange(ROWS - len(out)) % len(pool)].copy()
        out = pd.concat([out, _rewrite_identity(tail, "BENIGN")], ignore_index=True)
    out = out.iloc[:ROWS].copy()
    start = pd.Timestamp("2026-09-18T00:00:00Z")
    jitter = rng.integers(0, 250, size=len(out), dtype=np.int64)
    offsets = np.maximum.accumulate(np.arange(len(out), dtype=np.int64) * 250 + jitter)
    timestamp_col = next((c for c in out.columns if str(c).strip().lower() == "timestamp"), None)
    if timestamp_col is None:
        timestamp_col = "Timestamp"
    out[timestamp_col] = (start + pd.to_timedelta(offsets, unit="ms")).strftime("%Y-%m-%d %H:%M:%S.%f")
    OUT.mkdir(parents=True, exist_ok=True)
    out.to_csv(OUT / name, index=False)
    labels = out[label_col].astype(str).str.strip()
    return {"file": name, "rows": len(out), "label_counts": labels.value_counts().head(20).to_dict(),
            "episodes": metadata, "attack_families": order}


def main() -> None:
    pools = _load_pools()
    manifest = {"kind": "mixed_labelled_attack_forecasting_demo", "rows_per_file": ROWS,
                "forecast_target": "90-120 seconds where the current checkpoint raises a sustained alert",
                "caveat": "Lead time is measured after upload; it is not guaranteed for every family by the existing checkpoint.",
                "datasets": [build_suite(name, order, pools, SEED + i) for i, (name, order) in enumerate(ORDERS.items())]}
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
