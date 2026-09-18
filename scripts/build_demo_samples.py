"""Build small, REAL demo capture CSVs for the live SIH demo.

Each output is a raw slice of a CIC-IDS2017 TrafficLabelling day file, preserving the
original CICFlowMeter columns so it ingests through the upload pipeline (`_detect_map`
-> "cicids2017"). Every slice keeps a benign lead-in and the labelled attack, so the
world model sees a benign precursor before the onset. Nothing is synthetic or fabricated.

Run (from repo root, in the venv):
    .venv/Scripts/python.exe scripts/build_demo_samples.py

Outputs land in demo/samples/ with a README describing each capture's attack type/stage.
Verify by uploading each file on the Simulate page; the README records real behaviour.
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data/raw/CIC-IDS2017/TrafficLabelling"
OUT = ROOT / "demo/samples"

# (day file, label keyword (case-insensitive), output name, attack type, ATT&CK stage)
SAMPLES = [
    ("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", "portscan", "portscan_recon.csv", "Port scan", "Reconnaissance"),
    ("Friday-WorkingHours-Morning.pcap_ISCX.csv", "bot", "botnet_c2.csv", "Botnet", "Command & Control"),
    ("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", "ddos", "ddos_impact.csv", "DDoS", "Impact"),
    ("Wednesday-workingHours.pcap_ISCX.csv", "dos hulk", "dos_hulk_impact.csv", "DoS Hulk", "Impact"),
    ("Tuesday-WorkingHours.pcap_ISCX.csv", "ftp-patator", "ftp_bruteforce_initial_access.csv", "FTP brute force", "Initial Access"),
    ("Tuesday-WorkingHours.pcap_ISCX.csv", "ssh-patator", "ssh_bruteforce_initial_access.csv", "SSH brute force", "Initial Access"),
    ("Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv", "infiltration", "infiltration_lateral.csv", "Infiltration", "Lateral Movement"),
    ("Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv", "web attack", "webattack_initial_access.csv", "Web attack", "Initial Access"),
]

LEAD_ROWS = 30000   # benign precursor rows before the first attack row
TAIL_ROWS = 6000    # rows after the last attack row
MAX_ROWS = 80000    # cap so the demo file stays small


def _label_col(cols) -> str:
    for c in cols:
        if c.strip().lower() == "label":
            return c
    raise KeyError("no Label column")


def build_one(src: Path, keyword: str, out: Path, attack: str, stage: str) -> dict:
    df = pd.read_csv(src, encoding="latin-1", low_memory=False)
    label = _label_col(df.columns)
    lab = df[label].astype(str).str.strip().str.lower()
    hit = lab.str.contains(keyword.lower(), na=False)
    n_attack = int(hit.sum())
    if n_attack == 0:
        return {"out": out.name, "status": "SKIP", "reason": f"no rows matching '{keyword}'", "attack": attack, "stage": stage}
    idx = df.index[hit]
    first, last = int(idx.min()), int(idx.max())
    lo = max(0, first - LEAD_ROWS)
    hi = min(len(df), last + TAIL_ROWS)
    sl = df.iloc[lo:hi]
    if len(sl) > MAX_ROWS:  # keep the benign lead + attack, trim the middle-benign tail
        sl = pd.concat([sl.iloc[: MAX_ROWS - TAIL_ROWS], sl.iloc[-TAIL_ROWS:]])
    OUT.mkdir(parents=True, exist_ok=True)
    sl.to_csv(out, index=False)
    return {"out": out.name, "status": "OK", "rows": int(len(sl)), "attack_rows": n_attack,
            "benign_lead_rows": first - lo, "attack": attack, "stage": stage,
            "size_mb": round(out.stat().st_size / 1e6, 1)}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    results = []
    for fname, keyword, outname, attack, stage in SAMPLES:
        src = RAW / fname
        if not src.exists():
            results.append({"out": outname, "status": "MISSING", "reason": str(src)})
            continue
        try:
            results.append(build_one(src, keyword, OUT / outname, attack, stage))
        except Exception as e:  # noqa: BLE001
            results.append({"out": outname, "status": "ERROR", "reason": str(e)})

    # README
    lines = ["# Demo capture samples (real CIC-IDS2017 slices)\n",
             "Upload any of these on the Simulate page. Each is a raw slice of a CIC-IDS2017",
             "TrafficLabelling day (original CICFlowMeter columns), keeping a benign lead-in",
             "before the labelled attack. Nothing is synthetic.\n",
             "| File | Attack type | ATT&CK stage | Rows | Attack rows | Benign lead |",
             "|------|-------------|--------------|------|-------------|-------------|"]
    for r in results:
        if r["status"] == "OK":
            lines.append(f"| `{r['out']}` | {r['attack']} | {r['stage']} | {r['rows']} | {r['attack_rows']} | {r['benign_lead_rows']} |")
        else:
            lines.append(f"| `{r['out']}` | {r.get('attack','')} | {r.get('stage','')} | {r['status']}: {r.get('reason','')} | | |")
    lines.append("\n> Forecast behaviour (before-onset vs at-onset) is model-dependent; verify by upload.")
    (OUT / "README.md").write_text("\n".join(lines), encoding="utf-8")

    for r in results:
        print(r)
    print(f"\nWrote {sum(1 for r in results if r['status']=='OK')} samples to {OUT}")


if __name__ == "__main__":
    main()
