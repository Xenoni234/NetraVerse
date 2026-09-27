"""Cut replayable demo files from the raw datasets (original formats, untouched rows).

    python -m demo.make_samples

Each sample is a contiguous time slice so the replay shows benign lead-in ->
attack -> aftermath. Rows are copied verbatim (labels included, so the
dashboard can overlay ground truth); nothing is synthesised.
"""
from __future__ import annotations

import polars as pl

from src.features.flow_features import _parse_cic2017_ts, _parse_generic_ts
from src.utils.config import RAW, ROOT

OUT = ROOT / "demo" / "samples"
CIC = RAW / "CIC-IDS2017" / "TrafficLabelling"

# (output name, source file, start "HH:MM", end "HH:MM") - capture-local clock (24h after PM fix)
CIC_SLICES = [
    ("cic2017_portscan_friday.csv", "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", "13:40", "15:05"),
    ("cic2017_bruteforce_tuesday.csv", "Tuesday-WorkingHours.pcap_ISCX.csv", "08:55", "10:10"),
    ("cic2017_dos_wednesday.csv", "Wednesday-workingHours.pcap_ISCX.csv", "09:25", "10:25"),
    ("cic2017_webattack_thursday.csv", "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv", "09:00", "10:00"),
    ("cic2017_botnet_friday.csv", "Friday-WorkingHours-Morning.pcap_ISCX.csv", "09:40", "10:50"),
]
CTU_SLICES = [
    # scenario 10 (Rbot, ICMP DDoS from 10 infected hosts), first ~75 min
    ("ctu13_botnet_scenario10.binetflow", RAW / "CTU-13/_full/CTU-13-Dataset/10/capture20110818.binetflow", 0, 75),
]


def _clock(epoch: pl.Series) -> pl.Series:
    return (epoch % 86400)


def cic_slice(src: str, start: str, end: str) -> pl.DataFrame:
    df = pl.read_csv(CIC / src, infer_schema_length=0, encoding="utf8-lossy", truncate_ragged_lines=True)
    ts_col = next(c for c in df.columns if c.strip() == "Timestamp")
    t = _parse_cic2017_ts(df[ts_col].to_pandas())
    sec = (t % 86400).to_numpy()
    h0, m0 = map(int, start.split(":")); h1, m1 = map(int, end.split(":"))
    keep = (sec >= h0 * 3600 + m0 * 60) & (sec <= h1 * 3600 + m1 * 60)
    return df.filter(pl.Series(keep))


def ctu_slice(path, start_min: int, end_min: int) -> pl.DataFrame:
    df = pl.read_csv(path, infer_schema_length=0, truncate_ragged_lines=True)
    t = _parse_generic_ts(df["StartTime"].to_pandas().str.replace("/", "-", regex=False)).to_numpy()
    t0 = t[~(t != t)].min()
    keep = (t >= t0 + start_min * 60) & (t <= t0 + end_min * 60)
    return df.filter(pl.Series(keep))


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, src, a, b in CIC_SLICES:
        df = cic_slice(src, a, b)
        df.write_csv(OUT / name)
        lab = next(c for c in df.columns if c.strip() == "Label")
        print(name, df.height, df[lab].value_counts().sort("count", descending=True).head(4).to_dicts())
    for name, path, a, b in CTU_SLICES:
        df = ctu_slice(path, a, b)
        df.write_csv(OUT / name)
        print(name, df.height)


if __name__ == "__main__":
    main()
