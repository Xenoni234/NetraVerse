"""NetFlow-style flow extraction: every flow-record format -> canonical flow table.

Supported inputs (auto-detected from the header):

* CIC-IDS2017 ``TrafficLabelling`` CSVs (and CICFlowMeter-Java output in general)
* CIC-IDS2018 ``TrafficForML`` CSVs that carry IPs (only the 20-02 day does)
* Python ``cicflowmeter`` snake_case CSVs
* CTU-13 Argus ``.binetflow``
* UNSW-NB15 raw ``UNSW-NB15_{1..4}.csv`` (headerless)
* our own canonical flow CSV (``FLOW_COLUMNS``) - e.g. a saved live capture

All loaders return a pandas DataFrame with exactly ``schema.FLOW_COLUMNS``.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import polars as pl

from src.features.schema import FLOW_COLUMNS

PROTO_NUM = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmp"}


class UnsupportedFormat(ValueError):
    pass


# ---------------------------------------------------------------- helpers
def _finalise(df: pd.DataFrame) -> pd.DataFrame:
    """Coerce to FLOW_COLUMNS dtypes/order and drop unusable rows."""
    for col, dt in FLOW_COLUMNS.items():
        if col not in df.columns:
            df[col] = np.nan if dt == "float64" else ("" if dt == "str" else 0)
    df = df[list(FLOW_COLUMNS)].copy()
    df = df[df["src_ip"].astype(str).str.len() > 0]
    df = df[df["dst_ip"].astype(str).str.len() > 0]
    df = df[np.isfinite(df["ts_start"]) & np.isfinite(df["ts_end"])]
    for col, dt in FLOW_COLUMNS.items():
        if dt == "str":
            df[col] = df[col].fillna("").astype(str)
        elif dt == "float64":
            df[col] = pd.to_numeric(df[col], errors="coerce").astype("float64")
        else:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(dt)
    for c in ("fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes"):
        df[c] = df[c].fillna(0).clip(lower=0)
    df["ts_end"] = np.maximum(df["ts_end"], df["ts_start"])
    return df.sort_values("ts_end", kind="stable").reset_index(drop=True)


def _proto_name(series: pd.Series) -> pd.Series:
    s = series.astype(str).str.strip().str.lower()
    num = pd.to_numeric(s, errors="coerce")
    named = num.map(PROTO_NUM)
    out = named.where(num.notna(), s)
    return out.where(out.isin(["tcp", "udp", "icmp"]), "other").fillna("other")


def _port(series: pd.Series) -> pd.Series:
    s = series.astype(str).str.strip()
    hexmask = s.str.startswith("0x")
    out = pd.to_numeric(s.where(~hexmask), errors="coerce")
    if hexmask.any():
        out.loc[hexmask] = s[hexmask].map(lambda v: int(v, 16) if v else 0)
    return out.fillna(0).astype("int64")


def _parse_cic2017_ts(ts: pd.Series) -> pd.Series:
    """CIC-IDS2017 WorkingHours: d/m/Y H:M[:S], 12-hour clock with the AM/PM dropped.

    Capture hours are 08:00-17:59, so hours 1..7 are afternoon (+12h). Timestamps
    are minute-resolution on most days - one source of <=1 window jitter.
    """
    parts = ts.astype(str).str.strip().str.extract(
        r"^(\d{1,2})/(\d{1,2})/(\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?")
    ok = parts[0].notna()
    d = parts[0].astype(float); m = parts[1].astype(float); y = parts[2].astype(float)
    hh = parts[3].astype(float); mm = parts[4].astype(float); ss = parts[5].astype(float).fillna(0)
    hh = np.where((hh >= 1) & (hh <= 7), hh + 12, hh)
    base = pd.to_datetime(
        dict(year=y.where(ok, 1970), month=m.where(ok, 1), day=d.where(ok, 1)), errors="coerce")
    epoch = (base - pd.Timestamp("1970-01-01")).dt.total_seconds()
    out = epoch + hh * 3600 + mm * 60 + ss
    return out.where(ok)


def _parse_dmy_hms(ts: pd.Series) -> pd.Series:
    t = pd.to_datetime(ts.astype(str).str.strip(), format="%d/%m/%Y %H:%M:%S", errors="coerce")
    return (t - pd.Timestamp("1970-01-01")).dt.total_seconds()


def _parse_generic_ts(ts: pd.Series) -> pd.Series:
    num = pd.to_numeric(ts, errors="coerce")
    if num.notna().mean() > 0.9:
        return num / (1000.0 if num.median() > 1e11 else 1.0)
    t = pd.to_datetime(ts.astype(str).str.strip(), errors="coerce", format="mixed")
    if getattr(t.dt, "tz", None) is not None:
        t = t.dt.tz_convert(None)
    return (t - pd.Timestamp("1970-01-01")).dt.total_seconds()


# ---------------------------------------------------------------- CIC-style flow CSVs
_CIC_ALIASES = {
    "src_ip": ["Source IP", "Src IP", "src_ip"],
    "dst_ip": ["Destination IP", "Dst IP", "dst_ip"],
    "sport": ["Source Port", "Src Port", "src_port"],
    "dport": ["Destination Port", "Dst Port", "dst_port"],
    "proto": ["Protocol", "protocol"],
    "ts": ["Timestamp", "timestamp"],
    "dur": ["Flow Duration", "flow_duration"],
    "fwd_pkts": ["Total Fwd Packets", "Tot Fwd Pkts", "tot_fwd_pkts"],
    "bwd_pkts": ["Total Backward Packets", "Tot Bwd Pkts", "tot_bwd_pkts"],
    "fwd_bytes": ["Total Length of Fwd Packets", "TotLen Fwd Pkts", "totlen_fwd_pkts"],
    "bwd_bytes": ["Total Length of Bwd Packets", "TotLen Bwd Pkts", "totlen_bwd_pkts"],
    "syn": ["SYN Flag Count", "SYN Flag Cnt", "syn_flag_cnt"],
    "rst": ["RST Flag Count", "RST Flag Cnt", "rst_flag_cnt"],
    "fin": ["FIN Flag Count", "FIN Flag Cnt", "fin_flag_cnt"],
    "tcp_win": ["Init_Win_bytes_forward", "Init Fwd Win Byts", "init_fwd_win_byts"],
    "label": ["Label", "label"],
}


def _resolve(columns: list[str], aliases: dict[str, list[str]]) -> dict[str, str]:
    norm = {c.strip().lower(): c for c in columns}
    found = {}
    for key, names in aliases.items():
        for n in names:
            if n.lower() in norm:
                found[key] = norm[n.lower()]
                break
    return found


def load_cic_csv(path: Path, n_rows: int | None = None) -> pd.DataFrame:
    head = pl.read_csv(path, n_rows=1, encoding="utf8-lossy", infer_schema_length=0,
                       truncate_ragged_lines=True).columns
    cols = _resolve(head, _CIC_ALIASES)
    need = {"src_ip", "dst_ip", "ts", "dur", "fwd_pkts", "bwd_pkts"}
    if not need <= cols.keys():
        raise UnsupportedFormat(
            f"{Path(path).name}: CIC-style CSV without {sorted(need - cols.keys())}. "
            "Per-host forecasting needs source/destination IPs and timestamps.")
    raw = pl.read_csv(path, columns=list(cols.values()), encoding="utf8-lossy",
                      infer_schema_length=0, n_rows=n_rows, truncate_ragged_lines=True,
                      ignore_errors=True).to_pandas()
    raw = raw.rename(columns={v: k for k, v in cols.items()})
    df = pd.DataFrame()
    df["src_ip"] = raw["src_ip"].astype(str).str.strip()
    df["dst_ip"] = raw["dst_ip"].astype(str).str.strip()
    df["sport"] = _port(raw.get("sport", pd.Series(0, index=raw.index)))
    df["dport"] = _port(raw.get("dport", pd.Series(0, index=raw.index)))
    df["proto"] = _proto_name(raw.get("proto", pd.Series("other", index=raw.index)))
    ts_raw = raw["ts"].astype(str)
    sample = ts_raw.dropna().head(200)
    if sample.str.match(r"^\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}(:\d{2})?$").mean() > 0.9:
        # CIC-2017 (12h clock, AM/PM lost) vs CIC-2018 (24h, d/m/Y H:M:S)
        hours = sample.str.extract(r" (\d{1,2}):")[0].astype(float)
        is2018 = (hours > 12).any() or "2018" in ts_raw.iloc[0]
        start = _parse_dmy_hms(ts_raw) if is2018 else _parse_cic2017_ts(ts_raw)
    else:
        start = _parse_generic_ts(ts_raw)
    # CICFlowMeter (Java and Python) both write Flow Duration in microseconds
    dur_s = pd.to_numeric(raw["dur"], errors="coerce").fillna(0).clip(lower=0) / 1e6
    df["ts_start"] = start
    df["ts_end"] = start + dur_s
    for c in ("fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes"):
        df[c] = pd.to_numeric(raw.get(c, pd.Series(0, index=raw.index)), errors="coerce")
    for c in ("syn", "rst", "fin"):
        df[c] = (pd.to_numeric(raw.get(c, pd.Series(0, index=raw.index)), errors="coerce").fillna(0) > 0).astype(int)
    win = pd.to_numeric(raw.get("tcp_win", pd.Series(np.nan, index=raw.index)), errors="coerce")
    df["tcp_win"] = win.where(win > 0)          # CIC writes -1 when unobserved
    df["ttl"] = np.nan
    df["retrans"] = np.nan
    df["label"] = raw.get("label", pd.Series("", index=raw.index)).astype(str).str.strip()
    return _finalise(df)


# ---------------------------------------------------------------- CTU-13
def load_ctu13(path: Path, n_rows: int | None = None) -> pd.DataFrame:
    raw = pl.read_csv(path, infer_schema_length=0, n_rows=n_rows, ignore_errors=True,
                      truncate_ragged_lines=True).to_pandas()
    raw.columns = [c.strip() for c in raw.columns]
    start = _parse_generic_ts(raw["StartTime"].str.replace("/", "-", regex=False))
    dur = pd.to_numeric(raw["Dur"], errors="coerce").fillna(0).clip(lower=0)
    tot_p = pd.to_numeric(raw["TotPkts"], errors="coerce").fillna(0)
    tot_b = pd.to_numeric(raw["TotBytes"], errors="coerce").fillna(0)
    src_b = pd.to_numeric(raw["SrcBytes"], errors="coerce").fillna(0)
    frac = (src_b / tot_b.replace(0, np.nan)).fillna(1.0).clip(0, 1)
    state = raw["State"].fillna("").astype(str)
    df = pd.DataFrame({
        "ts_start": start, "ts_end": start + dur,
        "src_ip": raw["SrcAddr"].str.strip(), "dst_ip": raw["DstAddr"].str.strip(),
        "sport": _port(raw["Sport"]), "dport": _port(raw["Dport"]),
        "proto": _proto_name(raw["Proto"]),
        "fwd_pkts": np.maximum(1, np.round(tot_p * frac)), "bwd_pkts": np.round(tot_p * (1 - frac)),
        "fwd_bytes": src_b, "bwd_bytes": (tot_b - src_b).clip(lower=0),
        "syn": state.str.contains("S").astype(int), "rst": state.str.contains("R").astype(int),
        "fin": state.str.contains("F").astype(int),
        "ttl": np.nan, "tcp_win": np.nan, "retrans": np.nan,
        "label": raw["Label"].astype(str).str.strip(),
    })
    df.loc[df["proto"] != "tcp", ["syn", "rst", "fin"]] = 0
    return _finalise(df)


# ---------------------------------------------------------------- UNSW-NB15
UNSW_COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes", "sttl",
    "dttl", "sloss", "dloss", "service", "Sload", "Dload", "Spkts", "Dpkts", "swin", "dwin",
    "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth", "res_bdy_len", "Sjit", "Djit",
    "Stime", "Ltime", "Sintpkt", "Dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports",
    "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd", "ct_srv_src",
    "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
    "ct_dst_src_ltm", "attack_cat", "Label",
]


def load_unsw(path: Path, n_rows: int | None = None) -> pd.DataFrame:
    raw = pl.read_csv(path, has_header=False, new_columns=UNSW_COLUMNS, infer_schema_length=0,
                      n_rows=n_rows, encoding="utf8-lossy", ignore_errors=True,
                      truncate_ragged_lines=True).to_pandas()
    raw["srcip"] = raw["srcip"].astype(str).str.replace("﻿", "", regex=False).str.strip()
    state = raw["state"].fillna("").astype(str).str.upper()
    proto = _proto_name(raw["proto"])
    lab = pd.to_numeric(raw["Label"], errors="coerce").fillna(0)
    cat = raw["attack_cat"].fillna("").astype(str).str.strip()
    label = np.where(lab > 0, np.where(cat == "", "attack", cat), "BENIGN")
    spk = pd.to_numeric(raw["Spkts"], errors="coerce").fillna(0)
    sloss = pd.to_numeric(raw["sloss"], errors="coerce")
    df = pd.DataFrame({
        "ts_start": pd.to_numeric(raw["Stime"], errors="coerce"),
        "ts_end": pd.to_numeric(raw["Ltime"], errors="coerce"),
        "src_ip": raw["srcip"], "dst_ip": raw["dstip"].astype(str).str.strip(),
        "sport": _port(raw["sport"]), "dport": _port(raw["dsport"]), "proto": proto,
        "fwd_pkts": spk, "bwd_pkts": pd.to_numeric(raw["Dpkts"], errors="coerce"),
        "fwd_bytes": pd.to_numeric(raw["sbytes"], errors="coerce"),
        "bwd_bytes": pd.to_numeric(raw["dbytes"], errors="coerce"),
        "syn": ((proto == "tcp") & state.isin(["REQ", "CON", "FIN", "INT", "RST", "ACC", "CLO"])).astype(int),
        "rst": (state == "RST").astype(int), "fin": (state.isin(["FIN", "CLO"])).astype(int),
        "ttl": pd.to_numeric(raw["sttl"], errors="coerce"),
        "tcp_win": pd.to_numeric(raw["swin"], errors="coerce").where(proto == "tcp"),
        "retrans": sloss.where(proto == "tcp"),
        "label": label,
    })
    return _finalise(df)


# ---------------------------------------------------------------- canonical CSV
def load_canonical(path: Path) -> pd.DataFrame:
    return _finalise(pd.read_csv(path))


# ---------------------------------------------------------------- dispatch
def detect_format(path: Path) -> str:
    path = Path(path)
    if path.suffix == ".binetflow":
        return "ctu13"
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        first = fh.readline().replace("﻿", "")
    cols = [c.strip().lower() for c in first.split(",")]
    if {"starttime", "srcaddr", "dstaddr"} <= set(cols):
        return "ctu13"
    if set(FLOW_COLUMNS) <= set(cols):
        return "canonical"
    if len(cols) == 49 and not any(c.isalpha() and c in ("srcip", "label") for c in cols) \
            and cols[0].count(".") == 3:
        return "unsw"
    if any(c in cols for c in ("source ip", "src ip", "src_ip", "flow duration", "flow_duration",
                               "dst port", "destination port")):
        return "cic"
    raise UnsupportedFormat(f"Unrecognised flow CSV header: {first[:120]!r}")


def load_flows(path: Path, n_rows: int | None = None) -> tuple[pd.DataFrame, str]:
    fmt = detect_format(path)
    loader = {"cic": load_cic_csv, "ctu13": load_ctu13, "unsw": load_unsw,
              "canonical": lambda p, n_rows=None: load_canonical(p)}[fmt]
    return loader(path, n_rows=n_rows), fmt


def epoch_to_iso(t: float) -> str:
    return datetime.fromtimestamp(float(t), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
