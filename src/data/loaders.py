"""Per-dataset readers: raw CSV / binetflow / parquet in, ``pandas.DataFrame`` out.

Each loader knows exactly one dataset's quirks and nothing else. A loader's job
ends the moment it has produced a tidy frame with parsed timestamps and the
source dataset's own column names; mapping onto the unified schema belongs to
:mod:`src.data.unified_schema`.

CIC-IDS2018 quirks this module absorbs
--------------------------------------
1. **Repeated mid-file headers.** Several days were concatenated from multiple
   captures and contain the header row again partway through. Those rows parse
   as the literal string ``"Dst Port"`` in a numeric column and silently poison
   every downstream statistic. We detect and drop them.
2. **Infinity and NaN.** ``Flow Byts/s`` and ``Flow Pkts/s`` contain literal
   ``Infinity`` (zero-duration flows) and blanks. Coerced to NaN, then handled
   explicitly — never left to propagate into a scaler.
3. **Inconsistent column sets.** Most days have 80 columns; a few
   (e.g. Thursday-20-02) additionally carry ``Flow ID``, ``Src IP``,
   ``Src Port``, ``Dst IP``. We keep whatever is present and let
   :mod:`src.data.unified_schema` decide what to drop.
4. **Timestamps are naive local strings** in mixed ``dd/mm/yyyy`` and
   ``d/m/yyyy`` forms, sometimes with 12-hour clocks and no AM/PM marker. Parsed
   with ``dayfirst=True`` and localised to UTC.

Memory
------
CIC-IDS2018 is ~6.5 GB across ten CSVs; the largest single day does not fit
comfortably in RAM as float64. :func:`load_cicids2018` therefore reads in
chunks, downcasts to ``float32`` per chunk, and supports ``max_rows`` for dev
runs. ``pyarrow`` is used as the CSV engine when available (roughly 3-5x faster
than the C engine here) and falls back automatically.

TODO
----
* [ ] Implement ``load_cicids2017`` / ``load_unsw_nb15`` / ``load_ctu13``.
* [ ] Implement ``load_dataset`` dispatch + parquet caching round-trip.
* [ ] Confirm the capture timezone per day and replace the UTC assumption.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Final, Iterator, Sequence

import numpy as np
import pandas as pd

from src.data.paths import CICIDS2018_DAYS, DatasetName, cicids2018_csv

log = logging.getLogger(__name__)

#: Column every loader must emit, in UTC.
TIMESTAMP_COLUMN: Final[str] = "timestamp"

#: Source column holding the ground-truth label.
LABEL_COLUMN: Final[str] = "Label"

#: Source column holding the capture timestamp.
RAW_TIMESTAMP_COLUMN: Final[str] = "Timestamp"

#: Values CIC-IDS2018 uses for "no value" in numeric columns.
NA_VALUES: Final[tuple[str, ...]] = ("Infinity", "-Infinity", "inf", "-inf", "NaN", "nan", "")

#: Rows per chunk when streaming a large CSV.
DEFAULT_CHUNK_ROWS: Final[int] = 500_000

#: Microsecond<->second divisor (CTU-13 Dur is seconds; CIC durations are microseconds).
_US_PER_S: Final[float] = 1_000_000.0

#: Capture timezone of the CIC-IDS2018 testbed.
#: TODO: the AWS testbed reported local time; confirm the offset per day before
#: any cross-day analysis. For a single-day baseline the offset is a constant
#: shift and does not affect a chronological split.
CAPTURE_TZ: Final[str] = "UTC"


#: CIC-IDS2017 capture weekdays (Mon-Fri, July 2017). Thursday/Friday are split
#: across several files but are ONE capture day each -> one campaign.
CICIDS2017_WEEKDAYS: Final[tuple[str, ...]] = (
    "monday", "tuesday", "wednesday", "thursday", "friday",
)


def _weekday_from_filename(name: str) -> str:
    """First token of a CIC-2017 filename is the weekday, e.g. 'Monday-...' -> 'monday'."""
    return name.split("-", 1)[0].strip().lower()


def load_cicids2017(
    day: str = "all",
    *,
    variant: str = "TrafficLabelling",
    max_rows: int | None = None,
    chunk_rows: int = DEFAULT_CHUNK_ROWS,
    raw_dir: Path | None = None,
    verbose: bool = True,
) -> pd.DataFrame:
    """Load CIC-IDS2017 flow records (TrafficLabelling variant).

    The TrafficLabelling CSVs carry Source IP + Timestamp + Label, which the
    MachineLearningCVE variant lacks; only this variant supports per-host
    forecasting.

    Args:
        day: ``"all"`` (every weekday) or a single weekday
            (``"monday".."friday"``). Thursday/Friday span several files that are
            one capture day and share one ``campaign_id``.
        variant: Subfolder under the dataset root. Defaults to TrafficLabelling.
        max_rows: Cap total rows. Dev runs only.
        chunk_rows: Rows read per chunk.
        raw_dir: Override the dataset root (defaults to data/raw/CIC-IDS2017).
        verbose: Print progress.

    Returns:
        Unified-loader frame in the source's own (stripped) column names, plus a
        tz-aware UTC ``timestamp`` column and a per-weekday ``campaign_id``.
    """
    from src.data.paths import raw_dataset_dir

    root = Path(raw_dir) if raw_dir is not None else raw_dataset_dir("cicids2017")
    folder = root / variant
    if not folder.exists():
        raise FileNotFoundError(
            f"CIC-IDS2017 {variant} folder not found at {folder}. "
            f"Expected CSVs under data/raw/CIC-IDS2017/{variant}/."
        )

    day = day.strip().lower()
    files = sorted(folder.glob("*.csv"))
    if day != "all":
        if day not in CICIDS2017_WEEKDAYS:
            raise KeyError(f"Unknown 2017 day {day!r}; use one of {CICIDS2017_WEEKDAYS} or 'all'")
        files = [f for f in files if _weekday_from_filename(f.name) == day]
    if not files:
        raise FileNotFoundError(f"No CIC-IDS2017 CSVs matched day={day!r} under {folder}")

    frames: list[pd.DataFrame] = []
    total = 0
    for path in files:
        weekday = _weekday_from_filename(path.name)
        if verbose:
            print(f"  [loader] reading {path.name} ({path.stat().st_size / 1e6:,.0f} MB)")
        for chunk in _read_csv_chunks(path, chunk_rows=chunk_rows, encoding="latin-1"):
            chunk.columns = [str(c).strip() for c in chunk.columns]  # 2017 has leading spaces
            empty_rows = chunk.isna().all(axis=1)
            if verbose and empty_rows.any():
                print(f"  [loader] excluded {int(empty_rows.sum()):,} empty CSV records", flush=True)
            chunk = chunk.loc[~empty_rows].copy()
            # CIC-IDS2017 ships a duplicate "Fwd Header Length" column; keep first.
            chunk = chunk.loc[:, ~pd.Index(chunk.columns).duplicated()]
            chunk, _ = _drop_repeated_headers(chunk)
            chunk = _coerce_numeric(chunk)
            chunk["campaign_id"] = f"cicids2017-{weekday}"
            frames.append(chunk)
            total += len(chunk)
            if max_rows is not None and total >= max_rows:
                break
        if max_rows is not None and total >= max_rows:
            break

    df = pd.concat(frames, ignore_index=True)
    if max_rows is not None:
        df = df.iloc[:max_rows].copy()

    df[TIMESTAMP_COLUMN] = _parse_cic_working_hours(df[RAW_TIMESTAMP_COLUMN])
    n_bad = int(df[TIMESTAMP_COLUMN].isna().sum())
    if n_bad:
        df = df[df[TIMESTAMP_COLUMN].notna()].copy()
    df["dataset"] = "cicids2017"
    df = df.sort_values(["campaign_id", TIMESTAMP_COLUMN], kind="mergesort").reset_index(drop=True)

    if verbose:
        rate = float((df[LABEL_COLUMN].astype("string").str.strip() != "BENIGN").mean())
        print(
            f"  [loader] cicids2017 {day}: {len(df):,} rows | "
            f"{df['campaign_id'].nunique()} campaign(s) | attack rate {rate:.1%}"
            + (f" | dropped {n_bad:,} bad-timestamp rows" if n_bad else "")
        )

    return df


def load_cicids2018(
    day: str,
    *,
    max_rows: int | None = None,
    chunk_rows: int = DEFAULT_CHUNK_ROWS,
    raw_dir: Path | None = None,
    verbose: bool = True,
) -> pd.DataFrame:
    """Load one CIC-IDS2018 capture day.

    Args:
        day: Short key from :data:`~src.data.paths.CICIDS2018_DAYS`
            (e.g. ``"thu-15-02"``) or the full date string.
        max_rows: Stop after this many valid rows. Dev runs only.
        chunk_rows: Rows read per chunk.
        raw_dir: Override the dataset search root.
        verbose: Print progress.

    Returns:
        Frame in the dataset's own column names, plus a tz-aware UTC
        ``timestamp`` column and a ``campaign_id`` naming the capture day.

    Raises:
        FileNotFoundError: if the day's CSV is not on disk (message names the
            directory searched and what was found).
    """
    path = cicids2018_csv(day, raw_dir=raw_dir)
    date = CICIDS2018_DAYS.get(day, day)
    size_mb = path.stat().st_size / 1e6

    if verbose:
        print(f"  [loader] reading {path.name} ({size_mb:,.0f} MB)")

    started = time.perf_counter()
    frames: list[pd.DataFrame] = []
    total_read = 0
    dropped_headers = 0

    for chunk in _read_csv_chunks(
        path, chunk_rows=chunk_rows, prefer_pyarrow=(max_rows is None)
    ):
        total_read += len(chunk)
        chunk, n_headers = _drop_repeated_headers(chunk)
        dropped_headers += n_headers
        chunk = _coerce_numeric(chunk)
        frames.append(chunk)
        if max_rows is not None and sum(len(f) for f in frames) >= max_rows:
            break

    if not frames:
        raise ValueError(f"{path} produced no rows")

    df = pd.concat(frames, ignore_index=True)
    if max_rows is not None:
        df = df.iloc[:max_rows].copy()

    df[TIMESTAMP_COLUMN] = _parse_timestamps(df[RAW_TIMESTAMP_COLUMN])
    n_bad_ts = int(df[TIMESTAMP_COLUMN].isna().sum())
    if n_bad_ts:
        log.warning("%s: dropping %d rows with unparseable timestamps", path.name, n_bad_ts)
        df = df[df[TIMESTAMP_COLUMN].notna()].copy()

    df["campaign_id"] = f"cicids2018-{date}"
    df["dataset"] = "cicids2018"
    df = df.sort_values(TIMESTAMP_COLUMN, kind="mergesort").reset_index(drop=True)

    if verbose:
        elapsed = time.perf_counter() - started
        attack_rate = float((df[LABEL_COLUMN].astype("string").str.strip() != "Benign").mean())
        print(
            f"  [loader] {len(df):,} rows in {elapsed:,.1f}s "
            f"| {df[TIMESTAMP_COLUMN].min()} -> {df[TIMESTAMP_COLUMN].max()} "
            f"| attack rate {attack_rate:.1%}"
        )
        if dropped_headers:
            print(f"  [loader] dropped {dropped_headers} repeated header row(s)")
        if n_bad_ts:
            print(f"  [loader] dropped {n_bad_ts:,} rows with bad timestamps")

    return df


def load_cicids2018_days(
    days: Sequence[str],
    *,
    max_rows_per_day: int | None = None,
    raw_dir: Path | None = None,
    verbose: bool = True,
) -> pd.DataFrame:
    """Load several capture days and concatenate them, time-ordered per day.

    Each day keeps its own ``campaign_id`` so the split policy can treat it as a
    separate campaign.
    """
    frames = []
    for day in days:
        frames.append(
            load_cicids2018(day, max_rows=max_rows_per_day, raw_dir=raw_dir, verbose=verbose)
        )
    combined = pd.concat(frames, ignore_index=True)
    return combined.sort_values(
        ["campaign_id", TIMESTAMP_COLUMN], kind="mergesort"
    ).reset_index(drop=True)


# --------------------------------------------------------------------------- #
# Internals
# --------------------------------------------------------------------------- #


def _read_csv_chunks(
    path: Path, *, chunk_rows: int, encoding: str = "utf-8", prefer_pyarrow: bool = True
) -> Iterator[pd.DataFrame]:
    """Yield CSV chunks, preferring the pyarrow engine when it is available.

    Encoding: CIC-IDS2017 "Web Attack" labels are Windows-1252 (byte 0x96 en-dash),
    which is not valid UTF-8 and crashes a UTF-8 reader. We read as ``latin-1``,
    which never errors on any byte; the web-attack labels are matched by prefix
    downstream, so the exact trailing byte does not matter.

    pyarrow does not support ``chunksize`` (or per-call ``encoding``), so it is
    tried whole-file first and, on any failure, we fall back to the C engine with
    the explicit encoding.
    """
    # pyarrow is fast but does not honour a non-UTF-8 encoding here, so only use it
    # for UTF-8 files (CIC-IDS2018). CIC-IDS2017 is Windows-1252 -> C engine + latin-1.
    if prefer_pyarrow and encoding.lower().replace("-", "") in ("utf8", ""):
        try:
            import pyarrow  # noqa: F401

            df = pd.read_csv(
                path, engine="pyarrow", dtype_backend="numpy_nullable",
                na_values=list(NA_VALUES),
            )
            for start in range(0, len(df), chunk_rows):
                yield df.iloc[start : start + chunk_rows].copy()
            return
        except Exception as exc:  # pyarrow missing or OOM
            log.info("pyarrow CSV path unavailable (%s); falling back to the C engine", exc)

    reader = pd.read_csv(
        path, chunksize=chunk_rows, low_memory=False, na_values=list(NA_VALUES),
        skipinitialspace=True, encoding=encoding,
    )
    for chunk in reader:
        yield chunk


def _drop_repeated_headers(chunk: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Drop rows that are a repeated copy of the CSV header.

    Detected by the ``Label`` cell literally equalling ``"Label"``. These rows
    are common in the concatenated CIC-IDS2018 days and would otherwise turn
    whole numeric columns into ``object`` dtype.
    """
    if LABEL_COLUMN not in chunk.columns:
        return chunk, 0
    mask = chunk[LABEL_COLUMN].astype("string").str.strip() == LABEL_COLUMN
    n = int(mask.sum())
    return (chunk[~mask].copy(), n) if n else (chunk, 0)


def _coerce_numeric(chunk: pd.DataFrame) -> pd.DataFrame:
    """Coerce every non-identity column to ``float32`` and replace inf with NaN.

    Downcasting here rather than after ``concat`` roughly halves peak memory.
    """
    skip = {
        LABEL_COLUMN, RAW_TIMESTAMP_COLUMN, "Timestamp", "Label", "Flow ID",
        "Src IP", "Dst IP", "Source IP", "Destination IP",
    }
    for col in chunk.columns:
        if col in skip:
            continue
        if chunk[col].dtype == object or str(chunk[col].dtype).startswith(("Int", "Float", "UInt")):
            chunk[col] = pd.to_numeric(chunk[col], errors="coerce")
        if pd.api.types.is_numeric_dtype(chunk[col]):
            chunk[col] = chunk[col].astype("float32")
    return chunk.replace([np.inf, -np.inf], np.nan)


def _parse_timestamps(series: pd.Series) -> pd.Series:
    """Parse CIC-IDS2018 timestamps to tz-aware UTC.

    The column mixes ``dd/mm/yyyy HH:MM:SS`` with ``d/m/yyyy H:MM`` and 12-hour
    clocks. ``dayfirst=True`` is required — without it, ``02/03/2018`` silently
    parses as 3 February and the chronological split is quietly wrong.
    """
    parsed = pd.to_datetime(series, dayfirst=True, errors="coerce", format="mixed")
    if getattr(parsed.dtype, "tz", None) is None:
        parsed = parsed.dt.tz_localize(CAPTURE_TZ, ambiguous="NaT", nonexistent="NaT")
    return parsed.dt.tz_convert("UTC")


def _parse_cic_working_hours(series: pd.Series) -> pd.Series:
    """Repair CIC-IDS2017's unmarked 12-hour working-day clock.

    Source: https://www.unb.ca/cic/datasets/ids-2017.html (capture/attack timetable).
    Local TrafficLabelling files omit AM/PM: 1..7 mean 13..19, not overnight.
    Explicit AM/PM and 24-hour timestamps are preserved. This dataset-specific
    policy must never be applied to arbitrary uploaded/live traffic.
    """
    parsed = _parse_timestamps(series)
    explicit = series.astype('string').str.contains(r'(?i)\b[ap]m\b', regex=True, na=False)
    legacy_format = series.astype('string').str.match(r'^\s*\d{1,2}/\d{1,2}/2017\s', na=False)
    shift = parsed.dt.hour.between(1, 7) & ~explicit & legacy_format
    return parsed + pd.to_timedelta(shift.astype(int) * 12, unit='h')


# --------------------------------------------------------------------------- #
# Not yet implemented
# --------------------------------------------------------------------------- #


def load_dataset(
    dataset: DatasetName,
    *,
    campaigns: Sequence[str] | None = None,
    max_rows: int | None = None,
    use_cache: bool = True,
) -> pd.DataFrame:
    """Load one dataset's raw flow records (dispatching per dataset).

    TODO: implement the dispatch and the parquet cache. Only CIC-IDS2018 is
    wired up so far — call :func:`load_cicids2018` directly.
    """
    if dataset == "cicids2018":
        days = list(campaigns) if campaigns else list(CICIDS2018_DAYS)
        return load_cicids2018_days(days, max_rows_per_day=max_rows)
    if dataset == "unsw_nb15":
        return load_unsw_nb15(max_rows=max_rows)
    raise NotImplementedError(f"Loader for {dataset!r} not implemented yet")



def load_unsw_nb15(path: Path | None = None, *, max_rows: int | None = None) -> pd.DataFrame:
    """Load the raw, timestamped UNSW-NB15 flow files.

    The four raw files are headerless. The archive's feature dictionary is
    named ``NUSW-NB15_features.csv``. The summarized train/test files are not
    used because they omit the timestamps and endpoint identities needed for
    temporal forecasting.
    """
    from src.data.paths import raw_dataset_dir

    root = Path(path) if path is not None else raw_dataset_dir("unsw_nb15")
    if root.is_file():
        root = root.parent
    files = sorted(root.rglob("UNSW-NB15_[1-4].csv"))
    if not files:
        raise FileNotFoundError(f"No raw UNSW-NB15_1..4.csv files found under {root}")
    feature_files = sorted(root.rglob("*features*.csv"))
    if not feature_files:
        raise FileNotFoundError(f"UNSW-NB15 feature dictionary not found under {root}")
    feature_table = pd.read_csv(feature_files[0], encoding="latin1")
    if "Name" not in feature_table.columns:
        raise ValueError(f"Expected a Name column in {feature_files[0].name}")
    names = [str(v).strip().replace("ct_src_ ltm", "ct_src_ltm")
             for v in feature_table["Name"].tolist()]
    if len(names) != 49:
        raise ValueError(f"Expected 49 UNSW-NB15 feature names, found {len(names)}")

    def numeric(frame: pd.DataFrame, name: str) -> pd.Series:
        return pd.to_numeric(frame.get(name, 0), errors="coerce").fillna(0.0)

    frames: list[pd.DataFrame] = []
    remaining = max_rows
    for file_path in files:
        kwargs: dict = {"header": None, "names": names, "encoding": "latin1",
                        "na_values": ["-", ""]}
        if remaining is not None:
            kwargs["nrows"] = remaining
        raw = pd.read_csv(file_path, **kwargs)
        if raw.empty:
            continue
        dur_s = numeric(raw, "dur").clip(lower=0)
        fwd_pkts = numeric(raw, "Spkts").clip(lower=0)
        bwd_pkts = numeric(raw, "Dpkts").clip(lower=0)
        fwd_bytes = numeric(raw, "sbytes").clip(lower=0)
        bwd_bytes = numeric(raw, "dbytes").clip(lower=0)
        total_pkts = (fwd_pkts + bwd_pkts).replace(0, np.nan)
        dur_nonzero = dur_s.replace(0, np.nan)
        out = pd.DataFrame(index=raw.index)
        out["timestamp"] = pd.to_datetime(numeric(raw, "Stime"), unit="s", utc=True, errors="coerce")
        out["src_ip"] = raw.get("srcip", "").astype("string")
        out["dst_ip"] = raw.get("dstip", "").astype("string")
        out["src_port"] = numeric(raw, "sport")
        out["dst_port"] = numeric(raw, "dsport")
        out["protocol"] = raw.get("proto", "").astype("string")
        out["flow_duration"] = dur_s * _US_PER_S
        out["packets_per_second"] = ((fwd_pkts + bwd_pkts) / dur_nonzero).fillna(0)
        out["bytes_per_second"] = ((fwd_bytes + bwd_bytes) / dur_nonzero).fillna(0)
        out["fwd_bwd_ratio"] = (fwd_pkts / bwd_pkts.replace(0, np.nan)).fillna(0)
        out["fwd_packets"] = fwd_pkts
        out["bwd_packets"] = bwd_pkts
        out["fwd_bytes"] = fwd_bytes
        out["bwd_bytes"] = bwd_bytes
        out["iat_mean"] = (((numeric(raw, "Sintpkt") * fwd_pkts) +
                             (numeric(raw, "Dintpkt") * bwd_pkts)) / total_pkts).fillna(0) * 1000.0
        out["iat_std"] = 0.0
        out["iat_max"] = 0.0
        for flag in ("syn_count", "ack_count", "fin_count", "psh_count", "urg_count"):
            out[flag] = 0.0
        out["rst_count"] = raw.get("state", "").astype("string").str.contains(
            "RST", case=False, na=False).astype("float32")
        out["pkt_len_mean"] = ((fwd_pkts * numeric(raw, "smeansz") +
                                 bwd_pkts * numeric(raw, "dmeansz")) / total_pkts).fillna(0)
        out["pkt_len_std"] = 0.0
        out["fwd_pkt_len_mean"] = numeric(raw, "smeansz")
        out["bwd_pkt_len_mean"] = numeric(raw, "dmeansz")
        out["pkt_len_var"] = 0.0
        out["fwd_iat_mean"] = numeric(raw, "Sintpkt") * 1000.0
        out["bwd_iat_mean"] = numeric(raw, "Dintpkt") * 1000.0
        out["init_win_fwd"] = numeric(raw, "swin")
        out["init_win_bwd"] = numeric(raw, "dwin")
        out["active_mean"] = 0.0
        out["idle_mean"] = 0.0
        out["label_raw"] = raw.get("attack_cat", "Normal").astype("string").fillna("Normal")
        out["dataset"] = "unsw_nb15"
        out["campaign_id"] = "unsw_nb15"
        frames.append(out)
        if remaining is not None:
            remaining -= len(out)
            if remaining <= 0:
                break
    if not frames:
        raise ValueError(f"UNSW-NB15 files under {root} produced no rows")
    result = pd.concat(frames, ignore_index=True)
    result = result[result["timestamp"].notna()].copy()
    result = result.sort_values(["campaign_id", "timestamp"], kind="mergesort").reset_index(drop=True)
    if max_rows is not None:
        result = result.iloc[:max_rows].copy()
    print(f"  [loader] unsw_nb15: {len(result):,} rows | "
          f"{result['timestamp'].min()} -> {result['timestamp'].max()} | "
          f"attack rate {(result['label_raw'] != 'Normal').mean():.1%}")
    return result


#: Columns the FULL CTU-13 binetflow carries and that we need (Argus/binetflow).
CTU13_REQUIRED_COLS: Final[tuple[str, ...]] = ("StartTime", "SrcAddr", "DstAddr", "Dport")


def _ctu13_scenario(path: Path) -> str:
    """Scenario number for a CTU-13 file.

    The official tar extracts as ``CTU-13-Dataset/<N>/capture<date>.binetflow`` —
    the scenario is the numeric parent folder. The Kaggle parquets instead encode
    it as a filename prefix (``9-Neris-...``). Handle both.
    """
    if path.parent.name.isdigit():
        return path.parent.name.lstrip("0") or "0"
    head = path.name.split("-", 1)[0]
    return head.lstrip("0") or head


def load_ctu13(
    scenario: str = "all",
    *,
    raw_dir: Path | None = None,
    max_rows: int | None = None,
    verbose: bool = True,
) -> pd.DataFrame:
    """Load CTU-13 flow records from the ORIGINAL Stratosphere binetflow files.

    NOT YET TESTED — the data on disk is the stripped dhoogla/Kaggle parquet
    (no StartTime/IP/ports), which this refuses with a clear message. This loader
    targets the full ``.binetflow`` (CSV) / full-schema parquet from
    stratosphereips.org/datasets-ctu13, which carries
    ``StartTime, Dur, Proto, SrcAddr, Sport, Dir, DstAddr, Dport, State, sTos,
    dTos, TotPkts, TotBytes, SrcBytes, Label``.

    Unit note: CTU-13 ``Dur`` is **seconds**; converted to microseconds here so it
    matches the CIC convention the windower assumes.

    Args:
        scenario: ``"all"`` or a scenario number/name (e.g. ``"9"`` or ``"9-Neris"``).
        raw_dir: Override the dataset root (default data/raw/CTU-13).
        max_rows: Row cap for dev.
        verbose: Print progress.

    Returns:
        Frame in source column names + tz-aware UTC ``timestamp``, ``dataset`` and
        per-scenario ``campaign_id``, plus derived ``bwd_bytes``.
    """
    from src.data.paths import raw_dataset_dir

    root = Path(raw_dir) if raw_dir is not None else raw_dataset_dir("ctu13")
    # Prefer the REAL binetflow (full schema). Only fall back to the stripped
    # parquet/csv variants if no true .binetflow is present (so the dhoogla
    # parquets on disk don't get mixed in once real data is extracted).
    files = sorted(root.rglob("*.binetflow"))  # rglob: extracted tar has nested folders
    if not files:
        files = sorted(root.rglob("*.binetflow.parquet")) + sorted(root.rglob("*.binetflow.csv"))
    if scenario != "all":
        key = str(scenario).lstrip("0")
        files = [f for f in files if _ctu13_scenario(f) == key]
    if not files:
        raise FileNotFoundError(f"No CTU-13 binetflow files matched scenario={scenario!r} under {root}")

    frames: list[pd.DataFrame] = []
    total = 0
    for path in files:
        if path.suffix == ".parquet":
            df = pd.read_parquet(path)
        else:
            df = pd.read_csv(path, nrows=max_rows)
        # Guard: reject the stripped Kaggle variant early with an actionable message.
        missing = [c for c in CTU13_REQUIRED_COLS if c not in df.columns]
        if missing:
            raise ValueError(
                f"{path.name} is missing {missing} — this looks like the stripped "
                f"dhoogla/Kaggle CTU-13 (flat-ML, no timestamp/IP/ports). Download the "
                f"ORIGINAL .binetflow from stratosphereips.org/datasets-ctu13 to forecast."
            )
        df["campaign_id"] = f"ctu13-{_ctu13_scenario(path)}"
        frames.append(df.iloc[:max_rows] if max_rows else df)  # per-file cap
        total += len(df)

    df = pd.concat(frames, ignore_index=True)
    df["timestamp"] = pd.to_datetime(df["StartTime"], errors="coerce")
    if getattr(df["timestamp"].dtype, "tz", None) is None:
        df["timestamp"] = df["timestamp"].dt.tz_localize(CAPTURE_TZ, ambiguous="NaT",
                                                          nonexistent="NaT").dt.tz_convert("UTC")
    df = df[df["timestamp"].notna()].copy()
    # Dur seconds -> microseconds (CIC convention the windower expects).
    if "Dur" in df.columns:
        df["Dur"] = pd.to_numeric(df["Dur"], errors="coerce").fillna(0.0) * _US_PER_S
    # Directional bytes: SrcBytes is source->dst; the rest is reverse.
    if "TotBytes" in df.columns and "SrcBytes" in df.columns:
        df["bwd_bytes"] = (pd.to_numeric(df["TotBytes"], errors="coerce")
                           - pd.to_numeric(df["SrcBytes"], errors="coerce")).clip(lower=0)
    df["dataset"] = "ctu13"
    df = df.sort_values(["campaign_id", "timestamp"], kind="mergesort").reset_index(drop=True)
    if verbose:
        rate = float(df["Label"].astype("string").str.contains("Botnet", case=False, na=False).mean())
        print(f"  [loader] ctu13 {scenario}: {len(df):,} rows | "
              f"{df['campaign_id'].nunique()} scenario(s) | botnet rate {rate:.1%}")
    return df


def write_parquet(frame: pd.DataFrame, path: Path) -> Path:
    """Write ``frame`` to ``path`` as parquet (pyarrow, snappy). Returns ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_parquet(path, engine="pyarrow", compression="snappy", index=False)
    return path


def read_parquet(path: Path, *, columns: Sequence[str] | None = None) -> pd.DataFrame:
    """Read a parquet artefact written by :func:`write_parquet`."""
    return pd.read_parquet(path, engine="pyarrow", columns=list(columns) if columns else None)


__all__ = [
    "TIMESTAMP_COLUMN",
    "LABEL_COLUMN",
    "RAW_TIMESTAMP_COLUMN",
    "NA_VALUES",
    "load_cicids2017",
    "load_cicids2018",
    "load_cicids2018_days",
    "load_dataset",
    "load_cicids2017",
    "load_unsw_nb15",
    "load_ctu13",
    "write_parquet",
    "read_parquet",
]
