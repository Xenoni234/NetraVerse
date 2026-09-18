"""Central path constants for every dataset and artefact directory.

Single source of truth for *where things live*. No other module may hard-code a
filesystem location; import from here instead. Everything is a
:class:`pathlib.Path` — never a string — so the code behaves the same on
Windows and POSIX.

Layout assumed under ``DATA_ROOT`` (nothing here is committed; see .gitignore)::

    data/
      raw/
        cicids2017/    MachineLearningCSV/*.csv, PCAPs/*.pcap
        cicids2018/    *.csv
        UNSW-NB-15/unsw_nb15/  UNSW-NB15_{1..4}.csv, NUSW-NB15_features.csv
        ctu13/         scenario-*/  (*.binetflow, *.pcap)
      interim/         scratch, safe to delete
      processed/       unified parquet windows (the model's actual input)
    models/            checkpoints
    reports/           metrics JSON, plots, the results table

Override the root without editing code by setting the ``SIH26153_DATA_ROOT``
environment variable, or by passing ``paths.*`` keys in a config YAML.

TODO
----
* [ ] Implement ``resolve_roots`` so config ``paths.*`` overrides actually apply.
* [ ] Implement ``ensure_dirs`` (called once at the start of every CLI script).
* [ ] Implement ``raw_dataset_dir`` / ``processed_path`` / ``checkpoint_path``.
* [ ] Add ``verify_raw_layout`` that reports which datasets are actually present,
      so a teammate with only CIC-IDS2017 downloaded gets a clear message.
* [ ] Decide whether the parquet cache key should include SCHEMA_VERSION.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final, Literal, Mapping

# --------------------------------------------------------------------------- #
# Roots
# --------------------------------------------------------------------------- #

#: Repository root — this file is ``<repo>/src/data/paths.py``.
REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]

#: Data root; override with the ``SIH26153_DATA_ROOT`` environment variable.
DATA_ROOT: Final[Path] = Path(os.environ.get("SIH26153_DATA_ROOT", REPO_ROOT / "data"))

RAW_DIR: Final[Path] = DATA_ROOT / "raw"
INTERIM_DIR: Final[Path] = DATA_ROOT / "interim"
PROCESSED_DIR: Final[Path] = DATA_ROOT / "processed"

MODELS_DIR: Final[Path] = REPO_ROOT / "models"
REPORTS_DIR: Final[Path] = REPO_ROOT / "reports"
CONFIGS_DIR: Final[Path] = REPO_ROOT / "configs"

# --------------------------------------------------------------------------- #
# Datasets
# --------------------------------------------------------------------------- #

DatasetName = Literal[
    "cicids2017",
    "cicids2018",
    "cic_iot2023",
    "unsw_nb15",
    "ctu13",
    "darpa_optc",
    "lanl",
]

SUPPORTED_DATASETS: Final[tuple[DatasetName, ...]] = (
    "cicids2018",   # PRIMARY training set
    "cicids2017",
    "cic_iot2023",
    "unsw_nb15",    # cross-dataset test target
    "ctu13",
    "darpa_optc",   # stretch
    "lanl",         # stretch
)

#: Per-dataset raw subdirectory, relative to :data:`RAW_DIR`.
RAW_SUBDIR: Final[Mapping[DatasetName, str]] = {
    "cicids2017": "CIC-IDS2017",
    "cicids2018": "CIC-IDS2018",
    "cic_iot2023": "CIC-IoT-2023",
    "unsw_nb15": "UNSW-NB-15/unsw_nb15",
    "ctu13": "CTU-13",
    "darpa_optc": "DARPA-OpTC",
    "lanl": "LANL",
}

#: Glob pattern that finds the flow-record files of each dataset.
RAW_FLOW_GLOB: Final[Mapping[DatasetName, str]] = {
    "cicids2017": "TrafficLabelling/*.csv",  # TrafficLabelling has Timestamp+Source IP; the
    #                                        # MachineLearningCVE copy has neither -> unusable for forecasting
    "cicids2018": "csv_features/*.csv",
    "cic_iot2023": "Merged_CSV/*.csv",
    "unsw_nb15": "UNSW-NB15_[1-4].csv",
    "ctu13": "*.binetflow.parquet",
    "darpa_optc": "*.tar",
    "lanl": "*.txt.gz",
}

#: Glob pattern that finds the packet captures of each dataset (may be empty).
RAW_PCAP_GLOB: Final[Mapping[DatasetName, str]] = {
    "cicids2017": "**/*.pcap",
    "cicids2018": "**/*.pcap",
    "cic_iot2023": "**/*.pcap",
    "unsw_nb15": "**/*.pcap",
    "ctu13": "**/*.pcap",
    "darpa_optc": "**/*.pcap",
    "lanl": "**/*.pcap",
}


# --------------------------------------------------------------------------- #
# CIC-IDS2018 capture days
# --------------------------------------------------------------------------- #

#: Short day key -> the date portion of the CSV filename.
#:
#: The CSE-CIC-IDS2018 CSVs ship as one file per capture day. Filenames vary by
#: mirror: the Kaggle release uses ``<date>_TrafficForML_CICFlowMeter.csv`` while
#: others use just ``<date>.csv``. :func:`cicids2018_csv` globs for either, so
#: only the date string needs recording here.
CICIDS2018_DAYS: Final[Mapping[str, str]] = {
    "wed-14-02": "Wednesday-14-02-2018",   # FTP-BruteForce, SSH-Bruteforce
    "thu-15-02": "Thursday-15-02-2018",    # DoS GoldenEye, DoS Slowloris
    "fri-16-02": "Friday-16-02-2018",      # DoS Hulk, DoS SlowHTTPTest
    "tue-20-02": "Thuesday-20-02-2018",    # [sic] misspelled on disk; DDoS LOIC-HTTP; 3.9GB; the ONE 2018 day with IPs
    "wed-21-02": "Wednesday-21-02-2018",   # DDOS HOIC, DDOS LOIC-UDP
    "thu-22-02": "Thursday-22-02-2018",    # Brute Force Web/XSS, SQL Injection
    "fri-23-02": "Friday-23-02-2018",      # Brute Force Web/XSS, SQL Injection
    "wed-28-02": "Wednesday-28-02-2018",   # Infilteration
    "thu-01-03": "Thursday-01-03-2018",    # Infilteration (held-out family)
    "fri-02-03": "Friday-02-03-2018",      # Bot
}

#: The three days used by the logistic-regression smoke baseline. Chosen for
#: label variety rather than size: brute force (INITIAL_ACCESS), DoS (masked),
#: and Bot (C2) - three stages, three traffic shapes.
CICIDS2018_BASELINE_DAYS: Final[tuple[str, ...]] = ("wed-14-02", "thu-15-02", "fri-02-03")

#: Filename patterns tried, in order, when locating a day's CSV.
CICIDS2018_FILE_PATTERNS: Final[tuple[str, ...]] = (
    "{date}_TrafficForML_CICFlowMeter.csv",
    "{date}.csv",
    "*{date}*.csv",
)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def resolve_roots(overrides: Mapping[str, str | Path | None] | None = None) -> dict[str, Path]:
    """Return the effective root directories, applying config overrides.

    Args:
        overrides: Mapping from root name (``data_root``, ``raw_dir``,
            ``processed_dir``, ``models_dir``, ``reports_dir``) to a replacement
            path. ``None`` values mean "keep the default".

    Returns:
        Mapping of root name to resolved :class:`~pathlib.Path`.
    """
    roots: dict[str, Path] = {
        "data_root": DATA_ROOT,
        "raw_dir": RAW_DIR,
        "interim_dir": INTERIM_DIR,
        "processed_dir": PROCESSED_DIR,
        "models_dir": MODELS_DIR,
        "reports_dir": REPORTS_DIR,
    }
    if not overrides:
        return roots
    for key, value in overrides.items():
        if value is None or key not in roots:
            continue
        roots[key] = Path(value).expanduser().resolve()
    return roots


def ensure_dirs(*paths: Path) -> None:
    """Create each directory (and parents) if missing. Idempotent.

    Called once at the top of every CLI entry point so downstream writes never
    fail on a missing directory.
    """
    for path in paths:
        Path(path).mkdir(parents=True, exist_ok=True)


def raw_dataset_dir(dataset: DatasetName) -> Path:
    """Return the raw directory for ``dataset``."""
    if dataset not in RAW_SUBDIR:
        raise KeyError(f"Unknown dataset {dataset!r}; known: {SUPPORTED_DATASETS}")
    return RAW_DIR / RAW_SUBDIR[dataset]


def cicids2018_csv(day: str, *, raw_dir: Path | None = None) -> Path:
    """Locate the CSV for one CIC-IDS2018 capture day.

    Args:
        day: Either a short key from :data:`CICIDS2018_DAYS` (``"thu-15-02"``)
            or the full date string (``"Thursday-15-02-2018"``).
        raw_dir: Override the search root; defaults to the dataset raw dir.

    Returns:
        Path to the CSV.

    Raises:
        KeyError: if ``day`` is not a recognised key or date.
        FileNotFoundError: if no matching file exists, naming what *is* present.
    """
    date = CICIDS2018_DAYS.get(day, day)
    if date not in set(CICIDS2018_DAYS.values()):
        raise KeyError(
            f"Unknown CIC-IDS2018 day {day!r}. Use a key from CICIDS2018_DAYS "
            f"({sorted(CICIDS2018_DAYS)}) or a full date string."
        )
    search_root = Path(raw_dir) if raw_dir is not None else raw_dataset_dir("cicids2018")
    for pattern in CICIDS2018_FILE_PATTERNS:
        matches = sorted(search_root.rglob(pattern.format(date=date)))
        if matches:
            return matches[0]
    present = sorted(q.name for q in search_root.rglob("*.csv"))[:10] if search_root.exists() else []
    raise FileNotFoundError(
        f"No CSV for CIC-IDS2018 day {date!r} under {search_root}. "
        f"Expected one of {[q.format(date=date) for q in CICIDS2018_FILE_PATTERNS]}. "
        f"Directory exists: {search_root.exists()}. "
        f"CSVs found there: {present or 'none'}"
    )


def list_raw_flow_files(dataset: DatasetName) -> list[Path]:
    """Return every raw flow-record file for ``dataset``, sorted for determinism."""
    root = raw_dataset_dir(dataset)
    if not root.exists():
        return []
    return sorted(root.glob(RAW_FLOW_GLOB[dataset]))


def list_raw_pcap_files(dataset: DatasetName) -> list[Path]:
    """Return every raw PCAP for ``dataset``, sorted. May be empty."""
    root = raw_dataset_dir(dataset)
    if not root.exists():
        return []
    return sorted(root.glob(RAW_PCAP_GLOB[dataset]))


def processed_path(dataset: DatasetName, stage: str, campaign_id: str | None = None) -> Path:
    """Return the parquet cache path for a processed artefact.

    Args:
        dataset: Source dataset.
        stage: Pipeline stage, e.g. ``"unified"``, ``"labelled"``, ``"windows"``.
        campaign_id: Optional campaign to shard by; ``None`` means whole-dataset.
    """
    name = stage if campaign_id is None else f"{stage}_{campaign_id}"
    return PROCESSED_DIR / dataset / f"{name}.parquet"


def checkpoint_path(run_name: str, tag: str = "best") -> Path:
    """Return the checkpoint path for ``run_name`` (``models/<run>/<tag>.ckpt``)."""
    return MODELS_DIR / run_name / f"{tag}.ckpt"


def report_dir(run_name: str) -> Path:
    """Return the report output directory for ``run_name``."""
    return REPORTS_DIR / run_name


def verify_raw_layout(datasets: tuple[DatasetName, ...] = SUPPORTED_DATASETS) -> dict[str, bool]:
    """Report which of ``datasets`` are actually present on disk.

    Returns:
        Mapping of dataset name to whether at least one raw flow file was found.
    """
    return {name: bool(list_raw_flow_files(name)) for name in datasets}


__all__ = [
    "DatasetName",
    "SUPPORTED_DATASETS",
    "REPO_ROOT",
    "DATA_ROOT",
    "RAW_DIR",
    "INTERIM_DIR",
    "PROCESSED_DIR",
    "MODELS_DIR",
    "REPORTS_DIR",
    "CONFIGS_DIR",
    "RAW_SUBDIR",
    "RAW_FLOW_GLOB",
    "RAW_PCAP_GLOB",
    "CICIDS2018_DAYS",
    "CICIDS2018_BASELINE_DAYS",
    "CICIDS2018_FILE_PATTERNS",
    "cicids2018_csv",
    "resolve_roots",
    "ensure_dirs",
    "raw_dataset_dir",
    "list_raw_flow_files",
    "list_raw_pcap_files",
    "processed_path",
    "checkpoint_path",
    "report_dir",
    "verify_raw_layout",
]
