"""CLI feature extraction — raw datasets to the windowed parquet cache.

Run this once per dataset before any training.

Usage::

    python scripts/extract_features.py --config configs/dev.yaml
    python scripts/extract_features.py --config configs/train.yaml
    python scripts/extract_features.py --config configs/train.yaml --dataset cicids2017
    python scripts/extract_features.py --config configs/train.yaml --force   # rebuild

Pipeline per dataset
--------------------
1. ``loaders.load_dataset``            raw CSV / binetflow -> frame
2. ``unified_schema.to_unified``       -> the LOCKED unified flow schema
3. ``windowing.build_windows``         -> per-entity 30 s windows
4. ``features.extractor``              -> the flow features
5. ``features.packet_features``        -> optional PCAP enrichment
6. ``features.baselines``              -> host and peer-group z-scores
7. ``features.trajectory``             -> derivative features
8. ``labeller.label_windows``          -> binary / stage / distance labels
9. write ``data/processed/<dataset>/windows.parquet``

This is the slow step — hours for the full CIC-IDS2018 with packet features. It
is also the most cacheable, hence a standalone script rather than something
buried inside training. Resume support matters: a crash four datasets in should
not mean starting over.

TODO
----
* [ ] Implement ``parse_args`` and ``main``.
* [ ] Implement ``extract_dataset`` with per-campaign sharding.
* [ ] Skip campaigns whose output already exists unless ``--force``.
* [ ] Show a ``tqdm`` progress bar per dataset and per campaign.
* [ ] Validate the output against ``unified_schema.validate_features`` and fail
      on the first bad shard rather than after the whole run.
* [ ] Print the label summary per dataset — catching a 0 % attack rate here is
      an order of magnitude cheaper than catching it after training.
* [ ] Stamp ``SCHEMA_VERSION`` into the cache and invalidate on mismatch.
* [ ] Optional ``--jobs N`` for parallel per-campaign extraction.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Mapping, Sequence


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments.

    Namespace: ``config`` (Path), ``dataset`` (str | None — all when omitted),
    ``force`` (bool), ``jobs`` (int), ``dry_run`` (bool), plus dotlist
    ``overrides``.
    """
    raise NotImplementedError("TODO: argparse mirroring the other scripts")


def extract_dataset(
    dataset: str, config: Mapping[str, Any], *, force: bool = False
) -> Path:
    """Run the full extraction pipeline for one dataset.

    Args:
        dataset: Dataset name from ``paths.SUPPORTED_DATASETS``.
        config: Resolved config.
        force: Rebuild even when a valid cache exists.

    Returns:
        Path to the written parquet cache.
    """
    raise NotImplementedError("TODO: the nine pipeline steps, sharded per campaign")


def check_prerequisites(config: Mapping[str, Any]) -> Mapping[str, bool]:
    """Report what is available before doing any work.

    Checks which datasets are present (``paths.verify_raw_layout``) and whether
    ``tshark`` is installed when packet features are enabled. Fails fast with an
    actionable message rather than crashing forty minutes in.
    """
    raise NotImplementedError("TODO: dataset presence + tshark availability, clear messages")


def summarise_cache(path: Path) -> Mapping[str, Any]:
    """Print a summary of a written cache: rows, entities, date range, labels.

    Read this every time. A 0 % attack rate, a single entity, or a one-hour date
    range all mean the extraction went wrong, and all are invisible later.
    """
    raise NotImplementedError("TODO: read parquet metadata + labeller.label_summary")


def main(argv: Sequence[str] | None = None) -> int:
    """Run feature extraction. Returns a process exit code."""
    raise NotImplementedError("TODO: parse, check prerequisites, extract each, summarise")


if __name__ == "__main__":
    raise SystemExit(main())
