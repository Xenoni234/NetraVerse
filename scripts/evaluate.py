"""CLI evaluation entry point.

Usage::

    # while iterating - validation split
    python scripts/evaluate.py --config configs/eval.yaml --checkpoint models/best.ckpt

    # the one run that produces reported numbers
    python scripts/evaluate.py --config configs/eval.yaml --checkpoint models/best.ckpt eval.split=test

    # skip the expensive retraining ablations
    python scripts/evaluate.py --config configs/eval.yaml --checkpoint models/best.ckpt --no-ablations

Produces, under ``reports/<name>/``:

===================== =====================================================
``metrics.json``      machine-readable metrics plus provenance
``report.md``         the human-readable report with targets marked pass/fail
``predictions.parquet`` per-window predictions (also the demo's replay data)
``plots/``            lead-time histogram, risk timelines, confusion matrix
===================== =====================================================

**The test split is touched once.** The default config uses ``eval.split: val``.
Running on test prints a prominent warning and stamps the report metadata, so
nobody later wonders which numbers came from where.

TODO
----
* [ ] Implement ``parse_args`` and ``main``.
* [ ] Warn loudly (and record it) when ``eval.split == "test"``.
* [ ] Verify the checkpoint's schema version matches the running code.
* [ ] Print the summary line to stdout so CI logs carry the headline numbers.
* [ ] Exit non-zero when a DESIGN.md success criterion is missed, so a
      regression is visible rather than buried in a report nobody opens.
* [ ] Add ``--demo-bundle`` to also write the precomputed SHAP cache and
      trajectory library the dashboard needs.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Mapping, Sequence


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments.

    Namespace: ``config`` (Path), ``checkpoint`` (Path), ``output_dir``
    (Path | None), ``no_baselines`` / ``no_ablations`` / ``demo_bundle`` (bool),
    and trailing dotlist ``overrides``.
    """
    raise NotImplementedError("TODO: argparse mirroring scripts/train.py")


def load_config(config_path: Path, overrides: Sequence[str] = ()) -> Mapping[str, Any]:
    """Load ``configs/eval.yaml`` and apply dotlist overrides.

    Also checks the LOCKED window/labelling blocks against the checkpoint's
    stored config — evaluating a 30 s-window model with a 60 s-window pipeline
    produces numbers that look plausible and mean nothing.
    """
    raise NotImplementedError("TODO: OmegaConf load/merge + LOCKED consistency check")


def warn_if_test_split(config: Mapping[str, Any]) -> None:
    """Print a prominent warning when evaluating on test, and record it."""
    raise NotImplementedError("TODO: banner warning plus a provenance flag")


def check_success_criteria(report: Any, config: Mapping[str, Any]) -> bool:
    """Compare the report against the DESIGN.md section 6 targets.

    Returns:
        True when every target is met. The process exits non-zero otherwise, so
        a regression surfaces instead of sitting unread in a report.
    """
    raise NotImplementedError("TODO: per-metric target comparison, print a pass/fail table")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the evaluation. Returns a process exit code."""
    raise NotImplementedError("TODO: parse, load, evaluate, write report, check criteria")


if __name__ == "__main__":
    raise SystemExit(main())
