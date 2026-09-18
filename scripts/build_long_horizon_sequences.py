"""Build strict, clock-correct sequences for the 30-minute forecast experiment."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.data import windowing as W
from src.eval.splits import SplitConfig, chronological_split


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--windows", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--horizons", type=int, nargs="+", default=[1, 2, 4, 8, 16, 30, 60])
    parser.add_argument("--synthetic", action="store_true")
    args = parser.parse_args(argv)
    horizons = tuple(sorted(set(args.horizons)))
    frame = pd.read_parquet(args.windows)
    if args.synthetic:
        parts = {"train": frame, "val": frame, "test": frame}
    else:
        parts = chronological_split(frame, config=SplitConfig(time_col="window_start"), verbose=False)
    cfg = W.WindowConfig(horizons=horizons, history_policy="strict")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, part in parts.items():
        batch = W.build_sequences(part, cfg, target="onset")
        path = args.output_dir / f"{name}.npz"
        W.save_sequences(batch, path)
        print(f"[long] {name}: sequences={len(batch.x):,} positives={batch.y_risk.sum(0).tolist()} -> {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
