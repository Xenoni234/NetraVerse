"""Convert a Phase 6 synthetic window parquet into a SequenceBatch cache."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.data import windowing as W


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--windows", type=Path, default=Path("data/interim/phase6_synthetic/synthetic_windows.parquet"))
    parser.add_argument("--output", type=Path, default=Path("data/interim/phase6_synthetic/train.npz"))
    parser.add_argument("--history-policy", choices=("strict", "masked"), default="masked")
    parser.add_argument("--horizons", type=int, nargs="+", default=[1, 2, 4],
                        help="forecast windows; 60 windows equals 30 minutes")
    args = parser.parse_args(argv)
    frame = pd.read_parquet(args.windows)
    horizons = tuple(sorted(set(args.horizons)))
    batch = W.build_sequences(frame, W.WindowConfig(horizons=horizons,
                                                    history_policy=args.history_policy), target="onset")
    W.save_sequences(batch, args.output)
    print(f"[phase6] sequences={len(batch.x):,} positives={batch.y_risk.sum(axis=0).tolist()}")
    print(f"[phase6] saved {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
