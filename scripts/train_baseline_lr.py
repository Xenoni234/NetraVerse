"""End-to-end logistic-regression baseline on CIC-IDS2018.

Proves the pipeline works: load -> unify -> label -> split -> train -> evaluate,
with results written to ``results/lr_baseline.json``.

Usage::

    python scripts/train_baseline_lr.py --config configs/dev.yaml
    python scripts/train_baseline_lr.py --config configs/dev.yaml --days wed-14-02 fri-02-03
    python scripts/train_baseline_lr.py --config configs/dev.yaml --keep-dst-port
    python scripts/train_baseline_lr.py --synthetic          # no dataset needed

What this is and is not
-----------------------
This is a **flow-level detector**: one completed flow in, attack/benign out. It
is the smoke test for the data pipeline and the classical-ML bar for detection.

It is **not** the forecasting baseline. Warning lead time — the project's
headline metric (CLAUDE.md rule 3) — is structurally zero here, because a
completed flow carries no forecast horizon. The number this script prints must
not be used as the bar the world model has to beat; that bar comes from
``SequenceLogisticRegressionBaseline`` once windowing lands.

Expected F1 is roughly 0.75-0.85. Materially higher usually means a leaking
column survived; materially lower means the features or labels are broken.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.data import labeller, loaders, unified_schema  # noqa: E402
from src.data.paths import CICIDS2018_BASELINE_DAYS, CICIDS2018_DAYS  # noqa: E402
from src.eval import metrics as metrics_mod  # noqa: E402
from src.eval import splits as splits_mod  # noqa: E402
from src.models.baseline_lr import LogisticRegressionBaseline  # noqa: E402

DEFAULT_RESULTS_PATH = REPO_ROOT / "results" / "lr_baseline.json"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Logistic-regression baseline on CIC-IDS2018 (pipeline smoke test)"
    )
    parser.add_argument("--config", type=Path, default=REPO_ROOT / "configs" / "dev.yaml")
    parser.add_argument(
        "--days", nargs="*", default=None,
        help=f"CIC-IDS2018 day keys. Default: {' '.join(CICIDS2018_BASELINE_DAYS)}",
    )
    parser.add_argument("--max-rows-per-day", type=int, default=None)
    parser.add_argument("--raw-dir", type=Path, default=None, help="Override the dataset root")
    parser.add_argument(
        "--keep-dst-port", action="store_true",
        help="Keep dst_port/protocol. Inflates F1 - see unified_schema docstring.",
    )
    parser.add_argument("--threshold", type=float, default=None,
                        help="Fixed decision threshold. Default: selected on val.")
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS_PATH)
    parser.add_argument("--synthetic", action="store_true",
                        help="Run on generated data instead of the real dataset.")
    parser.add_argument("--seed", type=int, default=1337)
    return parser.parse_args(argv)


def load_config(path: Path) -> dict[str, Any]:
    """Load a YAML config, tolerating its absence."""
    if not path.exists():
        print(f"[config] {path} not found - using built-in defaults")
        return {}
    try:
        from omegaconf import OmegaConf

        cfg = OmegaConf.to_container(OmegaConf.load(path), resolve=True)
        print(f"[config] loaded {path}")
        return dict(cfg) if isinstance(cfg, dict) else {}
    except ImportError:
        import yaml

        with path.open(encoding="utf-8") as fh:
            print(f"[config] loaded {path} (pyyaml)")
            return yaml.safe_load(fh) or {}


def make_synthetic_frame(n_rows: int = 60_000, seed: int = 1337):
    """Generate a CIC-IDS2018-shaped frame for testing without the dataset.

    Deliberately crude: benign traffic plus three attack blocks placed *late* in
    the timeline, with attack rows given a shifted distribution on a handful of
    features. It exercises every code path — loading is skipped, but unification,
    labelling, splitting, training and evaluation all run for real.

    The resulting F1 is meaningless as a research result. It only proves the
    plumbing is connected.
    """
    import numpy as np
    import pandas as pd

    rng = np.random.default_rng(seed)
    start = pd.Timestamp("2018-02-14 08:00:00", tz="UTC")
    ts = start + pd.to_timedelta(np.arange(n_rows) * 0.5, unit="s")

    frame = pd.DataFrame(
        {
            "Timestamp": ts,
            "Dst Port": rng.integers(1, 65535, n_rows).astype("float32"),
            "Protocol": rng.choice([6, 17, 1], n_rows).astype("float32"),
            "Flow Duration": rng.lognormal(10, 2, n_rows).astype("float32"),
            "Flow Pkts/s": rng.lognormal(2, 1.5, n_rows).astype("float32"),
            "Flow Byts/s": rng.lognormal(6, 2, n_rows).astype("float32"),
            "Down/Up Ratio": rng.lognormal(0, 0.6, n_rows).astype("float32"),
            "Tot Fwd Pkts": rng.poisson(8, n_rows).astype("float32"),
            "Tot Bwd Pkts": rng.poisson(7, n_rows).astype("float32"),
            "TotLen Fwd Pkts": rng.lognormal(6, 1.5, n_rows).astype("float32"),
            "TotLen Bwd Pkts": rng.lognormal(6, 1.5, n_rows).astype("float32"),
            "Flow IAT Mean": rng.lognormal(8, 2, n_rows).astype("float32"),
            "Flow IAT Std": rng.lognormal(8, 2, n_rows).astype("float32"),
            "Flow IAT Max": rng.lognormal(10, 2, n_rows).astype("float32"),
            "SYN Flag Cnt": rng.binomial(1, 0.3, n_rows).astype("float32"),
            "ACK Flag Cnt": rng.binomial(1, 0.7, n_rows).astype("float32"),
            "FIN Flag Cnt": rng.binomial(1, 0.2, n_rows).astype("float32"),
            "RST Flag Cnt": rng.binomial(1, 0.05, n_rows).astype("float32"),
            "PSH Flag Cnt": rng.binomial(1, 0.4, n_rows).astype("float32"),
            "URG Flag Cnt": rng.binomial(1, 0.01, n_rows).astype("float32"),
            "Pkt Len Mean": rng.lognormal(5, 1, n_rows).astype("float32"),
            "Pkt Len Std": rng.lognormal(4, 1, n_rows).astype("float32"),
            "Label": "Benign",
        }
    )

    # Three attack episodes, each a contiguous block, all in the later half.
    # Positional (iloc) indexing throughout: .loc with an integer slice is
    # label-based and inclusive of the endpoint, which silently selects one
    # extra row and desynchronises the label block from the feature block.
    for label, lo, hi in [
        ("SSH-Bruteforce", 0.50, 0.58),
        ("DoS attacks-GoldenEye", 0.68, 0.76),
        ("Bot", 0.86, 0.93),
    ]:
        lo_i, hi_i = int(n_rows * lo), int(n_rows * hi)
        n = hi_i - lo_i
        frame.iloc[lo_i:hi_i, frame.columns.get_loc("Label")] = label
        for col, values in (
            ("Flow Pkts/s", rng.lognormal(5, 0.8, n)),
            ("SYN Flag Cnt", rng.binomial(1, 0.92, n)),
            ("RST Flag Cnt", rng.binomial(1, 0.55, n)),
            ("Flow IAT Mean", rng.lognormal(4, 1.0, n)),
        ):
            frame.iloc[lo_i:hi_i, frame.columns.get_loc(col)] = values.astype("float32")

    # Genuine non-finite values, as the real CSVs contain.
    bad = rng.choice(n_rows, size=max(2, n_rows // 500), replace=False)
    frame.iloc[bad, frame.columns.get_loc("Flow Byts/s")] = np.inf
    frame.iloc[bad[: len(bad) // 2], frame.columns.get_loc("Flow Pkts/s")] = np.nan

    frame["timestamp"] = frame["Timestamp"]
    frame["campaign_id"] = "synthetic-2018-02-14"
    frame["dataset"] = "cicids2018"
    return frame


def main(argv: Sequence[str] | None = None) -> int:
    """Run the baseline end to end."""
    args = parse_args(argv)
    config = load_config(args.config)
    started = time.perf_counter()

    print("=" * 78)
    print("CIC-IDS2018 LOGISTIC REGRESSION BASELINE  (flow-level detection)")
    print("=" * 78)

    # ---- 1. load ------------------------------------------------------- #
    print("\n[1/6] LOADING")
    if args.synthetic:
        print("  SYNTHETIC MODE - generated data, not the real dataset.")
        print("  Numbers below prove the pipeline runs. They are not results.")
        raw = make_synthetic_frame(seed=args.seed)
        days = ["synthetic"]
    else:
        days = list(args.days) if args.days else list(CICIDS2018_BASELINE_DAYS)
        unknown = [d for d in days if d not in CICIDS2018_DAYS]
        if unknown:
            print(f"  ERROR: unknown day key(s) {unknown}")
            print(f"  Valid keys: {sorted(CICIDS2018_DAYS)}")
            return 2
        print(f"  days: {', '.join(f'{d} ({CICIDS2018_DAYS[d]})' for d in days)}")
        max_rows = args.max_rows_per_day or (config.get("data", {}) or {}).get("max_rows_per_file")
        try:
            raw = loaders.load_cicids2018_days(
                days, max_rows_per_day=max_rows, raw_dir=args.raw_dir, verbose=True
            )
        except FileNotFoundError as exc:
            print(f"\n  DATASET NOT FOUND\n  {exc}\n")
            print("  Fix one of:")
            print("    - place the CSVs under data/raw/CIC-IDS2018/")
            print("    - pass --raw-dir <path to the CSV folder>")
            print("    - set SIH26153_DATA_ROOT to a different data root")
            print("    - run with --synthetic to test the pipeline without data")
            return 1
    print(f"  loaded {len(raw):,} rows x {len(raw.columns)} columns")

    # ---- 2. unify ------------------------------------------------------ #
    print("\n[2/6] UNIFYING SCHEMA")
    unified = unified_schema.to_unified(raw, "cicids2018")
    print(f"  mapped to {len(unified.columns)} unified columns")
    print(f"  features: {unified_schema.N_FLOW_FEATURES} flow-level")

    # ---- 3. label ------------------------------------------------------ #
    print("\n[3/6] LABELLING")
    labelled = labeller.label_frame(unified, dataset="cicids2018", verbose=True)

    # ---- 4. split ------------------------------------------------------ #
    print("\n[4/6] CHRONOLOGICAL SPLIT  (60/20/20, never shuffled)")
    split_frames = splits_mod.chronological_split(labelled, 0.60, 0.20, 0.20, verbose=True)
    splits_mod.assert_no_leakage(split_frames)
    print("  leakage check: PASSED")

    # ---- 5. train ------------------------------------------------------ #
    print("\n[5/6] TRAINING")
    feature_cols = [
        c for c in unified_schema.model_feature_columns(drop_dst_port=not args.keep_dst_port)
        if c in labelled.columns
    ]
    dropped = [c for c in labelled.columns if c not in feature_cols]
    print(f"  using {len(feature_cols)} features")
    print(f"  dropped {len(dropped)}: {', '.join(dropped)}")
    if args.keep_dst_port:
        print("  WARNING: --keep-dst-port is on; expect inflated F1 (near-label).")

    prepared, clean_reports = {}, {}
    for name, frame in split_frames.items():
        X, report = unified_schema.clean_features(frame[feature_cols])
        unified_schema.validate_features(X)
        prepared[name] = (X.to_numpy(), frame[labeller.BINARY_LABEL].to_numpy())
        clean_reports[name] = report
        print(
            f"  {name:<5} X={X.shape}  "
            f"non-finite cells imputed: {report['n_nonfinite']:,} "
            f"({report['imputed_fraction']:.4%})"
        )

    model = LogisticRegressionBaseline(random_state=args.seed)
    fit_started = time.perf_counter()
    model.fit(*prepared["train"], feature_names=feature_cols)
    print(f"  fitted in {time.perf_counter() - fit_started:,.1f}s")

    # ---- 6. evaluate --------------------------------------------------- #
    print("\n[6/6] EVALUATING")
    val_prob = model.predict_proba(prepared["val"][0])
    if args.threshold is not None:
        threshold = args.threshold
        print(f"  threshold: {threshold:.4f} (fixed via --threshold)")
    else:
        threshold = metrics_mod.select_threshold(prepared["val"][1], val_prob, objective="f1")
        print(f"  threshold: {threshold:.4f} (selected on VAL, never on test)")

    results: dict[str, Any] = {}
    for name in ("train", "val", "test"):
        X, y = prepared[name]
        prob = model.predict_proba(X)
        pred = (prob >= threshold).astype(int)
        results[name] = metrics_mod.compute_all_metrics(y, pred, prob, threshold=threshold)

    print()
    print(metrics_mod.format_metrics_table(results))
    print("\n  TEST operating points:")
    print(metrics_mod.format_operating_points(results["test"]))

    print("\n  Top coefficients (signed, |value| descending):")
    for feature, coef in model.top_coefficients(10):
        print(f"    {feature:<24} {coef:+.4f}")

    # ---- interpretation ------------------------------------------------ #
    test_f1 = results["test"]["f1"]
    print("\n" + "=" * 78)
    if args.synthetic:
        verdict = "SYNTHETIC - pipeline works; the number itself means nothing."
    elif test_f1 > 0.92:
        verdict = f"F1={test_f1:.3f} ABOVE expected range - suspect leakage."
    elif test_f1 < 0.60:
        verdict = f"F1={test_f1:.3f} BELOW expected range - suspect broken features/labels."
    else:
        verdict = f"F1={test_f1:.3f} in the expected 0.75-0.85 band (or close)."
    print(f"  {verdict}")
    print("  NOTE: flow-level DETECTION. Not the forecasting bar; lead time is 0 here.")
    print("=" * 78)

    # ---- write results ------------------------------------------------- #
    payload = {
        "run": {
            "script": "scripts/train_baseline_lr.py",
            "model": "LogisticRegressionBaseline (flow-level detection)",
            "task": "binary attack detection on completed flows",
            "not_comparable_to": "forecasting baselines; lead time is structurally 0",
            "synthetic": bool(args.synthetic),
            "days": days,
            "seed": args.seed,
            "elapsed_seconds": round(time.perf_counter() - started, 2),
            "schema_version": unified_schema.SCHEMA_VERSION,
        },
        "data": {
            "n_rows": int(len(labelled)),
            "attack_rate": float(labelled[labeller.BINARY_LABEL].mean()),
            "label_summary": labeller.label_summary(labelled),
            "split_sizes": {k: int(len(v)) for k, v in split_frames.items()},
        },
        "features": {
            "used": feature_cols,
            "n_used": len(feature_cols),
            "dropped": dropped,
            "dst_port_kept": bool(args.keep_dst_port),
            "cleaning": clean_reports,
        },
        "threshold": float(threshold),
        "metrics": results,
        "top_coefficients": [
            {"feature": f, "coefficient": c} for f, c in model.top_coefficients(20)
        ],
        "verdict": verdict,
    }

    args.results.parent.mkdir(parents=True, exist_ok=True)
    args.results.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    print(f"\n  results -> {args.results}")
    print(f"  total elapsed: {time.perf_counter() - started:,.1f}s\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
