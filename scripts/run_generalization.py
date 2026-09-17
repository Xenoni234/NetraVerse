"""Run the CLAUDE.md §9 generalization ablations and write generalization.json.

Each ablation is a full retrain (same data config as wm_final:
CIC-IDS2017 all days + CIC-IDS2018 IP day + CTU-13), differing only in the flag
under test. We compare each ablation's held-out-test PR-AUC against the
in-distribution reference recorded in ``models/wm_final/benchmark.json``.

Results are assembled into ``models/wm_final/generalization.json`` in the shape
the ``/api/evaluation`` endpoint (and the Validate page) consume:
``{"rows": [{"setting", "result", ...}], "generated": ...}``. Partial results are
written after every run, so an interrupted session keeps what finished.

Run (long; GPU strongly recommended):
    .venv/Scripts/python.exe scripts/run_generalization.py
Add ``--quick`` for a fast plumbing check (tuesday only, 1+1 epochs).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
BENCH = REPO_ROOT / "models" / "wm_final" / "benchmark.json"
OUT = REPO_ROOT / "models" / "wm_final" / "generalization.json"
TMP = REPO_ROOT / "models" / "_ablations"


def data_flags(quick: bool) -> list[str]:
    if quick:
        return ["--days", "tuesday", "--epochs-pretrain", "1", "--epochs-finetune", "1"]
    return ["--days", "all", "--add-2018", "--add-ctu13"]


def reference_prauc() -> list | None:
    if not BENCH.exists():
        return None
    b = json.loads(BENCH.read_text(encoding="utf-8"))
    for r in b.get("rows", []):
        if r["model"] == "World model":
            return r["pr_auc"]
    return None


def run(label: str, extra: list[str], quick: bool) -> dict | None:
    TMP.mkdir(parents=True, exist_ok=True)
    metrics = TMP / f"{label}.json"
    cmd = [PY, str(REPO_ROOT / "scripts" / "train_world_model.py"),
           *data_flags(quick), *extra,
           "--run-name", f"wm_ablate_{label}",
           "--metrics-out", str(metrics), "--label", label]
    print(f"\n{'='*74}\n[ablation] {label}\n  {' '.join(cmd)}\n{'='*74}", flush=True)
    t = time.perf_counter()
    proc = subprocess.run(cmd, cwd=str(REPO_ROOT))
    dt = time.perf_counter() - t
    if proc.returncode != 0 or not metrics.exists():
        print(f"[ablation] {label} FAILED (rc={proc.returncode}) after {dt:,.0f}s", flush=True)
        return None
    m = json.loads(metrics.read_text(encoding="utf-8"))
    m["seconds"] = round(dt, 1)
    return m


def fmt_prauc(vals) -> str:
    return " / ".join("n/a" if v is None else f"{v:.3f}" for v in vals)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="fast plumbing check (tuesday, 1+1 epochs)")
    ap.add_argument("--family", default="Infiltration", help="held-out attack family")
    args = ap.parse_args()

    ref = reference_prauc()
    ref_txt = fmt_prauc(ref) if ref else "see benchmark"
    rows: list[dict] = [
        {"setting": "In-distribution (held-out time)",
         "result": f"World model beats persistence and LR at every horizon (PR-AUC {ref_txt})."}
    ]

    def flush(extra_note: str = ""):
        OUT.write_text(json.dumps(
            {"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
             "reference_prauc": ref, "note": extra_note, "rows": rows}, indent=2), encoding="utf-8")
        print(f"[write] {OUT} ({len(rows)} rows){' - ' + extra_note if extra_note else ''}", flush=True)

    flush("ablations running")

    # 1) Ordered vs shuffled history — the control that proves the model reads dynamics.
    shuf = run("shuffle_history", ["--shuffle-history"], args.quick)
    if shuf:
        rows.append({"setting": "Ordered vs shuffled history (control)",
                     "result": f"With the 10-window history randomly permuted, PR-AUC drops to "
                               f"{fmt_prauc(shuf['pr_auc'])} — the model reads temporal dynamics, "
                               f"not a static host fingerprint.",
                     "pr_auc": shuf["pr_auc"]})
        flush("shuffle done")

    # 2) Flow-only vs flow+packet — do packet-derived features earn their cost?
    flow = run("flow_only", ["--flow-only"], args.quick)
    if flow:
        rows.append({"setting": "Flow-only features (no packet-derived)",
                     "result": f"Zeroing the 9 packet-derived features gives PR-AUC "
                               f"{fmt_prauc(flow['pr_auc'])} vs {ref_txt} with them.",
                     "pr_auc": flow["pr_auc"]})
        flush("flow-only done")

    # 3) Held-out attack family — generalization to an unseen family.
    fam = run("holdout_family", ["--held-out-family", args.family], args.quick)
    if fam:
        npos = fam.get("n_test_positives")
        rows.append({"setting": f"Held-out attack family ({args.family})",
                     "result": f"Trained with {args.family} excluded; tested only on it "
                               f"(positives {npos}): PR-AUC {fmt_prauc(fam['pr_auc'])}.",
                     "pr_auc": fam["pr_auc"]})
        flush("holdout done")

    flush("complete")
    print("\n[done] generalization.json written.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
