"""Calibrate the model to the target server's benign traffic.

The model is trained on CIC-IDS lab traffic; a real server's "normal" looks
different. Rather than disturb the trained feature scaler (which the model
relies on), we recalibrate the **decision threshold** to the server's benign
forecast-risk distribution — e.g. threshold = 99th percentile of benign risk, so
about 1% of benign windows would alert. This adapts the alarm boundary to the
server without breaking the model's expected inputs.

Usage:
    python scripts/calibrate.py --flows <benign_cicflowmeter_dir_or_csv> \
        --checkpoint models/wm_final/best.ckpt --out models/wm_server/best.ckpt \
        --benign-percentile 99

Feed it ~30-60 min of NORMAL server traffic (no attacks running).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import numpy as np
import torch

from src.inference.engine import load_forecaster
from src.inference.live import live_windows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Calibrate the alert threshold to server-benign traffic")
    ap.add_argument("--flows", required=True, help="benign CICFlowMeter CSV file or directory")
    ap.add_argument("--checkpoint", default=str(REPO_ROOT / "models" / "wm_final" / "best.ckpt"))
    ap.add_argument("--out", default=str(REPO_ROOT / "models" / "wm_server" / "best.ckpt"))
    ap.add_argument("--benign-percentile", type=float, default=99.0,
                    help="risk percentile of benign traffic to set as the alert threshold")
    ap.add_argument("--safety-margin", type=float, default=1.0,
                    help="multiply the benign percentile by this to leave headroom above "
                         "benign noise (e.g. 2.0). With a small benign sample the p99 sits at "
                         "the benign max and grazes it; a margin gives clean separation.")
    ap.add_argument("--horizon", type=int, default=4, help="horizon (windows) to calibrate on")
    args = ap.parse_args(argv)

    print("=" * 70)
    print("CALIBRATION — fit alert threshold to server-benign traffic")
    print("=" * 70)

    fc = load_forecaster(args.checkpoint, device="cpu")
    print(f"[calib] loaded base checkpoint (lab threshold {fc.threshold:.4f})")

    print(f"[calib] building windows from benign flows: {args.flows}")
    win = live_windows(args.flows, campaign_id="calib-benign")
    n_hosts = win.groupby(["campaign_id", "entity_id"]).ngroups
    print(f"[calib] {len(win):,} benign host-windows across {n_hosts} hosts")

    # forecast risk on all benign hosts, collect the risk distribution
    risks = []
    for _, hw in win.groupby(["campaign_id", "entity_id"], sort=False):
        tl = fc.forecast_host_timeline(hw)
        if not tl.empty:
            risks.append(tl[f"risk_k{args.horizon}"].to_numpy())
    if not risks:
        print("[calib] ERROR: no host had enough history (>=10 windows). Capture more benign traffic.")
        return 1
    risk = np.concatenate(risks)

    pct = float(np.percentile(risk, args.benign_percentile))
    thr = pct * args.safety_margin
    print(f"\n[calib] benign risk distribution (+{args.horizon*30}s):")
    print(f"        mean {risk.mean():.4f} | p50 {np.percentile(risk,50):.4f} | "
          f"p95 {np.percentile(risk,95):.4f} | p99 {np.percentile(risk,99):.4f} | max {risk.max():.4f}")
    print(f"[calib] p{args.benign_percentile:g} = {pct:.4f} x margin {args.safety_margin:g} "
          f"-> alert threshold = {thr:.4f}  (was {fc.threshold:.4f})")
    est_fp = float((risk >= thr).mean())
    print(f"[calib] estimated benign windows that would alert at this threshold: {est_fp:.2%}")

    # save a server-calibrated checkpoint: same weights/scaler, new threshold
    payload = torch.load(Path(args.checkpoint), map_location="cpu", weights_only=False)
    payload["threshold"] = thr
    # Newer checkpoints may carry one validation threshold per horizon.  The
    # server calibration must override those too; otherwise live inference
    # would continue using the lab thresholds despite the calibrated scalar.
    if payload.get("thresholds") is not None:
        payload["thresholds"] = [thr] * len(payload["thresholds"])
    payload["calibrated_on"] = str(args.flows)
    payload["benign_risk_p99"] = float(np.percentile(risk, 99))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    torch.save(payload, out)
    print(f"\n[calib] server-calibrated checkpoint -> {out}")
    print("Point the dashboard / live_forecast at this checkpoint for the server test.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
