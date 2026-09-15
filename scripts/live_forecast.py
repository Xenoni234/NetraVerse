"""Live forecasting loop — watch the capture agent's flows and forecast onset.

Reads the CICFlowMeter CSV(s) the server capture agent produces, rebuilds per-host
30 s windows every interval, forecasts attack-onset risk at +30/60/120 s, and:
  - prints an alert when a host's risk stays >= threshold for `sustain` windows,
  - writes a predictions parquet the dashboard (live mode) tails,
  - stamps each forecast with wall-clock time so lead time can be verified honestly
    against the operator's known attack-launch time.

Usage:
    python scripts/live_forecast.py --flows <agent_flow_dir> \
        --checkpoint models/wm_server/best.ckpt --interval 30

Runs offline. Ctrl-C to stop.
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pandas as pd

from src.inference.engine import load_forecaster
from src.inference.live import live_windows


def forecast_once(fc, flows_path: str, horizon: int, sustain: int) -> pd.DataFrame:
    """One pass: build windows from current flows, forecast latest risk per host."""
    win = live_windows(flows_path, campaign_id="live")
    now = datetime.now(timezone.utc).isoformat()
    rows = []
    for (_, ent), hw in win.groupby(["campaign_id", "entity_id"], sort=False):
        tl = fc.forecast_host_timeline(hw)
        if tl.empty:
            continue
        last = tl.iloc[-1]
        rk = tl[f"risk_k{horizon}"].to_numpy()
        alerting = len(rk) >= sustain and (rk[-sustain:] >= fc.threshold).all()
        rows.append({
            "issued_at": now,
            "host": ent,
            "last_window": last["window_start"],
            **{f"risk_k{k}": float(last[f"risk_k{k}"]) for k in fc.horizons},
            "stage": int(last[f"stage_k{horizon}"]),
            "alerting": bool(alerting),
        })
    return pd.DataFrame(rows)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Live attack-onset forecasting loop")
    ap.add_argument("--flows", required=True, help="dir/file of CICFlowMeter CSVs from the agent")
    ap.add_argument("--checkpoint", default=str(REPO_ROOT / "models" / "wm_server" / "best.ckpt"))
    ap.add_argument("--predictions", default=str(REPO_ROOT / "reports" / "live" / "predictions.parquet"))
    ap.add_argument("--interval", type=int, default=30, help="seconds between forecasts")
    ap.add_argument("--horizon", type=int, default=4)
    ap.add_argument("--sustain", type=int, default=2)
    ap.add_argument("--once", action="store_true", help="run a single pass and exit")
    args = ap.parse_args(argv)

    ckpt = args.checkpoint if Path(args.checkpoint).exists() else str(
        REPO_ROOT / "models" / "wm_final" / "best.ckpt")
    fc = load_forecaster(ckpt, device="cpu")
    print(f"[live] checkpoint={ckpt} | threshold={fc.threshold:.4f} | horizon=+{args.horizon*30}s")
    print(f"[live] watching {args.flows} every {args.interval}s (Ctrl-C to stop)")

    out = Path(args.predictions); out.parent.mkdir(parents=True, exist_ok=True)
    history = []
    try:
        while True:
            try:
                preds = forecast_once(fc, args.flows, args.horizon, args.sustain)
            except FileNotFoundError:
                print("[live] no flows yet, waiting…")
                preds = pd.DataFrame()
            if not preds.empty:
                history.append(preds)
                pd.concat(history, ignore_index=True).to_parquet(out, index=False)
                alerts = preds[preds["alerting"]]
                stamp = datetime.now().strftime("%H:%M:%S")
                if not alerts.empty:
                    for r in alerts.itertuples():
                        print(f"  [{stamp}] ⚠ ALERT host={r.host} "
                              f"risk(+{args.horizon*30}s)={getattr(r, f'risk_k{args.horizon}'):.2f}")
                else:
                    top = preds.sort_values(f"risk_k{args.horizon}", ascending=False).iloc[0]
                    print(f"  [{stamp}] ok | {len(preds)} hosts | "
                          f"top risk {top[f'risk_k{args.horizon}']:.2f} ({top['host']})")
            if args.once:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[live] stopped.")
    print(f"[live] predictions -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
