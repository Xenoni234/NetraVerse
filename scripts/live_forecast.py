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
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pandas as pd

from src.inference.engine import FEATURE_LABELS, load_forecaster
from src.inference.live import live_windows
from src.inference.live_state import make_live_event


def _atomic_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)


def _feature_drivers(fc, host_windows: pd.DataFrame, *, top_k: int = 5) -> list[dict]:
    """Report auditable robust-scaled observations, not invented SHAP values."""
    if host_windows.empty:
        return []
    current = host_windows.sort_values("window_start").iloc[-1]
    center = fc.scaler.get("center", [])
    scale = fc.scaler.get("scale", [])
    if len(center) != len(fc.feature_names) or len(scale) != len(fc.feature_names):
        return []
    scores = []
    for i, name in enumerate(fc.feature_names):
        try:
            value = float(current.get(name, 0.0))
            z = (value - float(center[i])) / max(abs(float(scale[i])), 1e-9)
        except (TypeError, ValueError):
            continue
        if name.startswith("mask_"):
            continue
        scores.append((abs(z), name, value, z))
    scores.sort(reverse=True)
    return [
        {"feature": name, "label": FEATURE_LABELS.get(name, name),
         "observed": round(value, 4), "robust_deviation": round(z, 4)}
        for _, name, value, z in scores[:top_k]
    ]


def forecast_once(fc, flows_path: str, horizon: int, sustain: int, *, mc_samples: int = 0) -> pd.DataFrame:
    """One pass: build windows from current flows, forecast latest risk per host."""
    win = live_windows(flows_path, campaign_id="live")
    now = datetime.now(timezone.utc).isoformat()
    rows = []
    for (_, ent), hw in win.groupby(["campaign_id", "entity_id"], sort=False):
        tl = fc.forecast_host_timeline(hw, mc_samples=mc_samples)
        if tl.empty:
            continue
        last = tl.iloc[-1]
        rk = tl[f"risk_k{horizon}"].to_numpy()
        selected_threshold = fc.threshold_for_horizon(horizon)
        levels = {
            "urgent": [k for k in fc.horizons if k <= 2],
            "warning": [k for k in fc.horizons if 2 < k <= 8],
            "advisory": [k for k in fc.horizons if k > 8],
        }
        crossed = {level: [k for k in ks if float(last[f"risk_k{k}"]) >= fc.threshold_for_horizon(k)]
                   for level, ks in levels.items()}
        alert_level = next((level for level in ("urgent", "warning", "advisory") if crossed[level]), "none")
        crossed_horizons = [k for ks in crossed.values() for k in ks]
        rows.append({
            "issued_at": now,
            "host": ent,
            "last_window": last["window_start"],
            **{f"risk_k{k}": float(last[f"risk_k{k}"]) for k in fc.horizons},
            "stage": int(last[f"stage_k{horizon}"]),
            "alerting": bool(len(rk) >= sustain and (rk[-sustain:] >= selected_threshold).all()),
            "alert_level": alert_level,
            "earliest_warning_horizon": max(crossed_horizons) if crossed_horizons else None,
            **{f"risk_lo_k{k}": float(last[f"risk_lo_k{k}"]) for k in fc.horizons if f"risk_lo_k{k}" in last},
            **{f"risk_hi_k{k}": float(last[f"risk_hi_k{k}"]) for k in fc.horizons if f"risk_hi_k{k}" in last},
            "predicted_stage": int(last[f"stage_k{horizon}"]),
        })
    return pd.DataFrame(rows)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Live attack-onset forecasting loop")
    ap.add_argument("--flows", required=True, help="dir/file of CICFlowMeter CSVs from the agent")
    ap.add_argument("--checkpoint", default=str(REPO_ROOT / "models" / "wm_server" / "best.ckpt"))
    ap.add_argument("--predictions", default=str(REPO_ROOT / "reports" / "live" / "predictions.parquet"))
    ap.add_argument("--state", default=str(REPO_ROOT / "reports" / "live" / "state.json"))
    ap.add_argument("--events", default=str(REPO_ROOT / "reports" / "live" / "events.jsonl"))
    ap.add_argument("--interval", type=int, default=5, help="seconds between live-feed checks")
    ap.add_argument("--horizon", type=int, default=4,
                    help="primary horizon in 30-second windows; 4 means +120 seconds")
    ap.add_argument("--sustain", type=int, default=2)
    ap.add_argument("--mc-samples", type=int, default=8,
                    help="MC-dropout samples for uncertainty; use 0 to disable")
    ap.add_argument("--once", action="store_true", help="run a single pass and exit")
    args = ap.parse_args(argv)

    ckpt = args.checkpoint if Path(args.checkpoint).exists() else str(
        REPO_ROOT / "models" / "wm_final" / "best.ckpt")
    fc = load_forecaster(ckpt, device="cpu")
    if args.horizon not in fc.horizons:
        requested = args.horizon
        args.horizon = max(fc.horizons)
        print(f"[live] requested +{requested * 30}s is unavailable in checkpoint; using +{args.horizon * 30}s")
    print(f"[live] checkpoint={ckpt} | threshold={fc.threshold:.4f} | horizon=+{args.horizon*30}s")
    print(f"[live] watching {args.flows} every {args.interval}s (Ctrl-C to stop)")

    out = Path(args.predictions); out.parent.mkdir(parents=True, exist_ok=True)
    history = []
    previous: dict[str, dict] = {}
    last_state: dict[str, dict] = {}
    last_event_state: dict[str, str] = {}
    last_prediction_window: dict[str, str] = {}
    timeline_by_host: dict[str, list[dict]] = {}
    state_path, events_path = Path(args.state), Path(args.events)
    try:
        while True:
            try:
                preds = forecast_once(fc, args.flows, args.horizon, args.sustain,
                                      mc_samples=max(0, args.mc_samples))
            except FileNotFoundError:
                print("[live] no flows yet, waiting…")
                preds = pd.DataFrame()
            if not preds.empty:
                # Poll frequently for low UI latency, but only persist a new
                # forecast when a new completed model window exists.  This
                # prevents duplicate rows from inflating the event log and
                # keeps the feed age honest.
                fresh_rows = []
                for row in preds.to_dict("records"):
                    host = str(row["host"])
                    window = str(row["last_window"])
                    if last_prediction_window.get(host) == window:
                        continue
                    last_prediction_window[host] = window
                    fresh_rows.append(row)
                preds = pd.DataFrame(fresh_rows)
            if not preds.empty:
                history.append(preds)
                pd.concat(history, ignore_index=True).to_parquet(out, index=False)
                threshold_map = {int(k): fc.threshold_for_horizon(k) for k in fc.horizons}
                current_state = {}
                new_events = []
                live_win = live_windows(args.flows, campaign_id="live")
                for row in preds.to_dict("records"):
                    host = str(row["host"])
                    host_hw = live_win.loc[live_win.entity_id.astype(str) == host]
                    event = make_live_event(
                        row, host=host, horizons=fc.horizons, thresholds=threshold_map,
                        previous=previous.get(host), checkpoint=str(ckpt),
                        calibration="horizon calibrator" if fc.calibrator else "server threshold",
                        feature_drivers=_feature_drivers(fc, host_hw),
                    )
                    old_state = last_event_state.get(host)
                    if event["forecast_state"] != old_state:
                        new_events.append(event)
                    current_state[host] = event
                    timeline_by_host.setdefault(host, []).append(row)
                    timeline_by_host[host] = timeline_by_host[host][-24:]
                    previous[host] = row
                    last_event_state[host] = event["forecast_state"]
                last_state = current_state
                now = datetime.now(timezone.utc).isoformat()
                _atomic_json(state_path, {
                    "available": True, "updated_at": now, "hosts": list(last_state.values()),
                    "timelines": timeline_by_host,
                    "checkpoint": str(ckpt), "calibration": "horizon calibrator" if fc.calibrator else "server threshold",
                    "horizons": [f"+{int(k) * 30}s" for k in fc.horizons],
                    "measurement_resolution_seconds": 30, "mode": "dry_run",
                })
                if new_events:
                    events_path.parent.mkdir(parents=True, exist_ok=True)
                    with events_path.open("a", encoding="utf-8") as fh:
                        for event in new_events:
                            fh.write(json.dumps(event, default=str) + "\n")
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
