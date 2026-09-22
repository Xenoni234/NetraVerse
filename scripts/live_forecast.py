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
import math
import sys
import time
from datetime import datetime, timezone
from numbers import Real
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pandas as pd

from src.inference.detector import score_present
from src.inference.engine import FEATURE_LABELS, load_forecaster
from src.inference.live import live_windows
from src.inference.live_state import infer_behavioral_stage, make_live_event


def _atomic_json(path: Path, payload: object) -> None:
    def safe(value):
        if isinstance(value, dict):
            return {str(k): safe(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [safe(v) for v in value]
        if isinstance(value, Real) and not isinstance(value, bool):
            number = float(value)
            return number if math.isfinite(number) else None
        return value

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(safe(payload), indent=2, default=str, allow_nan=False), encoding="utf-8")
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


def forecast_once(
    fc, flows_path: str, horizon: int, sustain: int, *, mc_samples: int = 0,
    entity_granularity: str = "dst_ip", target_hosts: set[str] | None = None,
    max_files: int = 60, window_before: object | None = None,
) -> pd.DataFrame:
    """One pass: build windows from current flows, forecast latest risk per host."""
    win = live_windows(
        flows_path, campaign_id="live", entity_granularity=entity_granularity,
        target_hosts=target_hosts,
        max_files=max_files, window_before=window_before,
    )
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
        alerting = bool(len(rk) >= sustain and (rk[-sustain:] >= selected_threshold).all())
        model_stage = int(last[f"stage_k{horizon}"])
        observed_window = hw.sort_values("window_start").iloc[-1]
        behavioral_stage = infer_behavioral_stage(observed_window)
        # Keep the model output for auditability.  A strong live signature may
        # supply a conservative stage only when the learned head says BENIGN;
        # this prevents a high-risk live alert from becoming an unhelpful
        # BENIGN/Monitor-only result under domain shift.
        stage = model_stage or (behavioral_stage if alerting else 0)
        stage_source = "model" if model_stage else (
            "behavioral_fallback" if behavioral_stage else "model"
        )
        rows.append({
            "issued_at": now,
            "host": ent,
            "last_window": last["window_start"],
            **{f"risk_k{k}": float(last[f"risk_k{k}"]) for k in fc.horizons},
            "stage": stage,
            "model_predicted_stage": model_stage,
            "stage_source": stage_source,
            "alerting": alerting,
            "alert_level": alert_level,
            "earliest_warning_horizon": max(crossed_horizons) if crossed_horizons else None,
            **{f"risk_lo_k{k}": float(last[f"risk_lo_k{k}"]) for k in fc.horizons if f"risk_lo_k{k}" in last},
            **{f"risk_hi_k{k}": float(last[f"risk_hi_k{k}"]) for k in fc.horizons if f"risk_hi_k{k}" in last},
            "predicted_stage": stage,
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
    ap.add_argument("--entity-granularity", choices=("src_ip", "dst_ip", "src_dst_pair"),
                    default="dst_ip",
                    help="live host identity; dst_ip is correct for inbound attacks")
    ap.add_argument("--target-host", action="append", default=[],
                    help="destination host to monitor (repeat for an allowlist); required for dst_ip")
    ap.add_argument("--max-files", type=int, default=60,
                    help="newest capture CSVs to read per poll; 60 is about 30 minutes at 30s/chunk")
    ap.add_argument("--once", action="store_true", help="run a single pass and exit")
    ap.add_argument("--replay", action="store_true",
                    help="replay a static flows dir one 30s window per interval instead of always "
                         "exposing the final window (demo mode; the dashboard advances over time)")
    ap.add_argument("--replay-start", default=None,
                    help="replay only: window timestamp to begin the cursor at (e.g. "
                         "'2026-09-20 15:58:00'); earlier windows still supply history. "
                         "Use it to reach a known attack quickly instead of walking from the start.")
    args = ap.parse_args(argv)
    if args.entity_granularity == "dst_ip" and not args.target_host:
        ap.error("--target-host is required when --entity-granularity=dst_ip")
    target_hosts = {str(host) for host in args.target_host}

    ckpt = args.checkpoint if Path(args.checkpoint).exists() else str(
        REPO_ROOT / "models" / "wm_final" / "best.ckpt")
    fc = load_forecaster(ckpt, device="cpu")
    if args.horizon not in fc.horizons:
        requested = args.horizon
        args.horizon = max(fc.horizons)
        print(f"[live] requested +{requested * 30}s is unavailable in checkpoint; using +{args.horizon * 30}s")
    print(f"[live] checkpoint={ckpt} | threshold={fc.threshold:.4f} | horizon=+{args.horizon*30}s")
    print(f"[live] watching {args.flows} every {args.interval}s "
          f"(entity={args.entity_granularity}; targets={','.join(sorted(target_hosts)) or 'all'}; Ctrl-C to stop)")

    # Replay cursor: walk a static flows dir forward one window per tick so the
    # dashboard advances instead of freezing on the final window. We warm up on
    # ~L+max(K) windows of history, then reveal one new window each interval.
    replay_steps: list = []
    replay_idx = 0
    if args.replay:
        all_windows = live_windows(
            args.flows, campaign_id="live", entity_granularity=args.entity_granularity,
            target_hosts=target_hosts, max_files=args.max_files,
        )
        replay_steps = sorted(pd.to_datetime(all_windows["window_start"]).unique())
        if not replay_steps:
            ap.error(f"--replay: no windows found under {args.flows}")
        warmup = min(len(replay_steps) - 1, 10 + max(fc.horizons))
        replay_idx = warmup
        if args.replay_start:
            start_ts = pd.to_datetime(args.replay_start)
            # Match the tz-awareness of the window steps (they are UTC-aware) so
            # the comparison below does not raise on a naive/aware mismatch.
            ref_tz = getattr(replay_steps[0], "tzinfo", None)
            if ref_tz is not None and start_ts.tzinfo is None:
                start_ts = start_ts.tz_localize(ref_tz)
            elif ref_tz is None and start_ts.tzinfo is not None:
                start_ts = start_ts.tz_localize(None)
            found = next((i for i, t in enumerate(replay_steps) if t >= start_ts), len(replay_steps) - 1)
            replay_idx = min(max(found, warmup), len(replay_steps) - 1)
        print(f"[live] replay: {len(replay_steps)} windows "
              f"({replay_steps[0]} → {replay_steps[-1]}); starting at window "
              f"{replay_idx + 1} ({replay_steps[replay_idx]})")

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
            window_before = replay_steps[min(replay_idx, len(replay_steps) - 1)] if args.replay else None
            try:
                current_preds = forecast_once(
                    fc, args.flows, args.horizon, args.sustain,
                    mc_samples=max(0, args.mc_samples),
                    entity_granularity=args.entity_granularity,
                    target_hosts=target_hosts,
                    max_files=args.max_files,
                    window_before=window_before,
                )
            except FileNotFoundError:
                print("[live] no flows yet, waiting…")
                current_preds = pd.DataFrame()
            if not current_preds.empty:
                # Poll frequently for low UI latency, but only persist a new
                # forecast when a new completed model window exists.  This
                # prevents duplicate rows from inflating the event log and
                # keeps the feed age honest.
                fresh_rows = []
                fresh_windows = {}
                for row in current_preds.to_dict("records"):
                    host = str(row["host"])
                    window = str(row["last_window"])
                    if last_prediction_window.get(host) == window:
                        continue
                    last_prediction_window[host] = window
                    fresh_windows[host] = window
                    fresh_rows.append(row)
                fresh_preds = pd.DataFrame(fresh_rows, columns=current_preds.columns)
                if not fresh_preds.empty:
                    history.append(fresh_preds)
                    history = history[-240:]
                    parquet_history = [frame.dropna(axis=1, how="all") for frame in history]
                    pd.concat(parquet_history, ignore_index=True).to_parquet(out, index=False)
                threshold_map = {int(k): fc.threshold_for_horizon(k) for k in fc.horizons}
                current_state = {}
                new_events = []
                live_win = live_windows(
                    args.flows, campaign_id="live",
                    entity_granularity=args.entity_granularity,
                    target_hosts=target_hosts,
                    max_files=args.max_files, window_before=window_before,
                )
                for row in current_preds.to_dict("records"):
                    host = str(row["host"])
                    host_hw = live_win.loc[live_win.entity_id.astype(str) == host]
                    # Dual-engine: present-state detector scores the current window
                    # (attack now), independent of the forecaster's future risk.
                    verdict = None
                    if not host_hw.empty:
                        observed = host_hw.sort_values("window_start").iloc[-1]
                        verdict = score_present(observed).to_json()
                    event = make_live_event(
                        row, host=host, horizons=fc.horizons, thresholds=threshold_map,
                        previous=previous.get(host), checkpoint=str(ckpt),
                        calibration="horizon calibrator" if fc.calibrator else "server threshold",
                        feature_drivers=_feature_drivers(fc, host_hw),
                        detector=verdict,
                    )
                    old_state = last_event_state.get(host)
                    if event["forecast_state"] != old_state:
                        new_events.append(event)
                    current_state[host] = event
                    if fresh_windows.get(host) == str(row["last_window"]):
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
                alerts = current_preds[current_preds["alerting"]]
                stamp = datetime.now().strftime("%H:%M:%S")
                if not alerts.empty:
                    for r in alerts.itertuples():
                        print(f"  [{stamp}] ⚠ ALERT host={r.host} "
                              f"risk(+{args.horizon*30}s)={getattr(r, f'risk_k{args.horizon}'):.2f}")
                else:
                    top = current_preds.sort_values(f"risk_k{args.horizon}", ascending=False).iloc[0]
                    print(f"  [{stamp}] ok | {len(current_preds)} hosts | "
                          f"top risk {top[f'risk_k{args.horizon}']:.2f} ({top['host']})")
            if args.once:
                break
            if args.replay:
                if replay_idx < len(replay_steps) - 1:
                    replay_idx += 1
                elif replay_idx == len(replay_steps) - 1:
                    print("[live] replay: reached the final window; holding.")
                    replay_idx += 1  # sentinel so this prints once
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[live] stopped.")
    print(f"[live] predictions -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
