"""Autonomous threshold recalibration — "the agent learns on its own".

Periodically re-derives the alert threshold from recent **benign** traffic and
rolls it into the live checkpoint, so the forecaster's sensitivity keeps
tracking the network's normal baseline instead of drifting. Intended to run
weekly from a systemd timer (see deploy/systemd/nv-recalibrate.*), but is also
safe to run by hand.

Safety rails:
- **Never calibrate on attack traffic.** If any monitored host is currently in
  EARLY_WARNING/CONFIRMED_ALERT (per the live state file), abort — recalibrating
  while an attack is in progress would raise the threshold and blind the model.
- **Require enough data.** Refuse if the benign window has too few flow rows.
- Delegates the actual p-percentile x margin computation to scripts/calibrate.py
  (single source of truth), then restarts the live services so the new threshold
  takes effect (the running forecaster loads the threshold once at start).

    python scripts/auto_recalibrate.py --flows ~/nv_flows_benign \
        --entity-granularity dst_ip --target-host 100.72.80.52

Fully offline.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

ALERTING = {"EARLY_WARNING", "CONFIRMED_ALERT"}


def _log(msg: str) -> None:
    print(f"[auto-recal {datetime.now(timezone.utc).isoformat(timespec='seconds')}] {msg}", flush=True)


def _any_host_alerting(state_path: Path) -> bool:
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False  # no state = nothing alerting
    for h in state.get("hosts", []):
        if str(h.get("forecast_state")) in ALERTING:
            return True
    return False


def _flow_row_count(flows: Path, max_files: int) -> int:
    files = sorted(flows.glob("*.csv")) if flows.is_dir() else [flows]
    files = files[-max_files:]
    rows = 0
    for f in files:
        try:
            with f.open("r", encoding="utf-8", errors="ignore") as fh:
                rows += max(0, sum(1 for _ in fh) - 1)  # minus header
        except OSError:
            continue
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Autonomous weekly threshold recalibration")
    ap.add_argument("--flows", required=True, help="benign CICFlowMeter dir/CSV to calibrate on")
    ap.add_argument("--checkpoint", default=str(REPO_ROOT / "models" / "wm_final" / "best.ckpt"))
    ap.add_argument("--out", default=str(REPO_ROOT / "models" / "wm_server" / "best.ckpt"))
    ap.add_argument("--state", default=str(REPO_ROOT / "reports" / "live" / "state.json"))
    ap.add_argument("--benign-percentile", type=float, default=99.0)
    ap.add_argument("--safety-margin", type=float, default=2.0)
    ap.add_argument("--horizon", type=int, default=4)
    ap.add_argument("--entity-granularity", choices=("src_ip", "dst_ip", "src_dst_pair"), default="dst_ip")
    ap.add_argument("--target-host", action="append", default=[])
    ap.add_argument("--max-files", type=int, default=600)
    ap.add_argument("--min-rows", type=int, default=200, help="minimum benign flow rows required")
    ap.add_argument("--restart-units", nargs="*", default=["nv-live", "nv-api"],
                    help="systemd --user units to restart so the new threshold loads")
    ap.add_argument("--no-restart", action="store_true", help="recalibrate only; don't restart services")
    args = ap.parse_args(argv)

    flows = Path(args.flows)
    if not flows.exists():
        _log(f"ABORT: benign flows path does not exist: {flows}")
        return 2

    # Rail 1: never learn on attack traffic.
    if _any_host_alerting(Path(args.state)):
        _log("ABORT: a host is currently alerting — refusing to calibrate on possible attack traffic.")
        return 3

    # Rail 2: enough benign data.
    rows = _flow_row_count(flows, args.max_files)
    if rows < args.min_rows:
        _log(f"ABORT: only {rows} benign flow rows (< {args.min_rows}); capture more first.")
        return 4

    _log(f"calibrating on {rows} benign rows from {flows} (p{args.benign_percentile:g} x {args.safety_margin:g})")
    cmd = [
        sys.executable, str(REPO_ROOT / "scripts" / "calibrate.py"),
        "--flows", str(flows), "--checkpoint", args.checkpoint, "--out", args.out,
        "--benign-percentile", str(args.benign_percentile),
        "--safety-margin", str(args.safety_margin),
        "--horizon", str(args.horizon),
        "--entity-granularity", args.entity_granularity,
    ]
    for host in args.target_host:
        cmd += ["--target-host", host]
    result = subprocess.run(cmd, cwd=str(REPO_ROOT))
    if result.returncode != 0:
        _log(f"ABORT: calibrate.py failed (exit {result.returncode}); threshold unchanged.")
        return result.returncode

    if args.no_restart:
        _log("calibration written; skipping service restart (--no-restart).")
        return 0

    for unit in args.restart_units:
        r = subprocess.run(["systemctl", "--user", "restart", unit])
        _log(f"restart {unit}: {'ok' if r.returncode == 0 else 'FAILED'}")
    _log("done — new benign-calibrated threshold is live.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
