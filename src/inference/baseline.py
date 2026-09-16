"""Signature / threshold baseline — the "dumb IDS" the world model must beat.

`docs/live_test_runbook.md` §5 asks for a trivial rule-based detector run alongside
the model so the **lead time is a real, measured gap**: "the world model warned N
seconds before a signature/threshold IDS would fire." This module is that baseline.

It fires on the *current* window's raw features (no forecasting): a scan is "many
distinct destination ports in one window"; a brute-force is "high connection rate
with a high failed-connection ratio". Both read columns produced by
:data:`src.data.windowing.STATE_FEATURE_COLUMNS`, so it runs on the same per-host
windows the model consumes — an honest apples-to-apples comparison.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd


@dataclass
class BaselineThresholds:
    """Operating points for the signature baseline (a plausible 'obvious attack')."""

    scan_ports: float = 50.0      # distinct dst ports in a 30 s window -> scan
    conn_rate: float = 2.0        # flows/sec -> aggressive connecting
    few_ports: float = 3.0        # brute-force hammers ONE service, so fan-out stays small
    failed_ratio: float = 0.5     # informational; brute-force TCP usually *succeeds*


def signature_alerts(
    host_windows: pd.DataFrame, thr: BaselineThresholds | None = None
) -> pd.DataFrame:
    """Per-window signature verdict for one host's ordered windows.

    Returns a frame with ``window_start``, ``sig_alert`` (bool) and ``sig_reason``
    (which rule fired), aligned to ``host_windows`` rows. A window alerts if it looks
    like a scan (port fan-out) **or** a brute-force (rate + failures) — the two
    attack shapes the live test uses.
    """
    thr = thr or BaselineThresholds()
    g = host_windows.sort_values("window_start").reset_index(drop=True)

    def col(name: str) -> np.ndarray:
        return g[name].to_numpy() if name in g.columns else np.zeros(len(g))

    n_ports = col("n_distinct_dst_port")
    rate = col("flows_per_sec")
    failed = col("failed_conn_ratio")

    # scan = wide port fan-out; brute-force = high rate concentrated on one service
    # (real SSH/FTP brute-force TCP-connects succeed, so we key on rate + low fan-out).
    scan_hit = n_ports >= thr.scan_ports
    bf_hit = (rate >= thr.conn_rate) & (n_ports <= thr.few_ports)
    alert = scan_hit | bf_hit
    reason = np.where(scan_hit, "port fan-out (scan)",
                      np.where(bf_hit, "connection-rate + failures (brute-force)", ""))

    return pd.DataFrame({
        "window_start": g["window_start"].to_numpy(),
        "sig_alert": alert,
        "sig_reason": reason,
        "n_distinct_dst_port": n_ports,
        "flows_per_sec": rate,
        "failed_conn_ratio": failed,
    })


def first_alert_index(mask: np.ndarray, sustain: int = 1) -> int | None:
    """Index of the first run of ``sustain`` consecutive True values, else None."""
    m = np.asarray(mask, dtype=bool)
    for i in range(len(m) - sustain + 1):
        if m[i : i + sustain].all():
            return i
    return None


__all__ = ["BaselineThresholds", "signature_alerts", "first_alert_index"]
