"""Small, serialisable state machine for the live forecast feed."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable
import uuid


ALERT_STATES = {
    "NORMAL",
    "EARLY_WARNING",
    "CONFIRMED_ALERT",
    "ACTION_PENDING",
    "ACTION_APPLIED",
    "ROLLED_BACK",
    "STALE",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _risk_map(row: dict[str, Any], horizons: Iterable[int]) -> dict[str, float]:
    return {f"+{int(k) * 30}s": round(float(row.get(f"risk_k{k}", 0.0)), 6) for k in horizons}


def classify_alert(
    row: dict[str, Any],
    *,
    horizons: Iterable[int],
    thresholds: dict[int, float],
    previous: dict[str, Any] | None = None,
) -> tuple[str, list[int]]:
    """Classify one host row without inventing attack labels.

    A single calibrated crossing is an early warning.  The existing live loop's
    sustained decision is the confirmed state.  The previous row is accepted so
    callers can also corroborate a warning across forecast horizons.
    """
    crossed = [
        int(k) for k in horizons
        if float(row.get(f"risk_k{k}", 0.0)) >= float(thresholds.get(int(k), 1.0))
    ]
    sustained = bool(row.get("alerting", False))
    corroborated = bool({1, 2}.intersection(crossed)) and bool(
        previous and {1, 2}.intersection(
            int(k) for k in horizons
            if float(previous.get(f"risk_k{k}", 0.0)) >= float(thresholds.get(int(k), 1.0))
        )
    )
    if sustained or corroborated:
        return "CONFIRMED_ALERT", crossed
    if crossed:
        return "EARLY_WARNING", crossed
    return "NORMAL", crossed


def _confidence(row: dict[str, Any], horizons: Iterable[int]) -> float | None:
    widths = []
    for k in horizons:
        lo, hi = row.get(f"risk_lo_k{k}"), row.get(f"risk_hi_k{k}")
        if lo is not None and hi is not None:
            widths.append(max(0.0, min(1.0, float(hi) - float(lo))))
    if not widths:
        return None
    return round(max(0.0, min(1.0, 1.0 - sum(widths) / len(widths))), 4)


def make_live_event(
    row: dict[str, Any],
    *,
    host: str,
    horizons: Iterable[int],
    thresholds: dict[int, float],
    previous: dict[str, Any] | None = None,
    checkpoint: str = "",
    calibration: str = "server threshold",
    feature_drivers: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    state, crossed = classify_alert(
        row, horizons=horizons, thresholds=thresholds, previous=previous
    )
    horizons = [int(k) for k in horizons]
    primary = max(horizons)
    return {
        "event_id": f"alert-{uuid.uuid4().hex[:16]}",
        "issued_at": str(row.get("issued_at") or utc_now()),
        "host": host,
        "last_window": str(row.get("last_window", "")),
        "forecast_state": state,
        "alert_level": str(row.get("alert_level", "none")),
        "crossed_horizons": [f"+{k * 30}s" for k in crossed],
        "risk": _risk_map(row, horizons),
        "uncertainty": {
            f"+{k * 30}s": {
                "low": (None if row.get(f"risk_lo_k{k}") is None else round(float(row[f"risk_lo_k{k}"]), 6)),
                "high": (None if row.get(f"risk_hi_k{k}") is None else round(float(row[f"risk_hi_k{k}"]), 6)),
            }
            for k in horizons
        },
        "confidence": _confidence(row, horizons),
        "predicted_stage": int(row.get("stage", row.get(f"stage_k{primary}", 0))),
        "feature_drivers": list(feature_drivers or []),
        "checkpoint": checkpoint,
        "calibration": calibration,
        "measurement_resolution_seconds": 30,
        "action": None,
    }


__all__ = ["ALERT_STATES", "classify_alert", "make_live_event", "utc_now"]
