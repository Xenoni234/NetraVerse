"""Small, serialisable state machine for the live forecast feed."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping
import uuid

from src.mitre.stage_mapping import (
    BENIGN,
    C2,
    EXFILTRATION,
    IMPACT,
    INITIAL_ACCESS,
    LATERAL_MOVEMENT,
    RECON,
    STAGE_NAMES,
)


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


def infer_behavioral_stage(row: Mapping[str, Any]) -> int:
    """Infer a conservative live stage from a strong observed flow signature.

    Live captures are unlabeled and can be far outside the training domain.  In
    that case the risk head may correctly raise an alert while the learned stage
    head falls back to BENIGN.  This fallback is deliberately used only by the
    live path after an alert and only for strong, auditable signatures; it does
    not overwrite the raw model stage.

    Returns BENIGN when the observed features do not support a sufficiently
    specific stage.  Thresholds are intentionally conservative and operate on
    the existing 30-second host-window fields.
    """
    def value(name: str) -> float:
        try:
            return float(row.get(name, 0.0) or 0.0)
        except (TypeError, ValueError):
            return 0.0

    n_flows = value("n_flows")
    flows_per_sec = value("flows_per_sec")
    failed = value("failed_conn_ratio")
    syn = value("syn_count")
    dst_ports = value("n_distinct_dst_port")
    dst_ips = value("n_distinct_dst_ip")
    new_peers = value("new_peer_count")
    port_entropy = value("dst_port_entropy")
    bytes_per_sec = value("bytes_per_sec")
    fwd_bwd = value("fwd_bwd_ratio")
    pkts_per_sec = value("pkts_per_sec")
    mean_iat = value("mean_iat_s")
    idle = value("idle_s")

    # High-volume SYN/packet pressure is a more specific impact signature than
    # a generic high risk score.
    if (pkts_per_sec >= 50.0 and syn >= 50.0) or flows_per_sec >= 4.0:
        return IMPACT

    # Wide destination-port fan-out is the strongest live recon signature.
    if dst_ports >= 10.0 or (port_entropy >= 2.0 and new_peers >= 3.0):
        return RECON

    # Repeated failed, low-fan-out service connections resemble the bounded SSH
    # / FTP initial-access ramp used by the live test.
    if failed >= 0.5 and syn >= 3.0 and dst_ports <= 4.0 and (
        flows_per_sec >= 0.15 or n_flows >= 6.0
    ):
        return INITIAL_ACCESS

    # Internal fan-out with new peers and no broad port scan is lateral movement.
    if dst_ips >= 5.0 and new_peers >= 3.0:
        return LATERAL_MOVEMENT

    # Large, asymmetric outbound volume is an exfiltration-shaped signature.
    if bytes_per_sec >= 5_000.0 and fwd_bwd >= 2.0:
        return EXFILTRATION

    # Periodic, low-volume traffic with long idle/arrival gaps is C2-shaped.
    if 1.0 <= n_flows <= 12.0 and mean_iat >= 2.0 and idle >= 2.0:
        return C2

    return BENIGN


def recommended_action(
    *, stage: int, state: str, host: str, stage_source: str = "model"
) -> dict[str, Any]:
    """Return the current advisory response for one live forecast.

    This is deliberately a recommendation, not an execution request.  The
    frontend uses it to keep the operator form aligned with the newest event;
    the API still requires a separate human preview and approval.
    """
    stage = int(stage)
    stage_name = STAGE_NAMES.get(stage, "UNKNOWN")
    if state not in {"EARLY_WARNING", "CONFIRMED_ALERT"} or stage == 0:
        return {
            "action_type": None,
            "label": "Monitor only",
            "target_ip": host,
            "target_port": None,
            "ttl_seconds": None,
            "stage": stage_name,
            "rationale": "No calibrated live alert currently requires containment.",
            "requires_human_approval": False,
            "recommendation_only": True,
        }

    # Keep this mapping inside the live event so every consumer receives the
    # same recommendation.  These are the narrow actions supported by the
    # guarded response store; none is applied automatically.
    action_type = {
        4: "block_destination_ip",  # C2
        3: "restrict_east_west",    # lateral movement
        5: "block_destination_ip",  # exfiltration egress
        6: "rate_limit",            # impact
    }.get(stage, "block_attack_port")
    needs_port = action_type in {"block_attack_port", "rate_limit"}
    source_text = "behaviorally inferred" if stage_source == "behavioral_fallback" else "predicted"
    return {
        "action_type": action_type,
        "label": action_type.replace("_", " "),
        "target_ip": host,
        # 22 is a demo-safe starting value only; the operator must verify the
        # observed service/port before previewing or approving the action.
        "target_port": 22 if needs_port else None,
        "target_port_note": "Verify the observed service/port before approval." if needs_port else None,
        "ttl_seconds": 300,
        "stage": stage_name,
        "rationale": f"Current {state.replace('_', ' ').lower()} for {source_text} {stage_name}.",
        "requires_human_approval": True,
        "recommendation_only": True,
    }


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
    detector: dict[str, Any] | None = None,
) -> dict[str, Any]:
    state, crossed = classify_alert(
        row, horizons=horizons, thresholds=thresholds, previous=previous
    )
    horizons = [int(k) for k in horizons]
    primary = max(horizons)
    predicted_stage = int(row.get("stage", row.get(f"stage_k{primary}", 0)))
    stage_source = str(row.get("stage_source", "model"))
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
        "predicted_stage": predicted_stage,
        "model_predicted_stage": int(row.get("model_predicted_stage", predicted_stage)),
        "stage_source": stage_source,
        "feature_drivers": list(feature_drivers or []),
        "detector": detector or {"attack_now": 0.0, "stage": 0, "stage_name": "BENIGN",
                                 "signature": "no present-state telemetry", "scores": {}},
        "checkpoint": checkpoint,
        "calibration": calibration,
        "measurement_resolution_seconds": 30,
        "action": None,
        "recommended_action": recommended_action(
            stage=predicted_stage, state=state, host=host, stage_source=stage_source
        ),
    }


__all__ = [
    "ALERT_STATES", "classify_alert", "infer_behavioral_stage", "make_live_event",
    "recommended_action", "utc_now",
]
