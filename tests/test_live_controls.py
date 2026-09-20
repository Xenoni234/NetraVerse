"""Pure tests for live alert states and guarded response actions."""

import json

import pandas as pd
import pytest

from src.inference.live_state import (
    classify_alert,
    infer_behavioral_stage,
    make_live_event,
    recommended_action,
)
from src.response.firewall import ActionStore, ActionValidationError, NftablesExecutor
from src.data.windowing import entity_key


def test_destination_entity_key_tracks_inbound_target_host():
    flows = pd.DataFrame({
        "src_ip": ["100.81.46.8", "100.81.46.8"],
        "dst_ip": ["100.72.80.52", "100.72.80.52"],
    })
    assert entity_key(flows, "dst_ip").tolist() == ["100.72.80.52", "100.72.80.52"]


def test_inbound_port_rule_targets_destination_address():
    executor = NftablesExecutor()
    calls = []
    executor._run = lambda args: calls.append(args) or ""
    executor.apply({
        "action_id": "abcdef1234567890",
        "action_type": "block_attack_port",
        "target_ip": "100.72.80.52",
        "target_port": 22,
    })
    rule = calls[-1]
    assert rule[5:7] == ["ip", "daddr"]
    assert rule[-2:] == ["counter", "drop"]


def test_two_tier_alert_state_uses_single_and_corroborated_crossings():
    thresholds = {1: 0.7, 2: 0.7, 4: 0.7}
    early, crossed = classify_alert(
        {"risk_k1": 0.1, "risk_k2": 0.1, "risk_k4": 0.8},
        horizons=[1, 2, 4], thresholds=thresholds,
    )
    assert early == "EARLY_WARNING"
    assert crossed == [4]

    confirmed, _ = classify_alert(
        {"risk_k1": 0.75, "risk_k2": 0.1, "risk_k4": 0.8},
        horizons=[1, 2, 4], thresholds=thresholds,
        previous={"risk_k1": 0.8, "risk_k2": 0.1, "risk_k4": 0.1},
    )
    assert confirmed == "CONFIRMED_ALERT"


def test_live_event_contains_risk_uncertainty_and_resolution():
    event = make_live_event(
        {"issued_at": "2026-09-20T00:00:00Z", "last_window": "2026-09-20T00:00:00Z",
         "risk_k1": 0.2, "risk_k2": 0.4, "risk_k4": 0.9,
         "risk_lo_k4": 0.8, "risk_hi_k4": 0.95, "stage": 1},
        host="100.81.46.8", horizons=[1, 2, 4], thresholds={1: .7, 2: .7, 4: .7},
    )
    assert event["forecast_state"] == "EARLY_WARNING"
    assert event["risk"]["+120s"] == .9
    assert event["uncertainty"]["+120s"]["low"] == .8
    assert event["measurement_resolution_seconds"] == 30
    assert event["event_id"].startswith("alert-")


def test_live_event_contains_current_human_approved_recommendation():
    event = make_live_event(
        {"risk_k1": 0.8, "risk_k2": 0.8, "risk_k4": 0.9, "stage": 4},
        host="192.0.2.10", horizons=[1, 2, 4],
        thresholds={1: .7, 2: .7, 4: .7},
    )
    recommendation = event["recommended_action"]
    assert recommendation["action_type"] == "block_destination_ip"
    assert recommendation["target_ip"] == "192.0.2.10"
    assert recommendation["requires_human_approval"] is True
    assert recommendation["recommendation_only"] is True


def test_normal_or_stale_live_event_recommends_monitoring_only():
    recommendation = recommended_action(stage=4, state="NORMAL", host="192.0.2.10")
    assert recommendation["action_type"] is None
    assert recommendation["label"] == "Monitor only"
    assert recommendation["requires_human_approval"] is False


def test_behavioral_fallback_classifies_bounded_initial_access():
    stage = infer_behavioral_stage({
        "n_flows": 6, "flows_per_sec": 0.2, "failed_conn_ratio": 0.5,
        "syn_count": 4, "n_distinct_dst_port": 2,
    })
    assert stage == 2


def test_behavioral_fallback_does_not_invent_stage_from_risk_alone():
    assert infer_behavioral_stage({"baseline_deviation": 8.0}) == 0


def test_behavioral_recommendation_explains_fallback_source():
    event = make_live_event(
        {"risk_k1": 0.8, "risk_k2": 0.8, "risk_k4": 0.9, "stage": 2,
         "model_predicted_stage": 0, "stage_source": "behavioral_fallback"},
        host="192.0.2.10", horizons=[1, 2, 4],
        thresholds={1: .7, 2: .7, 4: .7},
    )
    assert event["recommended_action"]["action_type"] == "block_attack_port"
    assert "behaviorally inferred" in event["recommended_action"]["rationale"]


def test_exfiltration_recommends_destination_block():
    recommendation = recommended_action(
        stage=5, state="CONFIRMED_ALERT", host="192.0.2.10"
    )
    assert recommendation["action_type"] == "block_destination_ip"
    assert recommendation["target_port"] is None
    assert recommendation["requires_human_approval"] is True


def _payload(action_type="block_attack_port", **extra):
    return {
        "alert_id": "alert-12345678", "host": "100.81.46.8",
        "action_type": action_type, "target_ip": "100.81.46.8",
        "target_port": 22, "ttl_seconds": 300,
        "reason": "controlled test", "mode": "dry_run", **extra,
    }


def test_action_store_dry_run_is_auditable_and_reversible(tmp_path):
    path = tmp_path / "actions.json"
    store = ActionStore(path, dry_run=True, management_ips={"100.81.46.8"})
    preview = store.preview(_payload(), operator="operator")
    assert preview["status"] == "preview"
    assert "block_attack_port" in preview["rule"]
    approved = store.approve(preview["preview_id"], operator="operator")
    assert approved["status"] == "dry_run"
    assert not approved["applied"]
    rolled = store.rollback(approved["action_id"], operator="operator")
    assert rolled["status"] == "rolled_back"
    assert json.loads(path.read_text(encoding="utf-8"))[approved["action_id"]]["status"] == "rolled_back"


def test_action_store_rejects_protected_source_and_bad_inputs(tmp_path):
    store = ActionStore(tmp_path / "actions.json", management_ips={"100.81.46.8"})
    with pytest.raises(ActionValidationError, match="protected"):
        store.preview(_payload("block_source_ip"), operator="operator")
    with pytest.raises(ActionValidationError, match="target_port"):
        store.preview(_payload("rate_limit", target_port=None), operator="operator")
    with pytest.raises(ActionValidationError, match="unsupported"):
        store.preview(_payload("run_shell"), operator="operator")


class FakeExecutor:
    def __init__(self):
        self.applied = []
        self.rolled_back = []

    def apply(self, action):
        self.applied.append(action["action_id"])
        return {"table": "nv_test", "rule": "fake"}

    def rollback(self, action):
        self.rolled_back.append(action["action_id"])


def test_enforced_action_calls_only_narrow_executor(tmp_path):
    executor = FakeExecutor()
    store = ActionStore(tmp_path / "actions.json", dry_run=False, enforce_enabled=True, executor=executor)
    preview = store.preview(_payload(mode="enforce"), operator="operator")
    approved = store.approve(preview["preview_id"], operator="operator")
    assert approved["status"] == "applied"
    assert executor.applied == [approved["action_id"]]
    store.rollback(approved["action_id"], operator="operator")
    assert executor.rolled_back == [approved["action_id"]]
