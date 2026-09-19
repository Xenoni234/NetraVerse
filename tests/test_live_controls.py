"""Pure tests for live alert states and guarded response actions."""

import json

import pytest

from src.inference.live_state import classify_alert, make_live_event
from src.response.firewall import ActionStore, ActionValidationError


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
