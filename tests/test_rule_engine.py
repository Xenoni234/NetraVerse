"""Decision engine is deterministic and every stage yields an action with alternatives."""
import pandas as pd

from src.decision.counterfactual import apply_to_flows
from src.decision.rule_engine import Action, recommend
from src.live.action_executor import apply as execute

CTX = {"host": "10.0.0.5", "role": "attacker", "attacker": "10.0.0.5", "victims": ["10.0.0.9"],
       "c2_peers": ["8.8.4.4"], "top_port": 22}
DRV = [{"feature": "out_distinct_dport", "attribution": 0.4}]


def test_every_attack_stage_has_action_and_alternatives():
    for stage in range(1, 7):
        a = recommend(stage, DRV, CTX)
        assert a.kind != "monitor" and a.rationale
        assert a.alternatives and a.alternatives[-1].kind == "monitor"


def test_benign_is_monitor_and_deterministic():
    assert recommend(0, [], CTX).kind == "monitor"
    assert recommend(2, DRV, CTX).to_dict() == recommend(2, DRV, CTX).to_dict()


def test_roundtrip_dict():
    a = recommend(1, DRV, CTX)
    assert Action.from_dict(a.to_dict()).to_dict() == a.to_dict()


def test_counterfactual_drops_only_future_matching_flows():
    f = pd.DataFrame({"src_ip": ["10.0.0.5", "10.0.0.5", "10.0.0.7"], "dst_ip": ["10.0.0.9"] * 3,
                      "sport": [1, 2, 3], "dport": [22, 22, 22], "ts_end": [10.0, 100.0, 100.0]})
    out = apply_to_flows(f, recommend(1, DRV, CTX), t_from=50.0)      # block_source 10.0.0.5
    assert len(out) == 2 and set(out["ts_end"]) == {10.0, 100.0}


def test_live_executor_guards_management_ips(monkeypatch):
    monkeypatch.setenv("NV_PROTECTED_IPS", "10.0.0.5")
    res = execute(recommend(1, DRV, CTX), live=True)
    assert not res.applied and "protected" in res.message
