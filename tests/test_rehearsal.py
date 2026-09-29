from pathlib import Path

import pytest

from demo.scenario_catalog import SCENARIOS, campaign_flows, scenario_flows
from demo.rehearse import _loopback
from src.decision.rule_engine import Action
from src.features.schema import FLOW_COLUMNS
from src.live.action_executor import apply
from src.live.rehearsal import ScenarioStream


ROOT = Path(__file__).resolve().parents[1]


def test_all_rehearsal_scenarios_use_canonical_flows():
    expected = set(FLOW_COLUMNS)
    for spec in SCENARIOS:
        flows = scenario_flows(spec.id)
        assert set(flows.columns) == expected
        assert len(flows) >= 100
        assert flows["ts_end"].is_monotonic_increasing
        assert flows["src_ip"].str.startswith("10.").all()
        assert flows["dst_ip"].str.startswith("10.").all()


def test_campaign_stream_keeps_virtual_minute_scale():
    stream = ScenarioStream("reconnaissance", speed=30)
    rows = stream.collect(stream.start_wall + 12)
    assert not rows.empty
    assert stream.virtual_time_s == pytest.approx(360, abs=1)
    assert (rows["ts_end"].max() - stream.start_wall) > 300


def test_safe_enforcement_never_builds_or_runs_firewall(monkeypatch):
    called = []
    monkeypatch.setenv("NV_LIVE_MODE", "safe_rehearsal")
    monkeypatch.setattr("src.live.action_executor.subprocess.run", lambda *a, **k: called.append(a))
    result = apply(Action(id="block-source", kind="block_source", target="10.50.0.11"), live=True)
    assert result.applied is True
    assert result.dry_run is True
    assert result.mode == "safe_rehearsal"
    assert result.commands == []
    assert called == []


def test_rehearsal_cli_rejects_remote_api():
    assert _loopback("http://127.0.0.1:8000")
    assert _loopback("http://localhost:8000")
    assert not _loopback("http://192.168.0.101:8000")


def test_campaign_artifact_has_multiple_timelines():
    flows = campaign_flows()
    pairs = flows.groupby(["src_ip", "dst_ip"]).size()
    assert len(pairs) >= 4
    assert len(flows) > 10000
