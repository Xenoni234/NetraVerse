"""Offline render smoke-test for the new dashboard panels (no API needed): each component must
render mock data without raising - guards against regressions like indexing STAGE_COLORS wrong."""
import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest

SCRIPT = """
import streamlit as st
from dashboard.components.killchain import kill_chain
from dashboard.components.campaign_board import campaign_board
from dashboard.components.event_feed import event_feed
from dashboard.components.whatif_panel import whatif_panel, audit_csv
from dashboard.components.narration_panel import narration_panel

hosts = [
    {"host": "10.20.0.11", "peak": 1.0, "stage": 2, "stage_name": "INITIAL_ACCESS", "first_alert_step": 3},
    {"host": "10.20.0.14", "peak": 0.9, "stage": 6, "stage_name": "IMPACT", "first_alert_step": 8},
]
actions = [{"host": "10.20.0.11", "choice": "accept", "at": 1.0,
            "action": {"label": "Block all traffic from 10.13.37.5", "kind": "block_source"},
            "enforcement": {"applied": True, "message": "Rule applied on the sensor."}}]
ctx = {"recommended": {"kind": "block_source", "label": "Block all traffic from 10.13.37.5", "id": "b1",
        "alternatives": [{"kind": "rate_limit", "label": "Rate-limit 10.13.37.5", "id": "r1", "alternatives": []}]}}

kill_chain(reached=2, forecast=3)
campaign_board(hosts, 0.429, 60, contained={"10.20.0.11"})
event_feed(hosts, actions, 60)
whatif_panel(ctx)
narration_panel(lambda: {"text": "Scan detected; blocking the source prevents the break-in.", "source": "template"})
assert audit_csv(actions).startswith(b"host,choice")
"""


def test_panels_render():
    at = AppTest.from_string(SCRIPT, default_timeout=30)
    at.run()
    assert not at.exception, [str(e.value) for e in at.exception]
