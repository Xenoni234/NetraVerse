"""End-to-end: upload CSV -> rollout + MITRE + explainability JSON -> decision re-simulates."""
from pathlib import Path

import pytest

MODEL = Path(__file__).resolve().parents[1] / "models" / "world_model.pt"
SAMPLE = Path(__file__).resolve().parents[1] / "demo" / "samples" / "cic2017_bruteforce_tuesday.csv"
pytestmark = pytest.mark.skipif(not MODEL.exists() or not SAMPLE.exists(),
                                reason="needs trained weights and demo samples")


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    from src.api.main import app
    with TestClient(app) as c:
        yield c


def test_health(client):
    h = client.get("/health").json()
    assert h["ok"] and h["horizon_s"] == 300


def test_upload_timeline_explain_decide(client):
    ov = client.post("/upload/path", params={"path": str(SAMPLE)}).json()
    assert ov["n_hosts"] > 0 and ov["labelled"]
    host = ov["focus_host"]
    tl = client.get(f"/upload/{ov['id']}/timeline", params={"host": host}).json()
    assert len(tl["risk"]) == ov["n_steps"] and len(tl["future"][0]) == 5
    step = tl["first_alert_step"] if tl["first_alert_step"] is not None else ov["n_steps"] // 2
    drv = client.get(f"/upload/{ov['id']}/explain", params={"host": host, "step": step}).json()
    assert isinstance(drv, list)
    topo = client.get(f"/upload/{ov['id']}/topology", params={"step": step}).json()
    assert topo["nodes"]
    ctx = client.get(f"/upload/{ov['id']}/decision", params={"host": host, "step": step}).json()
    assert ctx["recommended"]["label"]
    res = client.post(f"/upload/{ov['id']}/decision",
                      json={"host": host, "step": step, "choice": "accept"}).json()
    assert len(res["after"]["probs"]) == 5 and "delta" in res
    rej = client.post(f"/upload/{ov['id']}/decision",
                      json={"host": host, "step": step, "choice": "reject"}).json()
    assert rej["after"]["probs"] == rej["before"]["probs"]
