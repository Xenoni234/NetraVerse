"""The PDF incident report builds from a finished analysis and is a valid, non-empty PDF."""
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CSV = ROOT / "demo" / "samples" / "netraverse_campaign.csv"
MODEL = ROOT / "models" / "world_model.pt"
pytestmark = pytest.mark.skipif(not CSV.exists() or not MODEL.exists(),
                                reason="needs the demo campaign file and trained weights")


def test_report_pdf_bytes():
    from src.api.service import Engine, Service
    from src.features.flow_features import load_flows
    from src.features.fusion import windowize
    from src.reporting.incident_report import build_pdf

    svc = Service(Engine())
    flows, _ = load_flows(CSV)
    fm = windowize(flows, window_s=60, min_flows=5, max_hosts=200, source="demo")
    a = svc.analyze(fm, filename="netraverse_campaign.csv", aid="test")
    pdf = build_pdf(svc, a, title="test")
    assert isinstance(pdf, (bytes, bytearray)) and len(pdf) > 800
    assert bytes(pdf[:5]) == b"%PDF-"
