"""Live path: packets -> LiveFlowGen -> sliding windows -> same service/model -> live analysis."""
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(not (ROOT / "models" / "world_model.pt").exists(), reason="needs weights")


def test_live_tick_produces_analysis():
    import scapy.layers.inet  # noqa: F401
    import scapy.layers.l2  # noqa: F401
    from scapy.utils import rdpcap

    from src.api.service import get_service
    from src.live.sniffer import LiveMonitor

    svc = get_service()
    mon = LiveMonitor(svc, iface="test", tick_s=15)
    pkts = rdpcap(str(ROOT / "tests" / "fixtures" / "http.pcap"))
    now = time.time()
    first = float(pkts[0].time)
    for p in pkts:                                    # replay as if captured during the last minute
        mon.gen.fa.add(p, ts=now - 50 + float(p.time) - first)
    mon.tick(now=now)
    assert mon.latest is not None and mon.latest.id == "live"
    ov = svc.overview(mon.latest)
    assert ov["n_hosts"] >= 1
    topo = svc.topology(mon.latest, len(mon.latest.steps) - 1)
    assert topo["nodes"]
    assert mon.history                                  # per-host live risk series recorded
