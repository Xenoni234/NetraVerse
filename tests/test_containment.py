"""Enforcement-aware live risk: an actively-applied full block contains its source, so the live
monitor drops that source's packets from the risk feed. Gated strictly on enforcement.applied."""
import time
from types import SimpleNamespace

from src.live.sniffer import LiveMonitor


def _rec(kind, target, applied, ttl=300, at=None):
    at = time.time() if at is None else at
    return {"choice": "accept", "host": "192.168.0.201", "at": at,
            "action": {"kind": kind, "target": target, "ttl_s": ttl},
            "enforcement": {"applied": applied, "expires_at": (at + ttl) if applied else None}}


def test_contained_sources_only_applied_full_blocks():
    stub = SimpleNamespace(actions=[
        _rec("block_source", "192.168.0.199", applied=True),      # counts
        _rec("isolate_host", "192.168.0.50", applied=True),       # counts
        _rec("rate_limit", "192.168.0.60", applied=True),         # not a full block -> excluded
        _rec("block_source", "192.168.0.70", applied=False),      # refused/dry-run -> excluded
    ])
    got = LiveMonitor.contained_sources(stub)
    assert got == {"192.168.0.199", "192.168.0.50"}


def test_contained_expires_with_ttl():
    old = time.time() - 400
    stub = SimpleNamespace(actions=[_rec("block_source", "192.168.0.199", applied=True, ttl=300, at=old)])
    assert LiveMonitor.contained_sources(stub) == set()          # rule TTL lapsed
