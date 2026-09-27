"""Live capture + windowed inference loop (Phase 8).

A Scapy AsyncSniffer feeds packets into LiveFlowGen. Every ``tick_s`` seconds the
last (L+1) x 60 s of flows are windowed with windows ending *now* (a sliding
60 s window, 15 s stride), pushed through the same fusion -> world model ->
rollout path as file uploads, and stored as the "live" analysis.

Env:
  NV_LIVE_IFACE         capture interface (e.g. wlp0s20f3); required for real capture
  NV_LIVE_BPF           optional BPF filter (default "ip")
  NV_LIVE_REPLAY_PCAP   instead of sniffing, replay a PCAP at wall-clock pace (rehearsal / fallback)
  NV_LIVE_TICK_S        inference period, default 15
"""
from __future__ import annotations

import os
import threading
import time
from collections import deque

import numpy as np

from src.features.fusion import windowize
from src.live.live_flow_gen import LiveFlowGen
from src.live.windowing import FlowRing


class LiveMonitor:
    def __init__(self, service, iface: str | None = None, tick_s: float | None = None):
        self.svc = service
        self.E = service.E
        self.iface = iface or os.environ.get("NV_LIVE_IFACE")
        self.replay = os.environ.get("NV_LIVE_REPLAY_PCAP")
        self.tick_s = float(tick_s or os.environ.get("NV_LIVE_TICK_S", 15))
        self.gen = LiveFlowGen()
        self.ring = FlowRing(span_s=(self.E.L + 2) * self.E.window_s)
        self.history: dict[str, deque] = {}
        self.ticks = 0
        self.last_error: str | None = None
        self.started = None
        self.sniffer = None
        self.stop_evt = threading.Event()
        self.actions: list[dict] = []
        self.latest = None
        self.last_tick_ms = None
        self._neutralized: set[str] = set()      # hosts contained by a real applied block (this tick)

    # -- capture -------------------------------------------------------------
    def start(self) -> None:
        if self.started:
            return
        if not self.replay and not self.iface:
            raise RuntimeError("Set NV_LIVE_IFACE (or NV_LIVE_REPLAY_PCAP) to start live capture.")
        if self.replay:
            threading.Thread(target=self._replay_loop, daemon=True).start()
        else:
            import scapy.layers.inet  # noqa: F401
            from scapy.sendrecv import AsyncSniffer
            self.sniffer = AsyncSniffer(iface=self.iface, filter=os.environ.get("NV_LIVE_BPF", "ip"),
                                        prn=self.gen.on_packet, store=False)
            self.sniffer.start()       # raises here if the interface/capture permission is missing
        self.started = time.time()
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self) -> None:
        self.stop_evt.set()
        if self.sniffer is not None:
            self.sniffer.stop()

    def _replay_loop(self) -> None:
        import scapy.layers.inet  # noqa: F401
        import scapy.layers.l2  # noqa: F401
        from scapy.utils import PcapReader
        with PcapReader(self.replay) as rd:
            first_pkt, first_wall = None, None
            for pkt in rd:
                if self.stop_evt.is_set():
                    return
                if first_pkt is None:
                    first_pkt, first_wall = float(pkt.time), time.time()
                wait = (float(pkt.time) - first_pkt) - (time.time() - first_wall)
                if wait > 0:
                    time.sleep(min(wait, 5))
                self.gen.on_packet_at(pkt, first_wall + float(pkt.time) - first_pkt) \
                    if hasattr(self.gen, "on_packet_at") else self._feed_shifted(pkt, first_pkt, first_wall)

    def _feed_shifted(self, pkt, first_pkt, first_wall) -> None:
        with self.gen.lock:
            self.gen.fa.add(pkt, ts=first_wall + float(pkt.time) - first_pkt)

    # -- inference -------------------------------------------------------------
    def _loop(self) -> None:
        while not self.stop_evt.wait(self.tick_s):
            try:
                self.tick()
            except Exception as e:  # keep the sensor alive
                self.last_error = f"{type(e).__name__}: {e}"

    def contained_sources(self, now: float | None = None) -> set[str]:
        """Source IPs under an ACTIVELY APPLIED full block (block_source / isolate_host) whose nft
        rule has not expired. Their packets are being dropped at the sensor's firewall, so they can
        no longer reach or compromise the victim - the live risk must reflect that real containment
        (never a simulated or refused action; tied strictly to enforcement.applied)."""
        now = time.time() if now is None else now
        out: set[str] = set()
        for rec in self.actions:
            enf = rec.get("enforcement") or {}
            act = rec.get("action") or {}
            if not enf.get("applied") or act.get("kind") not in ("block_source", "isolate_host"):
                continue
            exp = enf.get("expires_at")
            if exp is not None and now >= exp:
                continue                       # rule's TTL lapsed -> no longer contained
            if act.get("target"):
                out.add(act["target"])
        return out

    def tick(self, now: float | None = None) -> None:
        t_start = time.time()
        now = time.time() if now is None else now
        self.ring.add(self.gen.collect(now))
        self.ring.prune(now)
        flows = self.ring.snapshot()
        if len(flows) == 0:
            return
        w = self.E.window_s
        t0 = now - (self.E.L + 1) * w          # windows end exactly at "now" (sliding)
        flows = flows[flows["ts_end"] >= t0]
        if len(flows) == 0:
            return
        # Keep ALL flows in the analysis so the topology never loses the attacker (it stays on the
        # graph, marked contained). The firewall drop is reflected at the RISK level instead.
        fm = windowize(flows, window_s=w, t0=t0, min_flows=3, max_hosts=150, source="live")
        a = self.svc.analyze(fm, filename=f"live:{self.iface or self.replay}", aid="live")
        # Enforcement-aware risk (gated on a REAL applied block): a source under an active block, and
        # any victim whose inbound traffic is now dominated by such blocked sources, is contained -
        # the firewall is dropping it, so it is no longer a live threat. Zero its forecast so the line
        # falls, and mark it mitigated on the graph. Never touches un-blocked hosts.
        contained = self.contained_sources(now)
        self._neutralized = set()
        if contained:
            inb = flows.groupby("dst_ip").size()
            inb_c = flows[flows["src_ip"].isin(contained)].groupby("dst_ip").size()
            frac = (inb_c / inb.reindex(inb_c.index)).fillna(0.0)
            dominated = set(frac[frac > 0.5].index)          # victims now shielded by the block
            self._neutralized = set(contained) | dominated
            m = a.frame["host"].isin(self._neutralized).to_numpy()
            if m.any():
                a.fc["future"][m] = 0.0
                a.fc["now"][m] = 0.0
        last = a.frame["window"].max()
        rows = np.flatnonzero(a.frame["window"].to_numpy() == last)
        for r in rows:
            h = a.frame["host"].iat[r]
            dq = self.history.setdefault(h, deque(maxlen=240))
            dq.append({"t": float(now), "risk": round(float(a.fc["future"][r].max()), 4),
                       "risk_now": round(float(a.fc["now"][r]), 4),
                       "future": [round(float(v), 4) for v in a.fc["future"][r]]})
        self.latest = a
        self.ticks += 1
        self.last_error = None
        self.last_tick_ms = int((time.time() - t_start) * 1000)

    def status(self) -> dict:
        return {"running": bool(self.started), "iface": self.iface, "replay": self.replay,
                "ticks": self.ticks, "packets": self.gen.packets, "flows_buffered": len(self.ring.df),
                "tick_s": self.tick_s, "last_tick_ms": self.last_tick_ms, "error": self.last_error,
                "contained": sorted(self.contained_sources()),
                "neutralized": sorted(getattr(self, "_neutralized", set()))}
