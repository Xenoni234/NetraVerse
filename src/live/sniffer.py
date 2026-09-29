"""Live capture and safe canonical-flow rehearsal inference loop."""
from __future__ import annotations

import os
import threading
import time
from collections import deque

from src.decision.rule_engine import Action
from src.features.fusion import windowize
from src.live.live_flow_gen import LiveFlowGen
from src.live.rehearsal import ScenarioStream
from src.live.windowing import FlowRing


class LiveMonitor:
    def __init__(self, service, iface: str | None = None, tick_s: float | None = None,
                 scenario: str | None = None, speed: float | None = None):
        self.svc = service
        self.E = service.E
        self.iface = iface or os.environ.get("NV_LIVE_IFACE")
        self.replay = os.environ.get("NV_LIVE_REPLAY_PCAP")
        self.scenario = scenario or os.environ.get("NV_LIVE_SCENARIO")
        self.speed = float(speed or os.environ.get("NV_LIVE_SCENARIO_SPEED", "12"))
        self.tick_s = float(tick_s or os.environ.get("NV_LIVE_TICK_S", 15))
        self.gen = LiveFlowGen()
        self.stream: ScenarioStream | None = None
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
        self._neutralized: set[str] = set()
        self._mitigated: set[str] = set()

    # -- capture -------------------------------------------------------------
    def start(self) -> None:
        if self.started:
            return
        if self.stop_evt.is_set():
            self.stop_evt = threading.Event()
        if not self.replay and not self.iface and not self.scenario:
            raise RuntimeError("Set NV_LIVE_IFACE, NV_LIVE_REPLAY_PCAP, or use a rehearsal scenario.")
        self.started = time.time()
        if self.scenario:
            self.stream = ScenarioStream(self.scenario, speed=self.speed)
        elif self.replay:
            threading.Thread(target=self._replay_loop, daemon=True).start()
        else:
            import scapy.layers.inet  # noqa: F401
            from scapy.sendrecv import AsyncSniffer
            self.sniffer = AsyncSniffer(iface=self.iface, filter=os.environ.get("NV_LIVE_BPF", "ip"),
                                        prn=self.gen.on_packet, store=False)
            self.sniffer.start()
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self) -> None:
        self.stop_evt.set()
        if self.sniffer is not None:
            self.sniffer.stop()
        self.started = None

    @property
    def is_rehearsal(self) -> bool:
        return self.stream is not None or bool(self.scenario)

    def register_action(self, record: dict) -> None:
        """Persist an approved decision and apply it to future rehearsal rows."""
        if self.stream:
            record = dict(record)
            record["at"] = self.stream.clock_now()
        self.actions.append(record)
        if self.stream and record.get("enforcement", {}).get("applied"):
            self.stream.add_action(Action.from_dict(record["action"]), at=record.get("at"))

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

    # -- inference -----------------------------------------------------------
    def _loop(self) -> None:
        while not self.stop_evt.wait(self.tick_s):
            try:
                self.tick()
            except Exception as e:  # keep the sensor alive
                self.last_error = f"{type(e).__name__}: {e}"

    def contained_sources(self, now: float | None = None) -> set[str]:
        """Return targets under an applied full containment action."""
        now = time.time() if now is None else now
        out: set[str] = set()
        for rec in self.actions:
            enf = rec.get("enforcement") or {}
            act = rec.get("action") or {}
            if not enf.get("applied") or act.get("kind") not in ("block_source", "isolate_host"):
                continue
            exp = ((rec.get("at", now) + float(act.get("ttl_s", 300)))
                   if enf.get("mode") == "safe_rehearsal" else enf.get("expires_at"))
            if exp is not None and now >= exp:
                continue
            if act.get("target"):
                out.add(act["target"])
        return out

    def _action_hosts(self, flows, action: dict) -> set[str]:
        target = action.get("target")
        peers = set(action.get("peers") or [])
        if action.get("peer"):
            peers.add(action["peer"])
        hosts: set[str] = {x for x in (target, *peers) if x}
        if target:
            touched = flows[(flows["src_ip"] == target) | (flows["dst_ip"] == target)]
            hosts.update(touched["src_ip"].astype(str).tolist())
            hosts.update(touched["dst_ip"].astype(str).tolist())
        return hosts

    def _containment_hosts(self, flows, now: float) -> tuple[set[str], set[str]]:
        neutralized: set[str] = set()
        mitigated: set[str] = set()
        for record in self.actions:
            enf = record.get("enforcement", {})
            if not enf.get("applied"):
                continue
            action = record.get("action", {})
            expires = ((record.get("at", now) + float(action.get("ttl_s", 300)))
                       if enf.get("mode") == "safe_rehearsal" else enf.get("expires_at"))
            if expires is not None and now >= expires:
                continue
            hosts = self._action_hosts(flows, action)
            mitigated.update(hosts)
            if action.get("kind") in {"block_source", "block_pair", "isolate_host", "block_egress"}:
                neutralized.update(hosts)

        for source in self.contained_sources(now):
            inbound = flows.groupby("dst_ip").size()
            blocked = flows[flows["src_ip"] == source].groupby("dst_ip").size()
            frac = (blocked / inbound.reindex(blocked.index)).fillna(0.0)
            neutralized.update(frac[frac > 0.5].index.astype(str).tolist())
        mitigated.update(neutralized)
        return neutralized, mitigated

    def tick(self, now: float | None = None) -> None:
        t_start = time.time()
        wall_now = time.time() if now is None else float(now)
        now = self.stream.clock_now(wall_now) if self.stream else wall_now
        incoming = self.stream.collect(wall_now) if self.stream else self.gen.collect(now)
        self.ring.add(incoming)
        self.ring.prune(now)
        flows = self.ring.snapshot()
        if len(flows) == 0:
            return
        w = self.E.window_s
        t0 = now - (self.E.L + 1) * w
        flows = flows[flows["ts_end"] >= t0]
        if len(flows) == 0:
            return
        fm = windowize(flows, window_s=w, t0=t0, min_flows=3, max_hosts=150, source="live")
        a = self.svc.analyze(fm, filename=f"live:{self.scenario or self.iface or self.replay}", aid="live")
        risk_before = a.fc["future"].copy()
        self._neutralized, self._mitigated = self._containment_hosts(flows, now)
        for record in self.actions:
            enf = record.get("enforcement", {})
            action = record.get("action", {})
            if not enf.get("applied"):
                continue
            hosts = self._action_hosts(flows, action)
            if not hosts:
                continue
            kind = action.get("kind")
            factor = 0.0 if kind in {"block_source", "block_pair", "isolate_host", "block_egress"} else 0.2
            mask = a.frame["host"].isin(hosts).to_numpy()
            a.fc["future"][mask] *= factor
            a.fc["now"][mask] *= factor

        last = a.frame["window"].max()
        rows = (a.frame["window"].to_numpy() == last).nonzero()[0]
        for r in rows:
            h = a.frame["host"].iat[r]
            dq = self.history.setdefault(h, deque(maxlen=240))
            risk_after = float(a.fc["future"][r].max())
            dq.append({"t": now, "risk": round(risk_after, 4),
                       "risk_before": round(float(risk_before[r].max()), 4),
                       "risk_after": round(risk_after, 4),
                       "risk_now": round(float(a.fc["now"][r]), 4),
                       "future": [round(float(v), 4) for v in a.fc["future"][r]]})
        self.latest = a
        self.ticks += 1
        self.last_error = None
        self.last_tick_ms = int((time.time() - t_start) * 1000)

    def status(self) -> dict:
        mode = "safe_rehearsal" if self.is_rehearsal else ("pcap_replay" if self.replay else "sensor")
        return {"running": bool(self.started) and not self.stop_evt.is_set(), "mode": mode, "scenario": self.scenario,
                "iface": self.iface, "replay": self.replay,
                "virtual_time": round(self.stream.virtual_time_s, 1) if self.stream else None,
                "speed": self.speed if self.is_rehearsal else None,
                "ticks": self.ticks,
                "packets": self.gen.packets if not self.stream else int(self.stream.emitted * 4),
                "flows_buffered": len(self.ring.df), "tick_s": self.tick_s,
                "last_tick_ms": self.last_tick_ms, "error": self.last_error,
                "contained": sorted(self.contained_sources()),
                "neutralized": sorted(self._neutralized), "mitigated": sorted(self._mitigated)}
