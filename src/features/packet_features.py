"""Packet-level extraction (Scapy): raw packets -> canonical flow table.

One ``FlowAssembler`` serves both offline PCAP files and the live sniffer, so a
PCAP of some traffic and the same traffic captured live produce identical flows.

Besides NetFlow-style counters it keeps the packet-level signals flow CSVs lack:
TTL, TCP window size and retransmissions (a repeated TCP sequence number that
carries payload), which feed the masked packet features of the unified schema.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import pandas as pd

from src.features.flow_features import _finalise

IDLE_TIMEOUT_S = 60.0     # flow ends after 60 s of silence
ACTIVE_TIMEOUT_S = 60.0   # long flows are cut every 60 s so each window sees them promptly


@dataclass
class _Flow:
    src: str
    dst: str
    sport: int
    dport: int
    proto: str
    first: float
    last: float
    fwd_pkts: int = 0
    bwd_pkts: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    syn: int = 0
    rst: int = 0
    fin: int = 0
    ttl_sum: float = 0.0
    ttl_n: int = 0
    win_sum: float = 0.0
    win_n: int = 0
    retrans: int = 0
    seen_seq: set = field(default_factory=set)

    def row(self) -> dict:
        return {
            "ts_start": self.first, "ts_end": self.last, "src_ip": self.src, "dst_ip": self.dst,
            "sport": self.sport, "dport": self.dport, "proto": self.proto,
            "fwd_pkts": self.fwd_pkts, "bwd_pkts": self.bwd_pkts,
            "fwd_bytes": self.fwd_bytes, "bwd_bytes": self.bwd_bytes,
            "syn": self.syn, "rst": self.rst, "fin": self.fin,
            "ttl": self.ttl_sum / self.ttl_n if self.ttl_n else float("nan"),
            "tcp_win": self.win_sum / self.win_n if self.win_n else float("nan"),
            "retrans": float(self.retrans) if self.proto == "tcp" else float("nan"),
            "label": "",
        }


class FlowAssembler:
    """Bidirectional 5-tuple flow table with idle/active timeouts."""

    def __init__(self, idle: float = IDLE_TIMEOUT_S, active: float = ACTIVE_TIMEOUT_S):
        self.idle, self.active = idle, active
        self.table: dict[tuple, _Flow] = {}
        self.done: list[dict] = []
        self.packets = 0

    @staticmethod
    def _parse(pkt):
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.inet6 import IPv6
        if IP in pkt:
            ip = pkt[IP]; ttl = ip.ttl; src, dst = ip.src, ip.dst
            frag = bool(ip.flags.MF) or ip.frag > 0
        elif IPv6 in pkt:
            ip = pkt[IPv6]; ttl = ip.hlim; src, dst = ip.src, ip.dst; frag = False
        else:
            return None
        size = len(ip)          # IP-layer length (no link header)
        if TCP in pkt:
            t = pkt[TCP]
            return (src, dst, int(t.sport), int(t.dport), "tcp", size, ttl, str(t.flags),
                    int(t.window), int(t.seq), len(bytes(t.payload)), frag)
        if UDP in pkt:
            u = pkt[UDP]
            return (src, dst, int(u.sport), int(u.dport), "udp", size, ttl, "", None, None, 0, frag)
        if ICMP in pkt:
            return (src, dst, 0, 0, "icmp", size, ttl, "", None, None, 0, frag)
        return (src, dst, 0, 0, "other", size, ttl, "", None, None, 0, frag)

    def add(self, pkt, ts: float | None = None) -> None:
        p = self._parse(pkt)
        if p is None:
            return
        ts = float(pkt.time if ts is None else ts)
        src, dst, sport, dport, proto, size, ttl, flags, win, seq, plen, _frag = p
        self.packets += 1
        key_f = (src, dst, sport, dport, proto)
        key_b = (dst, src, dport, sport, proto)
        fl = self.table.get(key_f)
        fwd = True
        if fl is None:
            fl = self.table.get(key_b)
            fwd = False
        if fl is not None and (ts - fl.last > self.idle or ts - fl.first > self.active):
            self._close(key_f if fwd else key_b)
            fl = None
        if fl is None:
            fwd = True
            fl = _Flow(src, dst, sport, dport, proto, ts, ts)
            self.table[key_f] = fl
        fl.last = max(fl.last, ts)
        if fwd:
            fl.fwd_pkts += 1; fl.fwd_bytes += size
            fl.ttl_sum += ttl; fl.ttl_n += 1
            if win is not None:
                fl.win_sum += win; fl.win_n += 1
        else:
            fl.bwd_pkts += 1; fl.bwd_bytes += size
        if proto == "tcp":
            fl.syn |= "S" in flags
            fl.rst |= "R" in flags
            fl.fin |= "F" in flags
            if plen > 0 and seq is not None:
                k = (fwd, seq)
                if k in fl.seen_seq:
                    fl.retrans += 1
                else:
                    fl.seen_seq.add(k)

    def _close(self, key) -> None:
        fl = self.table.pop(key, None)
        if fl is not None:
            fl.seen_seq = set()
            self.done.append(fl.row())

    def expire(self, now: float) -> None:
        for k, fl in list(self.table.items()):
            if now - fl.last > self.idle or now - fl.first > self.active:
                self._close(k)

    def flush_all(self) -> None:
        for k in list(self.table):
            self._close(k)

    def drain(self) -> pd.DataFrame:
        rows, self.done = self.done, []
        if not rows:
            return pd.DataFrame(columns=list(_Flow("", "", 0, 0, "", 0, 0).row()))
        return _finalise(pd.DataFrame(rows))


def packets_to_flows(packets: Iterable) -> pd.DataFrame:
    fa = FlowAssembler()
    for i, pkt in enumerate(packets):
        fa.add(pkt)
        if i % 5000 == 0:
            fa.expire(float(pkt.time))
    fa.flush_all()
    return fa.drain()


def pcap_to_flows(path: Path) -> pd.DataFrame:
    import scapy.layers.inet  # noqa: F401  (register IP/TCP/UDP dissectors before reading)
    import scapy.layers.inet6  # noqa: F401
    import scapy.layers.l2  # noqa: F401  (Ethernet link type)
    from scapy.utils import PcapReader
    with PcapReader(str(path)) as reader:
        return packets_to_flows(reader)
