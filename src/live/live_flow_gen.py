"""CICFlowMeter-equivalent live flow assembly: the SAME FlowAssembler the PCAP path uses."""
from __future__ import annotations

import threading
import time

import pandas as pd

from src.features.packet_features import FlowAssembler


class LiveFlowGen:
    def __init__(self):
        self.fa = FlowAssembler()
        self.lock = threading.Lock()

    def on_packet(self, pkt) -> None:
        with self.lock:
            self.fa.add(pkt)

    def collect(self, now: float | None = None, flush_active: bool = True) -> pd.DataFrame:
        """Expire finished flows; optionally also cut still-active flows so the newest
        window sees them (their counters restart in a fresh flow record)."""
        now = time.time() if now is None else now
        with self.lock:
            self.fa.expire(now)
            if flush_active:
                self.fa.flush_all()
            return self.fa.drain()

    @property
    def packets(self) -> int:
        return self.fa.packets
