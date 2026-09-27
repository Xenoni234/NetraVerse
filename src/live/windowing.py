"""In-process sliding-window buffer of canonical flows (the Redis alternative in architecture.md)."""
from __future__ import annotations

import threading

import pandas as pd

from src.features.schema import FLOW_COLUMNS


class FlowRing:
    """Holds the last ``span_s`` seconds of flows across all hosts."""

    def __init__(self, span_s: float):
        self.span_s = span_s
        self.df = pd.DataFrame(columns=list(FLOW_COLUMNS))
        self.lock = threading.Lock()

    def add(self, flows: pd.DataFrame) -> None:
        if flows is None or len(flows) == 0:
            return
        with self.lock:
            self.df = flows.copy() if len(self.df) == 0 else pd.concat([self.df, flows], ignore_index=True)

    def prune(self, now: float) -> None:
        with self.lock:
            self.df = self.df[self.df["ts_end"] >= now - self.span_s].reset_index(drop=True)

    def snapshot(self) -> pd.DataFrame:
        with self.lock:
            return self.df.copy()
