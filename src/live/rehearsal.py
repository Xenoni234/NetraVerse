"""Local-only canonical flow stream for repeatable live forecasting.

This module intentionally has no packet, socket, subprocess or capture imports.
It advances a validated flow scenario on a virtual clock and applies approved
actions to future rows before the normal live windowing pipeline sees them.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass

import pandas as pd

from demo.scenario_catalog import get_scenario, scenario_flows
from src.decision.counterfactual import affected_mask, KEEP_FRACTION
from src.decision.rule_engine import Action


@dataclass
class RehearsalAction:
    action: Action
    at: float


class ScenarioStream:
    """Emit canonical rows at an accelerated wall-clock pace."""

    def __init__(self, scenario: str, speed: float = 12.0, root=None):
        self.spec = get_scenario(scenario)
        self.speed = max(0.1, float(speed))
        self.df = scenario_flows(self.spec.id, root=root, include_campaign=True)
        self.start_wall = time.time()
        self.base = float(self.df["ts_start"].min())
        self.actions: list[RehearsalAction] = []
        self.lock = threading.Lock()
        self.emitted = 0
        self.last_virtual_s = 0.0

        # Convert the scenario's relative seconds into a virtual epoch. A high
        # speed advances this clock faster, but never compresses 60 s model
        # windows into one physical minute.
        self.df = self.df.copy()
        self.df["ts_start"] = self.start_wall + (self.df["ts_start"] - self.base)
        self.df["ts_end"] = self.start_wall + (self.df["ts_end"] - self.base)

    @property
    def virtual_time_s(self) -> float:
        return self.last_virtual_s

    def clock_now(self, wall_now: float | None = None) -> float:
        wall_now = time.time() if wall_now is None else float(wall_now)
        return self.start_wall + max(0.0, wall_now - self.start_wall) * self.speed

    @property
    def finished(self) -> bool:
        return self.emitted >= len(self.df)

    def add_action(self, action: Action, at: float | None = None) -> None:
        with self.lock:
            self.actions.append(RehearsalAction(action, time.time() if at is None else float(at)))

    def _apply_actions(self, rows: pd.DataFrame) -> pd.DataFrame:
        out = rows
        for rec in self.actions:
            action = rec.action
            if action.kind == "monitor":
                continue
            hit = affected_mask(out, action) & (out["ts_end"] >= rec.at)
            if action.kind in ("rate_limit", "throttle_egress"):
                idx = hit[hit].index.to_numpy()[::int(round(1 / KEEP_FRACTION))]
                hit.loc[idx] = False
            out = out.loc[~hit].copy()
        return out

    def collect(self, now: float | None = None) -> pd.DataFrame:
        wall_now = time.time() if now is None else float(now)
        with self.lock:
            virtual_now = self.clock_now(wall_now)
            self.last_virtual_s = max(0.0, virtual_now - self.start_wall)
            remaining = self.df.iloc[self.emitted:]
            due = remaining[remaining["ts_end"] <= virtual_now].copy()
            if due.empty:
                return self.df.iloc[0:0].copy()
            self.emitted += len(due)
            return self._apply_actions(due).reset_index(drop=True)


__all__ = ["ScenarioStream"]
