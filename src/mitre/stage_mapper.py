"""Predicted latent state -> MITRE ATT&CK stage (FR10).

The stage head is only trusted where the risk head says an attack is plausible:
below ``gate`` x threshold a step is BENIGN, otherwise the most probable attack
stage (benign excluded). A small hysteresis keeps a timeline from flickering.
"""
from __future__ import annotations

import numpy as np

from src.mitre.mitre_lookup import BENIGN, stage_info


def map_stage(risk: float, stage_probs, threshold: float, gate: float = 0.5) -> int:
    if risk < gate * threshold:
        return BENIGN
    sp = np.asarray(stage_probs, dtype=float)
    return int(np.argmax(sp[1:]) + 1)


def map_sequence(risks, stage_probs, threshold: float, gate: float = 0.5, hold: int = 2) -> list[int]:
    raw = [map_stage(r, sp, threshold, gate) for r, sp in zip(risks, stage_probs)]
    out, cur, streak, cand = [], BENIGN, 0, None
    for s in raw:
        if s == cur:
            streak, cand = 0, None
        elif s == BENIGN or cur == BENIGN:
            cur = s                              # entering/leaving an attack is immediate
        else:
            streak = streak + 1 if s == cand else 1
            cand = s
            if streak >= hold:
                cur, streak, cand = s, 0, None
        out.append(cur)
    return out


def describe(stage_id: int) -> dict:
    return stage_info(stage_id)
