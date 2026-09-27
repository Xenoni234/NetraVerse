"""MITRE ATT&CK kill-chain strip: the seven stages Recon -> Impact with the reached/forecast stage
lit, plus the tactic id and a one-line containment for each. Fills the width under the topology."""
from __future__ import annotations

import streamlit as st

from dashboard.components.state_graph import STAGE_COLORS

STAGES = [
    ("BENIGN", "", "no action"),
    ("Reconnaissance", "TA0043", "block the scanner before it picks a target"),
    ("Initial Access", "TA0001", "cut the brute-forced service path"),
    ("Lateral Movement", "TA0008", "isolate the pivot host"),
    ("Command & Control", "TA0011", "block the beacon egress"),
    ("Exfiltration", "TA0010", "throttle / block the outbound transfer"),
    ("Impact", "TA0040", "rate-limit the flood, keep the service up"),
]


def kill_chain(reached: int, forecast: int | None = None, title: str = "MITRE ATT&CK kill chain") -> None:
    """reached = highest labelled/observed stage; forecast = stage the model projects next."""
    cells = []
    for i, (name, tid, remedy) in enumerate(STAGES[1:], start=1):
        col = STAGE_COLORS[i] if i < len(STAGE_COLORS) else "#9AA0A6"
        on = i <= (reached or 0)
        nxt = forecast is not None and i == forecast and not on
        bg = f"{col}22" if on else ("#20242688" if nxt else "transparent")
        bd = col if (on or nxt) else "#2a2f31"
        tx = col if (on or nxt) else "#6E7478"
        mark = "reached" if on else ("forecast" if nxt else "")
        cells.append(
            f"<div style='flex:1;min-width:0;border:1px solid {bd};border-radius:4px;padding:6px 8px;"
            f"background:{bg}'>"
            f"<div style='font:600 11px/1.3 var(--nv-sans);color:{tx}'>{name}</div>"
            f"<div style='font:10px var(--nv-mono);color:#6E7478'>{tid} {('· ' + mark) if mark else ''}</div>"
            f"<div style='font:10px/1.3 var(--nv-sans);color:#8a9095;margin-top:3px'>{remedy}</div></div>")
    arrow = "<div style='align-self:center;color:#4a4f51;padding:0 2px'>&rsaquo;</div>"
    strip = arrow.join(cells)
    st.html(f"<div class='nv-card'><div class='nv-h'>{title}</div>"
            f"<div style='display:flex;gap:2px;align-items:stretch'>{strip}</div></div>")
