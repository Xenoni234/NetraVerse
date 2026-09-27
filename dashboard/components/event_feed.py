"""Timestamped event feed: detections (per-host first alert) and analyst decisions, newest first."""
from __future__ import annotations

import streamlit as st


def event_feed(hosts: list[dict], actions: list[dict], window_s: int, t0: float | None = None,
               title: str = "Event feed") -> None:
    import time as _t
    ev = []
    for h in hosts:
        al = h.get("first_alert_step")
        if al is not None:
            ev.append((al * window_s, "alert",
                       f"forecast alert on {h['host']} — {h.get('stage_name', 'attack')} "
                       f"({h.get('peak', 0):.0%})"))
    for a in actions:
        enf = a.get("enforcement", {})
        state = "applied" if enf.get("applied") else ("rejected" if a["choice"] == "reject" else "not enforced")
        ev.append((a.get("at", 0), "decision",
                   f"{a['choice'].upper()} on {a['host']} — {a['action']['label']} ({state})"))
    # detections are relative seconds; decisions are wall-clock — show detections first if no wall time
    ev.sort(key=lambda e: e[0], reverse=True)
    rows = []
    for _, kind, text in ev[:12]:
        dot = "#C0472C" if kind == "alert" else "#4B8A5E"
        rows.append(f"<div style='display:flex;gap:8px;padding:4px 0;border-top:1px solid #23282a'>"
                    f"<span style='color:{dot}'>&#9679;</span>"
                    f"<span style='font-size:12px;color:#c8ccce'>{text}</span></div>")
    inner = "".join(rows) or "<div style='color:#6E7478;font-size:12px'>No events yet.</div>"
    st.html(f"<div class='nv-card'><div class='nv-h'>{title}</div>{inner}</div>")
