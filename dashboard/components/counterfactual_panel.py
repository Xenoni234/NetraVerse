"""Counterfactual before/after: plain numbers + a two-line comparison (design.md section 5)."""
from __future__ import annotations

import plotly.graph_objects as go
import streamlit as st

from dashboard.components.probability_timeline import ACCENT, GRAY, GREEN, GRID, PANEL


def counterfactual_panel(res: dict) -> None:
    b, a = res["before"], res["after"]
    d = res["delta"]
    act = res["action"]
    enf = res.get("enforcement", {})
    st.html(
        "<div class='nv-card'>"
        f"<div class='nv-h'>Re-simulated future · {res['choice'].upper()}: {act['label']}</div>"
        "<div class='nv-kv'>"
        f"<span>peak risk, no action</span><b class='nv-mono'>{d['peak_before']:.1%}</b>"
        f"<span>peak risk, with action</span><b class='nv-mono'>{d['peak_after']:.1%}</b>"
        f"<span>change</span><b class='nv-mono'>{d['absolute_change']:+.1%}</b>"
        f"<span>enforcement</span><b>{enf.get('message', '-')}</b></div></div>")
    xs = [s // 60 for s in b["horizon_s"]]
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=xs, y=b["probs"], name="no action", mode="lines+markers",
                             line=dict(color=GRAY, dash="dot")))
    fig.add_trace(go.Scatter(x=xs, y=a["probs"], name="with action", mode="lines+markers",
                             line=dict(color=GREEN if res["choice"] != "reject" else ACCENT)))
    fig.update_layout(height=220, margin=dict(l=48, r=12, t=16, b=36), paper_bgcolor=PANEL, plot_bgcolor=PANEL,
                      font=dict(color="#E6E6E6", size=11), legend=dict(orientation="h", y=1.15),
                      xaxis=dict(title="minutes ahead", gridcolor=GRID, dtick=1),
                      yaxis=dict(title="P(attack)", range=[0, 1.05], tickformat=".0%", gridcolor=GRID))
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
