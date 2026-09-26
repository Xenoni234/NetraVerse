"""World-model state graph: one node per observed 60 s state s_t, plus the K imagined states
the rollout forecasts from the current state (with their forecast MITRE stage and risk).

Observed states are filled circles coloured by the mapped ATT&CK stage and sized by risk;
imagined states are hollow, joined by dashed transitions - the "states + next-k forecast"
view of the replay.
"""
from __future__ import annotations

import plotly.graph_objects as go

from dashboard.components.probability_timeline import GRID, PANEL

STAGE_COLORS = ["#8A9098", "#C98A2C", "#C0472C", "#B5673A", "#9E3B3B", "#7D8B3A", "#6F2F2F"]
STAGE_SHORT = ["Benign", "Recon", "Init. access", "Lateral", "C2", "Exfil", "Impact"]
WINDOW = 24          # observed states shown (scrolls with the cursor)


def state_graph(tl: dict, cursor: int, branch: dict | None = None, decision_step: int | None = None,
                height: int = 250) -> go.Figure:
    src = branch if (branch and decision_step is not None and cursor >= decision_step) else tl
    lo = max(0, cursor - WINDOW + 1)
    xs = list(range(lo, cursor + 1))
    risk = [(branch["risk"][i] if (branch and decision_step is not None and i >= decision_step) else tl["risk"][i])
            for i in xs]
    stage = [(branch["stage"][i] if (branch and decision_step is not None and i >= decision_step) else tl["stage"][i])
             for i in xs]
    thr = tl["threshold"]
    fig = go.Figure()
    # observed transitions
    fig.add_trace(go.Scatter(x=xs, y=[0] * len(xs), mode="lines", line=dict(color="#3A4250", width=2),
                             hoverinfo="skip", showlegend=False))
    fig.add_trace(go.Scatter(
        x=xs, y=[0] * len(xs), mode="markers", showlegend=False,
        marker=dict(size=[10 + 22 * r for r in risk], color=[STAGE_COLORS[s] for s in stage],
                    line=dict(width=[2.5 if r >= thr else 0.5 for r in risk], color="#E6E6E6")),
        customdata=[[f"s{i}", STAGE_SHORT[s], r] for i, s, r in zip(xs, stage, risk)],
        hovertemplate="%{customdata[0]} (observed)<br>%{customdata[1]}<br>P(attack≤300 s) %{customdata[2]:.0%}"
                      "<extra></extra>"))
    # imagined next-K states from the cursor
    fut = src["future"][cursor]
    fst = src.get("future_stage", tl["future_stage"])[cursor]
    fx = [cursor + k + 1 for k in range(len(fut))]
    fig.add_trace(go.Scatter(x=[cursor] + fx, y=[0] + [1] * len(fx), mode="lines", hoverinfo="skip",
                             line=dict(color="#3B9C9B", width=1.5, dash="dash"), showlegend=False))
    fig.add_trace(go.Scatter(
        x=fx, y=[1] * len(fx), mode="markers+text", showlegend=False,
        marker=dict(size=[10 + 22 * p for p in fut], color="rgba(0,0,0,0)",
                    line=dict(width=2, color=[STAGE_COLORS[s] for s in fst])),
        text=[f"{STAGE_SHORT[s]}<br>{p:.0%}" for s, p in zip(fst, fut)], textposition="top center",
        textfont=dict(size=10, color="#C9CDD2", family="'IBM Plex Mono', monospace"),
        customdata=[[f"ŝ{cursor}+{k + 1}", (k + 1) * tl["window_s"], STAGE_SHORT[s], p]
                    for k, (s, p) in enumerate(zip(fst, fut))],
        hovertemplate="%{customdata[0]} (imagined, +%{customdata[1]} s)<br>forecast %{customdata[2]}"
                      "<br>P(attack) %{customdata[3]:.0%}<extra></extra>"))
    if decision_step is not None and lo <= decision_step <= cursor:
        fig.add_vline(x=decision_step, line=dict(color="#C0472C", width=1, dash="dot"))
    # legend chips for stages present
    used = sorted(set(stage) | set(fst))
    for s in used:
        fig.add_trace(go.Scatter(x=[None], y=[None], mode="markers", name=STAGE_SHORT[s],
                                 marker=dict(size=9, color=STAGE_COLORS[s])))
    fig.update_layout(
        height=height, margin=dict(l=40, r=16, t=30, b=30), paper_bgcolor=PANEL, plot_bgcolor=PANEL,
        font=dict(color="#E6E6E6", size=11), legend=dict(orientation="h", y=1.18, x=0, font=dict(size=10)),
        xaxis=dict(title="state index (60 s windows)", gridcolor=GRID, zeroline=False,
                   range=[lo - 0.7, cursor + len(fut) + 0.9], dtick=2),
        yaxis=dict(tickvals=[0, 1], ticktext=["observed s_t", "imagined ŝ_t+k"], range=[-0.6, 1.9],
                   gridcolor=GRID, zeroline=False))
    return fig
