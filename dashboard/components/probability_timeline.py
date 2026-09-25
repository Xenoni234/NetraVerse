"""Probability timeline (Plotly): observed forecast curve, 300 s rollout, threshold, MITRE ticks."""
from __future__ import annotations

import plotly.graph_objects as go

ACCENT = "#3B9C9B"
GRAY = "#8A9098"
MUTED = "#6B7280"
RED = "#C0472C"
GREEN = "#4B8A5E"
PANEL = "#20242B"
GRID = "#2C313A"
SHORT = ["", "Recon", "Init. access", "Lateral", "C2", "Exfil", "Impact"]


def _layout(fig: go.Figure, height: int, x_max: float) -> go.Figure:
    fig.update_layout(
        height=height, margin=dict(l=48, r=16, t=28, b=40), paper_bgcolor=PANEL, plot_bgcolor=PANEL,
        font=dict(family="Inter, 'IBM Plex Sans', 'Segoe UI', sans-serif", size=12, color="#E6E6E6"),
        showlegend=True, legend=dict(orientation="h", y=1.08, x=0, font=dict(size=11), bgcolor="rgba(0,0,0,0)"),
        hovermode="x unified",
        xaxis=dict(title="minutes since capture start", range=[0, x_max], gridcolor=GRID, zeroline=False,
                   tickfont=dict(family="'IBM Plex Mono', Consolas, monospace")),
        yaxis=dict(title="P(attack within 300 s)", range=[-0.02, 1.05], gridcolor=GRID, zeroline=False,
                   tickformat=".0%", tickfont=dict(family="'IBM Plex Mono', Consolas, monospace")),
    )
    return fig


def timeline_figure(tl: dict, cursor: int, height: int = 360, branch: dict | None = None,
                    decision_step: int | None = None, show_truth: bool = True) -> go.Figure:
    """Causal view: only windows <= cursor are drawn, plus the rollout from the cursor."""
    ws = tl["window_s"] / 60.0
    n = len(tl["risk"])
    x = [i * ws for i in range(n)]
    x_max = (n - 1) * ws + tl["horizon_s"] / 60.0
    fig = go.Figure()
    thr = tl["threshold"]
    upto = cursor + 1

    # observed (as-forecast) curve, original branch
    orig_end = upto if not (branch and decision_step is not None) else min(upto, decision_step + 1)
    fig.add_trace(go.Scatter(x=x[:orig_end], y=tl["risk"][:orig_end], mode="lines", name="forecast risk",
                             line=dict(color=ACCENT, width=2)))
    if branch and decision_step is not None and upto > decision_step:
        xs = x[decision_step:upto]
        # cost-of-inaction reference: what the unmitigated traffic produced
        fig.add_trace(go.Scatter(x=xs, y=tl["risk"][decision_step:upto], mode="lines", name="no action (recorded)",
                                 line=dict(color=GRAY, width=1.5, dash="dot")))
        fig.add_trace(go.Scatter(x=xs, y=branch["risk"][decision_step:upto], mode="lines",
                                 name=f"after: {branch['action']['kind'].replace('_', ' ')}",
                                 line=dict(color=GREEN, width=2)))

    # rollout from the cursor (predicted, not yet observed) with MC band
    src = branch if (branch and decision_step is not None and cursor >= decision_step) else tl
    fut, lo, hi = src["future"][cursor], src["lo"][cursor], src["hi"][cursor]
    fx = [x[cursor] + (k + 1) * ws for k in range(len(fut))]
    fig.add_trace(go.Scatter(x=fx + fx[::-1], y=hi + lo[::-1], fill="toself", fillcolor="rgba(59,156,155,0.12)",
                             line=dict(width=0), hoverinfo="skip", name="rollout 10-90%", showlegend=False))
    fig.add_trace(go.Scatter(x=[x[cursor]] + fx, y=[src["risk"][cursor] if "risk" in src else tl["risk"][cursor]]
                             + fut, mode="lines+markers", name="300 s rollout",
                             line=dict(color=ACCENT, width=1.5, dash="dash"), opacity=0.7,
                             marker=dict(size=4, color=ACCENT)))

    fig.add_hline(y=thr, line=dict(color=MUTED, width=1, dash="dash"),
                  annotation_text=f"alert threshold {thr:.2f}", annotation_position="top left",
                  annotation_font=dict(size=10, color=MUTED))
    fig.add_vline(x=x[cursor], line=dict(color=GRID, width=1))
    if decision_step is not None and decision_step <= cursor:
        fig.add_vline(x=x[decision_step], line=dict(color=RED, width=1, dash="dot"))
        fig.add_annotation(x=x[decision_step], y=1.03, text="decision", showarrow=False,
                           font=dict(size=10, color=RED), xanchor="left")

    # MITRE stage transitions as small flat labels along the x-axis (not bands)
    prev = 0
    for i in range(upto):
        s = tl["stage"][i]
        if s != prev and s > 0:
            fig.add_annotation(x=x[i], y=-0.02, yref="y", text=f"▲ {SHORT[s]}", showarrow=False, yanchor="top",
                               font=dict(size=10, color="#C98A2C", family="'IBM Plex Mono', monospace"),
                               xanchor="left")
        prev = s

    # labelled ground truth (only when the file carried labels): thin rug at the bottom
    if show_truth and tl.get("truth_stage"):
        tx = [x[i] for i in range(upto) if tl["truth_stage"][i] > 0]
        if tx:
            fig.add_trace(go.Scatter(x=tx, y=[0.005] * len(tx), mode="markers", name="labelled attack (truth)",
                                     marker=dict(symbol="line-ns", size=8, line=dict(width=2, color=RED)),
                                     hoverinfo="skip"))
    return _layout(fig, height, x_max)


def live_figure(series: list[dict], threshold: float, horizon_s: int, height: int = 340) -> go.Figure:
    fig = go.Figure()
    if not series:
        return _layout(fig, height, 10)
    t0 = series[0]["t"]
    x = [(p["t"] - t0) / 60 for p in series]
    fig.add_trace(go.Scatter(x=x, y=[p["risk"] for p in series], mode="lines", name="forecast risk",
                             line=dict(color=ACCENT, width=2)))
    fut = series[-1]["future"]
    fx = [x[-1] + (k + 1) for k in range(len(fut))]
    fig.add_trace(go.Scatter(x=[x[-1]] + fx, y=[series[-1]["risk"]] + fut, mode="lines", name="300 s rollout",
                             line=dict(color=ACCENT, dash="dash", width=1.5), opacity=0.7))
    fig.add_hline(y=threshold, line=dict(color=MUTED, width=1, dash="dash"))
    fig = _layout(fig, height, max(fx[-1], 10))
    fig.update_xaxes(title="minutes since monitoring started")
    return fig
