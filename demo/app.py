"""Streamlit dashboard — Network Attack Forecasting (offline).

The money shot: replay a recorded capture and watch the forecast **risk curve
rise before** the true attack window, with the measured lead time, per-horizon
forecasts, and a plain-English reason.

Run:
    streamlit run demo/app.py

Modes:
- **Replay** (default): pick a recorded windows parquet + a host; see the
  forecast timeline vs ground truth.
- **Live**: point at the predictions store written by scripts/live_forecast.py.

Fully offline — no cloud APIs. Loads a checkpoint from scripts/train_world_model.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from src.inference.engine import explain_window, lead_time_seconds, load_forecaster

st.set_page_config(page_title="Network Attack Forecasting — SIH26153", page_icon="🛡", layout="wide")

DEFAULT_CKPT = REPO_ROOT / "models" / "wm_final" / "best.ckpt"
DEFAULT_WINDOWS = REPO_ROOT / "data" / "processed" / "windows_cicids2017_all_+2018.parquet"


@st.cache_resource(show_spinner=False)
def get_forecaster(ckpt_path: str):
    return load_forecaster(ckpt_path, device="cpu")  # CPU: portable for the demo


@st.cache_data(show_spinner=False)
def get_windows(path: str) -> pd.DataFrame:
    return pd.read_parquet(path)


def contiguous_spans(mask: np.ndarray) -> list[tuple[int, int]]:
    """Start/end indices of contiguous True runs (for shading attack windows)."""
    spans, start = [], None
    for i, v in enumerate(mask):
        if v and start is None:
            start = i
        elif not v and start is not None:
            spans.append((start, i - 1)); start = None
    if start is not None:
        spans.append((start, len(mask) - 1))
    return spans


def risk_timeline_figure(tl: pd.DataFrame, horizon: int, threshold: float) -> go.Figure:
    x = pd.to_datetime(tl["window_start"])
    fig = go.Figure()

    # shade true-attack windows
    true = tl["true_label"].to_numpy().astype(bool)
    for s, e in contiguous_spans(true):
        fig.add_vrect(x0=x.iloc[s], x1=x.iloc[e], fillcolor="#c62828", opacity=0.15,
                      line_width=0, annotation_text="attack" if s == contiguous_spans(true)[0][0] else None,
                      annotation_position="top left")

    # uncertainty band if present
    lo, hi = f"risk_lo_k{horizon}", f"risk_hi_k{horizon}"
    if lo in tl and hi in tl:
        fig.add_trace(go.Scatter(x=pd.concat([x, x[::-1]]),
                                 y=pd.concat([tl[hi], tl[lo][::-1]]),
                                 fill="toself", fillcolor="rgba(33,150,243,0.15)",
                                 line=dict(width=0), hoverinfo="skip", name="uncertainty"))

    fig.add_trace(go.Scatter(x=x, y=tl[f"risk_k{horizon}"], mode="lines",
                             line=dict(color="#1565c0", width=2.5),
                             name=f"forecast risk (+{horizon*30}s)"))
    fig.add_hline(y=threshold, line=dict(color="#f9a825", dash="dash"),
                  annotation_text=f"alert threshold {threshold:.2f}")

    # first sustained alert marker
    over = tl[f"risk_k{horizon}"].to_numpy() >= threshold
    for i in range(len(over) - 1):
        if over[i] and over[i + 1]:
            fig.add_vline(x=x.iloc[i], line=dict(color="#2e7d32", dash="dot"),
                          annotation_text="first alert", annotation_position="bottom right")
            break

    fig.update_layout(height=380, margin=dict(l=10, r=10, t=30, b=10),
                      yaxis=dict(title="attack probability", range=[0, 1]),
                      xaxis=dict(title="time"), legend=dict(orientation="h", y=1.12),
                      template="plotly_white")
    return fig


def main() -> None:
    st.title("🛡 Network Attack Forecasting")
    st.caption("Forecasts an attack **before** it completes — a weather forecast for the network. "
               "World-model (LSTM encoder–decoder) trained on CIC-IDS; runs offline.")

    with st.sidebar:
        st.header("Setup")
        ckpt = st.text_input("Checkpoint", str(DEFAULT_CKPT))
        wpath = st.text_input("Recorded windows (parquet)", str(DEFAULT_WINDOWS))
        horizon = st.selectbox("Forecast horizon", [1, 2, 4],
                               format_func=lambda k: f"+{k*30}s", index=2)
        mc = st.checkbox("Show uncertainty band (MC-dropout, slower)", value=False)

    if not Path(ckpt).exists():
        st.error(f"Checkpoint not found: {ckpt}. Train first: scripts/train_world_model.py")
        return
    if not Path(wpath).exists():
        st.error(f"Windows parquet not found: {wpath}.")
        return

    fc = get_forecaster(ckpt)
    win = get_windows(wpath)
    thr = st.sidebar.slider("Alert threshold", 0.0, 1.0, float(fc.threshold), 0.005)

    # host picker — default to hosts that have an attack (interesting to watch)
    counts = win.groupby(["campaign_id", "entity_id"]).agg(
        n=("binary_label", "size"), atk=("binary_label", "max")).reset_index()
    interesting = counts[(counts.n >= 14) & (counts.atk == 1)].sort_values("n", ascending=False)
    if interesting.empty:
        st.warning("No attacked host with enough history in this file.")
        return
    labels = [f"{r.entity_id}  ({r.campaign_id}, {r.n} windows)" for r in interesting.itertuples()]
    pick = st.sidebar.selectbox("Host to inspect", range(len(labels)), format_func=lambda i: labels[i])
    row = interesting.iloc[pick]

    hw = win[(win.campaign_id == row.campaign_id) & (win.entity_id == row.entity_id)]
    with st.spinner("Forecasting…"):
        tl = fc.forecast_host_timeline(hw, mc_samples=20 if mc else 0)
    if tl.empty:
        st.warning("Not enough windows to forecast for this host.")
        return

    # headline metrics
    lt = lead_time_seconds(tl, horizon_key=f"risk_k{horizon}", threshold=thr, sustain=2)
    true = tl["true_label"].to_numpy().astype(bool)
    peak_before = None
    if true.any():
        ai = int(np.argmax(true))
        if ai > 0:
            peak_before = float(tl[f"risk_k{horizon}"].to_numpy()[:ai].max())

    c1, c2, c3 = st.columns(3)
    c1.metric("Host", str(row.entity_id))
    c2.metric("Warning lead time", f"{lt:.0f} s early" if lt and lt > 0 else ("—" if lt is None else "late"))
    c3.metric("Peak risk before attack", f"{peak_before:.0%}" if peak_before is not None else "—")

    st.plotly_chart(risk_timeline_figure(tl, horizon, thr), width='stretch')

    # explanation at the first-alert (or peak) window
    feat = [c for c in fc.feature_names if c in hw.columns]
    benign = hw[hw["binary_label"] == 0][feat].median() if (hw["binary_label"] == 0).any() else hw[feat].median()
    # pick the window where risk first crossed threshold, else peak
    rk = tl[f"risk_k{horizon}"].to_numpy()
    idx = next((i for i in range(len(rk) - 1) if rk[i] >= thr and rk[i + 1] >= thr), int(np.argmax(rk)))
    alert_time = pd.to_datetime(tl["window_start"].iloc[idx])
    cur = hw.sort_values("window_start")
    cur_row = cur[cur["window_start"] <= alert_time].iloc[-1] if (cur["window_start"] <= alert_time).any() else cur.iloc[0]
    sentence, drivers = explain_window(cur_row, benign, feat, top_k=3)

    st.subheader("Why the model is warning")
    st.info(sentence)
    if drivers:
        st.table(pd.DataFrame(drivers, columns=["feature", "now", "normal"]))

    with st.expander("What am I looking at?"):
        st.markdown(
            "- **Blue line** = forecast probability that this host is entering an attack, "
            f"**+{horizon*30}s ahead**.\n"
            "- **Red band** = when the attack was actually happening (ground truth).\n"
            "- **Green dotted line** = first sustained alert. The gap to the red band is the **lead time**.\n"
            "- Persistence / signature tools only flag once the red band starts; the world model warns during "
            "the run-up.")


if __name__ == "__main__":
    main()
