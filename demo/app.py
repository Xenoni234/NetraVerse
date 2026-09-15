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
from src.inference.live import live_windows

st.set_page_config(page_title="Network Attack Forecasting — SIH26153", page_icon="🛡", layout="wide")

DEFAULT_CKPT = REPO_ROOT / "models" / "wm_final" / "best.ckpt"
DEFAULT_WINDOWS = REPO_ROOT / "data" / "processed" / "windows_cicids2017_all_+2018.parquet"
DEFAULT_SERVER_CKPT = REPO_ROOT / "models" / "wm_server" / "best.ckpt"
DEFAULT_LIVE_CSV = REPO_ROOT / "data" / "live" / "server_attack.csv"


@st.cache_resource(show_spinner=False)
def get_forecaster(ckpt_path: str):
    return load_forecaster(ckpt_path, device="cpu")  # CPU: portable for the demo


@st.cache_data(show_spinner=False)
def get_windows(path: str) -> pd.DataFrame:
    return pd.read_parquet(path)


@st.cache_data(show_spinner=False)
def get_live_windows(path: str) -> pd.DataFrame:
    win = live_windows(path, campaign_id="live")
    win["window_start"] = pd.to_datetime(win["window_start"]).dt.tz_localize(None)
    return win


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


def risk_timeline_figure(tl: pd.DataFrame, horizon: int, threshold: float,
                         *, attack_start=None, autoscale: bool = False) -> go.Figure:
    x = pd.to_datetime(tl["window_start"])
    fig = go.Figure()

    # shade the attack region: from ground-truth labels (replay) or a known
    # launch time (live capture is unlabelled — operator supplies the time).
    if attack_start is not None:
        fig.add_vrect(x0=pd.Timestamp(attack_start), x1=x.iloc[-1], fillcolor="#c62828",
                      opacity=0.15, line_width=0, annotation_text="scan launched",
                      annotation_position="top left")
    else:
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

    if autoscale:
        ymax = max(float(tl[f"risk_k{horizon}"].max()), threshold) * 1.35
        yaxis = dict(title="attack probability (autoscaled)", range=[0, ymax], tickformat=".3f")
    else:
        yaxis = dict(title="attack probability", range=[0, 1])
    fig.update_layout(height=380, margin=dict(l=10, r=10, t=30, b=10),
                      yaxis=yaxis,
                      xaxis=dict(title="time"), legend=dict(orientation="h", y=1.12),
                      template="plotly_white")
    return fig


def live_view(horizon: int, mc: bool) -> None:
    """Live server capture: unlabelled CSV from cicflowmeter, server-calibrated model."""
    with st.sidebar:
        ckpt = st.text_input("Checkpoint", str(DEFAULT_SERVER_CKPT))
        csv = st.text_input("Live capture CSV (cicflowmeter)", str(DEFAULT_LIVE_CSV))
        launch = st.text_input("Attack launch time (server-local, blank if none)",
                               "2026-09-16 02:52:52")

    if not Path(ckpt).exists():
        st.error(f"Server checkpoint not found: {ckpt}. Run scripts/calibrate.py first.")
        return
    if not Path(csv).exists():
        st.error(f"Live CSV not found: {csv}.")
        return

    fc = get_forecaster(ckpt)
    win = get_live_windows(csv)
    thr = st.sidebar.slider("Alert threshold", 0.0, 0.05, float(fc.threshold), 0.0002, format="%.4f")
    attack_start = pd.Timestamp(launch) if launch.strip() else None

    # pick the busiest host (the scanner has the most windows / fan-out)
    counts = win.groupby("entity_id").size().sort_values(ascending=False)
    hosts = list(counts.index)
    if not hosts:
        st.warning("No hosts in this capture.")
        return
    host = st.sidebar.selectbox("Host to inspect", hosts,
                                format_func=lambda h: f"{h}  ({counts[h]} windows)")
    hw = win[win.entity_id == host].sort_values("window_start")

    with st.spinner("Forecasting…"):
        tl = fc.forecast_host_timeline(hw, mc_samples=20 if mc else 0)
    if tl.empty:
        st.warning(f"Host {host} has ≤ {fc.history_length} windows — not enough history to forecast. "
                   "Capture a longer benign runway before the attack.")
        return
    tl["window_start"] = pd.to_datetime(tl["window_start"]).dt.tz_localize(None)

    # lead time vs the known launch time (live data is unlabelled)
    rk = tl[f"risk_k{horizon}"].to_numpy()
    over = rk >= thr
    alert_idx = next((i for i in range(len(over) - 1) if over[i] and over[i + 1]), None)
    lead = None
    if alert_idx is not None and attack_start is not None:
        lead = (attack_start - tl["window_start"].iloc[alert_idx]).total_seconds()

    c1, c2, c3 = st.columns(3)
    c1.metric("Host (scanner)", str(host))
    if alert_idx is None:
        c2.metric("Alert", "none")
    elif lead is None:
        c2.metric("Alert", "fired")
    else:
        c2.metric("Detection vs onset", f"{lead:+.0f} s" if abs(lead) >= 1 else "at onset",
                  help="positive = warned before launch; ~0 = detected within one window of onset")
    c3.metric("Peak risk (scan)", f"{rk.max():.3f}")

    st.plotly_chart(
        risk_timeline_figure(tl, horizon, thr, attack_start=attack_start, autoscale=True),
        width='stretch')
    st.caption("Risk is autoscaled — absolute values are low on out-of-distribution live traffic "
               "(data ceiling + lab→server shift); the **benign→scan separation and ramp** are the signal.")

    # explanation at the alert (or peak) window vs this host's benign baseline
    feat = [c for c in fc.feature_names if c in hw.columns]
    if attack_start is not None and (hw["window_start"] < attack_start).any():
        baseline = hw[hw["window_start"] < attack_start][feat].mean()
    else:
        baseline = hw[feat].median()
    peak_ws = tl["window_start"].iloc[int(np.argmax(rk))]
    cur_row = hw.iloc[(hw["window_start"] - peak_ws).abs().argmin()]
    sentence, drivers = explain_window(cur_row, baseline, feat, top_k=4)
    st.subheader("Why the model is warning")
    st.info(sentence)
    if drivers:
        st.table(pd.DataFrame(drivers, columns=["feature", "now", "normal"]))

    with st.expander("What am I looking at?"):
        st.markdown(
            f"- **Blue line** = forecast probability this host is entering an attack, **+{horizon*30}s "
            "ahead**, from live cicflowmeter features.\n"
            "- **Red band** = when the scan was actually launched (operator-recorded).\n"
            "- **Green dotted line** = first sustained alert. For an abrupt scan this lands within one "
            "30 s window of onset; a slow/stealthy scan would push it earlier.\n"
            "- Threshold is calibrated on this server's benign traffic (see scripts/calibrate.py).")


def main() -> None:
    st.title("🛡 Network Attack Forecasting")
    st.caption("Forecasts an attack **before** it completes — a weather forecast for the network. "
               "World-model (LSTM encoder–decoder) trained on CIC-IDS; runs offline.")

    with st.sidebar:
        st.header("Setup")
        mode = st.radio("Data source", ["Replay (recorded CIC)", "Live server capture"])
        horizon = st.selectbox("Forecast horizon", [1, 2, 4],
                               format_func=lambda k: f"+{k*30}s", index=2)
        mc = st.checkbox("Show uncertainty band (MC-dropout, slower)", value=False)

    if mode == "Live server capture":
        live_view(horizon, mc)
        return

    with st.sidebar:
        ckpt = st.text_input("Checkpoint", str(DEFAULT_CKPT))
        wpath = st.text_input("Recorded windows (parquet)", str(DEFAULT_WINDOWS))

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
