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

from src.inference.baseline import BaselineThresholds, first_alert_index, signature_alerts
from src.inference.engine import explain_window, lead_time_seconds, load_forecaster
from src.inference.live import live_windows

st.set_page_config(page_title="Network Attack Forecasting — SIH26153", page_icon="🛡", layout="wide")

DEFAULT_CKPT = REPO_ROOT / "models" / "wm_final" / "best.ckpt"
DEFAULT_WINDOWS = REPO_ROOT / "data" / "processed" / "windows_cicids2017_all_+2018.parquet"
DEFAULT_SERVER_CKPT = REPO_ROOT / "models" / "wm_server" / "best.ckpt"
DEFAULT_LIVE_CSV = REPO_ROOT / "data" / "live" / "server_attack.csv"
DEFAULT_REALTIME_CSV = REPO_ROOT / "data" / "live" / "live.csv"


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
                         *, attack_start=None, autoscale: bool = False,
                         baseline_alert_time=None) -> go.Figure:
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
                          annotation_text="model alert", annotation_position="bottom right")
            break

    # signature-baseline first alert (the "dumb IDS") — the gap is the lead time
    if baseline_alert_time is not None:
        fig.add_vline(x=pd.Timestamp(baseline_alert_time), line=dict(color="#6a1b9a", dash="dot"),
                      annotation_text="baseline alert", annotation_position="top right")

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


def read_live_windows_fresh(path: str) -> pd.DataFrame:
    """Uncached per-host windows for the growing live CSV (must re-read every tick)."""
    win = live_windows(path, campaign_id="live")
    win["window_start"] = pd.to_datetime(win["window_start"]).dt.tz_localize(None)
    return win


def render_live_forecast(fc, win: pd.DataFrame, *, horizon: int, thr: float, mc: bool,
                         attack_start=None, baseline_thr: BaselineThresholds,
                         host: str | None = None) -> None:
    """Shared renderer for both live modes: forecast + signature baseline + lead time."""
    counts = win.groupby("entity_id").size().sort_values(ascending=False)
    hosts = list(counts.index)
    if not hosts:
        st.info("No flows yet — waiting for the capture feed…")
        return
    if host is None or host not in hosts:
        host = hosts[0]  # busiest host = the scanner
    hw = win[win.entity_id == host].sort_values("window_start")

    tl = fc.forecast_host_timeline(hw, mc_samples=20 if mc else 0)
    if tl.empty:
        st.warning(f"Host {host} has ≤ {fc.history_length} windows — not enough history yet. "
                   "Let the benign runway build up (5 min) before attacking.")
        return
    tl["window_start"] = pd.to_datetime(tl["window_start"]).dt.tz_localize(None)

    # --- model first sustained alert (2 windows) ---
    rk = tl[f"risk_k{horizon}"].to_numpy()
    over = rk >= thr
    model_i = next((i for i in range(len(over) - 1) if over[i] and over[i + 1]), None)
    model_t = tl["window_start"].iloc[model_i] if model_i is not None else None

    # --- signature baseline on the same (forecast) windows ---
    sig = signature_alerts(hw, baseline_thr)
    sig = sig[sig["window_start"].isin(tl["window_start"])]
    bi = first_alert_index(sig["sig_alert"].to_numpy(), sustain=1)
    base_t = sig["window_start"].iloc[bi] if bi is not None else None
    base_reason = sig["sig_reason"].iloc[bi] if bi is not None else ""

    # --- lead time = how much earlier the model warned than the dumb IDS ---
    lead_vs_base = ((base_t - model_t).total_seconds()
                    if (model_t is not None and base_t is not None) else None)
    lead_vs_launch = ((attack_start - model_t).total_seconds()
                      if (model_t is not None and attack_start is not None) else None)

    c1, c2, c3 = st.columns(3)
    c1.metric("Host", str(host))
    if model_i is None:
        c2.metric("Model", "no alert")
    elif lead_vs_base is not None:
        c2.metric("Lead vs signature IDS", f"{lead_vs_base:+.0f} s",
                  help="positive = the world model warned this many seconds before the threshold IDS fired")
    else:
        c2.metric("Model", "ALERT (IDS silent)",
                  help="model is warning while the signature IDS has not fired at all")
    c3.metric("Peak risk", f"{rk.max():.3f}")

    st.plotly_chart(
        risk_timeline_figure(tl, horizon, thr, attack_start=attack_start, autoscale=True,
                             baseline_alert_time=base_t),
        width='stretch')
    cap = ("Risk is autoscaled — absolute values are low on out-of-distribution live traffic; the "
           "**benign→attack separation, the ramp, and the gap to the baseline alert** are the signal.")
    if lead_vs_launch is not None:
        cap += f"  (vs recorded launch: {lead_vs_launch:+.0f} s)"
    st.caption(cap)

    # explanation at the alert (or peak) window vs this host's benign baseline
    feat = [c for c in fc.feature_names if c in hw.columns]
    if attack_start is not None and (hw["window_start"] < attack_start).any():
        baseline = hw[hw["window_start"] < attack_start][feat].mean()
    else:
        baseline = hw[feat].median()
    focus_t = model_t if model_t is not None else tl["window_start"].iloc[int(np.argmax(rk))]
    cur_row = hw.iloc[(hw["window_start"] - focus_t).abs().argmin()]
    sentence, drivers = explain_window(cur_row, baseline, feat, top_k=4)
    st.subheader("Why the model is warning")
    st.info(sentence)
    if base_t is not None:
        st.caption(f"Signature IDS would fire at {base_t:%H:%M:%S} on: {base_reason}.")
    if drivers:
        st.table(pd.DataFrame(drivers, columns=["feature", "now", "normal"]))


def _baseline_controls() -> BaselineThresholds:
    with st.sidebar:
        st.markdown("**Signature baseline (the 'dumb IDS' we beat)**")
        sp = st.slider("scan: distinct dst ports / 30 s", 5, 300, int(BaselineThresholds.scan_ports), 5)
        cr = st.slider("brute-force: flows / sec (few ports)", 0.5, 10.0,
                       float(BaselineThresholds.conn_rate), 0.5)
    return BaselineThresholds(scan_ports=sp, conn_rate=cr)


def live_realtime_view(horizon: int, mc: bool) -> None:
    """Real-time: auto-refresh from the growing live.csv the sync loop writes."""
    with st.sidebar:
        ckpt = st.text_input("Checkpoint", str(DEFAULT_SERVER_CKPT))
        csv = st.text_input("Live feed CSV (synced from server)", str(DEFAULT_REALTIME_CSV))
        refresh = st.slider("Refresh every (s)", 2, 15, 3)
    if not Path(ckpt).exists():
        st.error(f"Server checkpoint not found: {ckpt}. Run scripts/calibrate.py first.")
        return
    fc = get_forecaster(ckpt)
    thr = st.sidebar.slider("Alert threshold", 0.0, 0.05, float(fc.threshold), 0.0002, format="%.4f")
    baseline_thr = _baseline_controls()

    st.caption(f"🔴 LIVE — refreshing every {refresh}s from `{csv}`. "
               "Launch an attack at the server's tailnet IP and watch the risk climb.")

    @st.fragment(run_every=refresh)
    def _tick() -> None:
        stamp = pd.Timestamp.now().strftime("%H:%M:%S")
        if not Path(csv).exists():
            st.info(f"[{stamp}] waiting for the live feed at {csv} …")
            return
        try:
            win = read_live_windows_fresh(csv)
        except Exception as e:  # partial/empty CSV between writes
            st.info(f"[{stamp}] feed not ready ({type(e).__name__}) — retrying…")
            return
        st.caption(f"updated {stamp} · {len(win)} host-windows")
        render_live_forecast(fc, win, horizon=horizon, thr=thr, mc=mc,
                             baseline_thr=baseline_thr)

    _tick()


def live_static_view(horizon: int, mc: bool) -> None:
    """Static: inspect an already-captured CSV (the one-shot recording)."""
    with st.sidebar:
        ckpt = st.text_input("Checkpoint", str(DEFAULT_SERVER_CKPT))
        csv = st.text_input("Capture CSV (cicflowmeter)", str(DEFAULT_LIVE_CSV))
        launch = st.text_input("Attack launch time (server-local, blank if none)",
                               "2026-09-16 02:52:52")
    if not Path(ckpt).exists():
        st.error(f"Server checkpoint not found: {ckpt}. Run scripts/calibrate.py first.")
        return
    if not Path(csv).exists():
        st.error(f"Capture CSV not found: {csv}.")
        return
    fc = get_forecaster(ckpt)
    win = get_live_windows(csv)
    thr = st.sidebar.slider("Alert threshold", 0.0, 0.05, float(fc.threshold), 0.0002, format="%.4f")
    baseline_thr = _baseline_controls()
    attack_start = pd.Timestamp(launch) if launch.strip() else None
    hosts = list(win.groupby("entity_id").size().sort_values(ascending=False).index)
    host = st.sidebar.selectbox("Host to inspect", hosts) if hosts else None
    render_live_forecast(fc, win, horizon=horizon, thr=thr, mc=mc,
                         attack_start=attack_start, baseline_thr=baseline_thr, host=host)


def main() -> None:
    st.title("🛡 Network Attack Forecasting")
    st.caption("Forecasts an attack **before** it completes — a weather forecast for the network. "
               "World-model (LSTM encoder–decoder) trained on CIC-IDS; runs offline.")

    with st.sidebar:
        st.header("Setup")
        mode = st.radio("Data source",
                        ["Live (real-time)", "Live (static capture)", "Replay (recorded CIC)"])
        horizon = st.selectbox("Forecast horizon", [1, 2, 4],
                               format_func=lambda k: f"+{k*30}s", index=2)
        mc = st.checkbox("Show uncertainty band (MC-dropout, slower)", value=False)

    if mode == "Live (real-time)":
        live_realtime_view(horizon, mc)
        return
    if mode == "Live (static capture)":
        live_static_view(horizon, mc)
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
