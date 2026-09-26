"""NetraVerse dashboard - Streamlit entrypoint.

    streamlit run dashboard/app.py          (backend: uvicorn src.api.main:app)

CSV Upload / PCAP Upload replay the file window by window: the forecast curve
builds causally, the 3D host graph highlights attacker and victim, playback
pauses at the first sustained alert for an Accept / Modify / Reject decision,
and the replay continues on the re-simulated (mitigated) traffic.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from dashboard.components import api_client as api  # noqa: E402
from dashboard.components.counterfactual_panel import counterfactual_panel, outcome_comparison  # noqa: E402
from dashboard.components.state_graph import STAGE_COLORS, state_graph  # noqa: E402
from dashboard.components.decision_panel import decision_panel, drivers_block  # noqa: E402
from dashboard.components.probability_timeline import live_figure, timeline_figure  # noqa: E402
from dashboard.components.topology_view import topology_view  # noqa: E402

st.set_page_config(page_title="NetraVerse", page_icon=":material/lan:", layout="wide",
                   initial_sidebar_state="expanded")
st.html(f"<style>{(ROOT / 'dashboard' / 'styles' / 'theme.css').read_text(encoding='utf-8')}</style>")

SPEEDS = {"0.5x": 2.0, "1x": 1.0, "2x": 0.5, "4x": 0.25}
STAGES = ["Benign", "Reconnaissance", "Initial Access", "Lateral Movement", "Command & Control",
          "Exfiltration", "Impact"]
S = st.session_state


def _init() -> None:
    for k, v in {"aid": None, "ov": None, "focus": None, "tl": {}, "cursor": 0, "playing": False,
                 "speed": "1x", "decision_step": None, "decided": False, "result": None, "branch": None,
                 "pending_ctx": None}.items():
        S.setdefault(k, v)


_init()


def reset_replay(keep_file: bool = True) -> None:
    if S.aid:
        try:
            api.reset(S.aid)
        except api.ApiError:
            pass
    S.update(cursor=0, playing=False, decided=False, result=None, branch=None, pending_ctx=None)
    if S.ov and S.focus:
        S.decision_step = S.ov["decision_step"]          # file-wide first sustained alert
        S.decision_host = S.ov["focus_host"]


def get_tl(host: str) -> dict:
    if host not in S.tl:
        S.tl[host] = api.timeline(S.aid, host)
    return S.tl[host]


def load_analysis(ov: dict) -> None:
    S.update(aid=ov["id"], ov=ov, tl={}, focus=ov["focus_host"])
    reset_replay()


# ------------------------------------------------------------------ sidebar
with st.sidebar:
    st.html("<div class='nv-title'>NETRAVERSE</div>"
            "<div class='nv-sub'>World-model attack forecasting · PS 26153</div>")
    mode = st.radio("Mode", ["CSV Upload", "PCAP Upload", "Live Monitor"], key="mode")
    h = api.health()
    if h:
        tr = ", ".join(h.get("trained_on") or [])
        st.html(f"<div class='nv-status'>backend <span class='nv-pill ok'>online</span> {h['device']}<br>"
                f"model {Path(h['checkpoint']).name}<br>trained on {tr}<br>"
                f"window {h['window_s']} s · horizon {h['horizon_s']} s · threshold {h['threshold']:.3f}</div>")
    else:
        st.html(f"<div class='nv-status'>backend <span class='nv-pill atk'>offline</span><br>{api.API_URL}</div>")
    if mode == "Live Monitor":
        st.text_input("Operator token", type="password", key="op_token",
                      help="Required by the sensor before a real nftables rule is applied.")


# ------------------------------------------------------------------ file modes
def file_intake(kind: str) -> None:
    types = ["csv", "binetflow"] if kind == "csv" else ["pcap", "pcapng", "cap"]
    c1, c2 = st.columns([2, 1])
    with c1:
        f = st.file_uploader(f"{'Flow CSV' if kind == 'csv' else 'Packet capture'} to replay", type=types,
                             key=f"up-{kind}")
    with c2:
        folder = ROOT / "demo" / ("samples" if kind == "csv" else "fallback_pcap")
        pats = ("*.csv", "*.binetflow") if kind == "csv" else ("*.pcap", "*.pcapng")
        samples = sorted(p for pat in pats for p in folder.glob(pat))
        sample = st.selectbox("or a bundled sample", ["-"] + [p.name for p in samples], key=f"sample-{kind}")
    go_ = st.button("Analyse", type="primary", disabled=not (f or sample != "-"), key=f"go-{kind}")
    if go_:
        with st.spinner("Fusing features, encoding latent state, rolling out 300 s forecasts ..."):
            try:
                if f is not None:
                    ov = api.upload(f.name, f.getvalue())
                else:
                    sub = "samples" if kind == "csv" else "fallback_pcap"
                    ov = api.upload_path(f"demo/{sub}/{sample}")
                load_analysis(ov)
            except api.ApiError as e:
                st.error(str(e))


def summary_strip(ov: dict) -> None:
    cols = st.columns(6)
    alert = next((hh for hh in ov["hosts"] if hh["first_alert_step"] is not None), None)
    cols[0].metric("file", ov["filename"][:22])
    cols[1].metric("flows", f"{ov['n_flows']:,}")
    cols[2].metric("hosts", ov["n_hosts"])
    cols[3].metric("duration", f"{ov['n_steps'] * ov['window_s'] // 60} min")
    cols[4].metric("first alert", f"t+{alert['first_alert_step'] * ov['window_s'] // 60} min" if alert else "none")
    cols[5].metric("alerting hosts", sum(1 for hh in ov["hosts"] if hh["first_alert_step"] is not None))


def replay_controls(n: int) -> None:
    c = st.columns([1, 1, 1, 1, 1.4, 6])
    if c[0].button("⏸ Pause" if S.playing else "▶ Play", key="play", use_container_width=True):
        if S.pending_ctx is None:
            S.playing = not S.playing
            if S.cursor >= n - 1:
                S.cursor = 0
            st.rerun()                      # full rerun re-arms the fragment timer
    if c[1].button("⏮", key="restart", help="Restart replay (clears the decision)", use_container_width=True):
        reset_replay()
        st.rerun()
    if c[2].button("◀", key="back", help="Step back", use_container_width=True):
        S.playing = False
        S.cursor = max(0, S.cursor - 1)
    if c[3].button("▶|", key="fwd", help="Step forward", use_container_width=True):
        S.playing = False
        S.cursor = min(n - 1, S.cursor + 1)
    sp = c[4].selectbox("speed", list(SPEEDS), index=list(SPEEDS).index(S.speed), label_visibility="collapsed")
    if sp != S.speed:
        S.speed = sp
        st.rerun()
    new = c[5].slider("scrub", 0, n - 1, S.cursor, label_visibility="collapsed", key=f"scrub-{S.aid}-{S.cursor}")
    if new != S.cursor:
        S.playing = False
        S.cursor = new


def replay_body() -> None:
    ov = S.ov
    n = ov["n_steps"]
    tl = get_tl(S.focus)
    # advance the causal cursor
    if S.playing:
        if S.decision_step is not None and not S.decided and S.cursor >= S.decision_step:
            S.cursor = S.decision_step
            S.playing = False
        elif S.cursor < n - 1:
            S.cursor += 1
        else:
            S.playing = False
    if (S.decision_step is not None and not S.decided and S.cursor == S.decision_step and S.pending_ctx is None):
        S.focus = S.get("decision_host") or S.focus       # jump to the alerting host
        S.branch = None
        S.pending_ctx = api.decision_context(S.aid, S.focus, S.cursor)
        S.playing = False
        st.rerun()                          # stop the timer; the decision panel takes over

    replay_controls(n)
    cur = S.cursor
    t_min = cur * ov["window_s"] // 60
    left, right = st.columns([1.05, 1])
    with left:
        snap = api.topology(S.aid, cur)
        clicked = topology_view(snap, key="topo-file", height=540, selected=S.focus)
        roles = {nd["id"]: nd["role"] for nd in snap["nodes"]}
        atk = [k for k, v in roles.items() if v == "attacker"]
        vic = [k for k, v in roles.items() if v == "victim"]
        mit = [k for k, v in roles.items() if v == "mitigated"]
        st.html("<div class='nv-status'>"
                f"t+{t_min} min · window {cur + 1}/{n} · "
                + "".join(f"<span class='nv-pill atk'>{a}</span>" for a in atk)
                + "".join(f"<span class='nv-pill warn'>{v}</span>" for v in vic)
                + "".join(f"<span class='nv-pill ok'>{m}</span>" for m in mit) + "</div>")
        if clicked and clicked != S.focus and clicked in {hh["host"] for hh in ov["hosts"]}:
            S.focus = clicked
            S.branch = None
            st.rerun()
    with right:
        tlf = get_tl(S.focus)
        if S.decided and S.branch is None and S.result and S.result["choice"] != "reject":
            S.branch = api.branch(S.aid, S.focus)
        dstep = S.result["step"] if S.result else S.decision_step
        on_branch = bool(S.branch and S.result and cur >= S.result["step"])
        src = S.branch if on_branch else tlf
        fig = timeline_figure(tlf, cur, height=340, branch=S.branch if S.decided else None, decision_step=dstep)
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False}, key="tl-chart")
        risk = src["risk"][cur]
        stg = src["stage"][cur]
        st.html("<div class='nv-status'>"
                f"host <b class='nv-mono'>{S.focus}</b> · state s{cur} · P(attack ≤300 s) <b>{risk:.1%}</b> · "
                f"stage <b>{STAGES[stg]}</b>"
                + (f" · labelled: {STAGES[tlf['truth_stage'][cur]]}" if tlf.get("truth_stage") else "")
                + "</div>")
        forecast_strip(src, tlf, cur)
        detection_banner(tlf, cur)
        if S.pending_ctx is not None and not S.decided:
            choice, action = decision_panel(
                S.pending_ctx, key=f"dec-{S.aid}",
                fetch_narration=lambda: api.narration(S.aid, S.focus, S.cursor))
            if choice:
                with st.spinner("Applying action to the traffic and re-running the rollout ..."):
                    res = api.decide(S.aid, S.focus, S.cursor, choice, action)
                S.update(result=res, decided=True, pending_ctx=None, branch=None, playing=True)
                st.rerun(scope="app")
        elif S.result is not None:
            outcome_comparison(S.result)
            with st.expander("Rollout from the decision point: no action vs with action", expanded=False):
                counterfactual_panel(S.result)
        else:
            if tlf["present"][cur]:
                drivers_block(api.explain(S.aid, S.focus, cur),
                              f"Why {risk:.0%} at t+{t_min} min (integrated gradients)")
    # world-model states: observed s_t and the K imagined future states with forecast ATT&CK stages
    st.plotly_chart(state_graph(tlf, cur, branch=S.branch if S.decided else None, decision_step=dstep),
                    use_container_width=True, config={"displayModeBar": False}, key="state-graph")


def forecast_strip(src: dict, tl: dict, cur: int) -> None:
    """Forecast MITRE ATT&CK stage + risk for each imagined step from the current state."""
    fut = src["future"][cur]
    fst = src.get("future_stage", tl["future_stage"])[cur]
    ws = tl["window_s"]
    chips = "".join(f"<span class='nv-stage' style='border-color:{STAGE_COLORS[s]};color:{STAGE_COLORS[s] if s else '#9AA0A6'}'>"
                    f"+{(k + 1) * ws}s {STAGES[s]} {p:.0%}</span>" for k, (s, p) in enumerate(zip(fst, fut)))
    st.html(f"<div class='nv-card nv-fc'><div class='nv-h'>Forecast from s{cur}: next 300 s "
            f"(imagined states, MITRE ATT&CK)</div>{chips}</div>")


def detection_banner(tl: dict, cur: int) -> None:
    al = tl.get("first_alert_step")
    if al is None or cur < al:
        return
    ws = tl["window_s"]
    parts = [f"Alert raised at <b>t+{al * ws // 60} min</b> (state s{al})."]
    if tl.get("forecast_lead_s"):
        parts.append(f"The rollout forecast the attack <b>{tl['forecast_lead_s']} s before</b> its first "
                     f"labelled window (from state s{tl['forecast_hit_step']}).")
    lt = tl.get("lead_time_s")
    if lt is not None:
        parts.append(f"<b>{abs(lt)} s {'before' if lt > 0 else 'after'}</b> the first labelled attack flow"
                     + (" (detected at onset, not forecast in advance)." if lt <= 0 else "."))
    elif tl.get("truth_stage") is None:
        parts.append("No labels in this file - lead time vs ground truth not available.")
    if tl.get("predicted_compromise_s_after_alert"):
        parts.append(f"At the alert, the model forecast the attack to continue/escalate within "
                     f"<b>{tl['predicted_compromise_s_after_alert']} s</b>.")
    st.html(f"<div class='nv-card nv-banner'><div class='nv-h'>Detection</div>{' '.join(parts)}</div>")


def file_mode(kind: str) -> None:
    file_intake(kind)
    if not S.ov:
        st.info("Upload a file (or pick a bundled sample) to replay it through the world model.")
        return
    ov = S.ov
    summary_strip(ov)
    run_every = SPEEDS[S.speed] if S.playing else None
    st.fragment(run_every=run_every)(replay_body)()

    with st.expander("All hosts (forecast peaks)", expanded=False):
        df = pd.DataFrame(ov["hosts"])
        df["first_alert_min"] = df["first_alert_step"].map(lambda v: None if pd.isna(v) else int(v) * ov["window_s"] // 60)
        st.dataframe(df[["host", "peak", "stage_name", "first_alert_min", "flows"] +
                        (["truth_attack_steps"] if ov["labelled"] else [])],
                     hide_index=True, use_container_width=True,
                     column_config={"peak": st.column_config.ProgressColumn("peak risk", min_value=0, max_value=1,
                                                                             format="percent")})
        pick = st.selectbox("Focus host", [hh["host"] for hh in ov["hosts"]],
                            index=[hh["host"] for hh in ov["hosts"]].index(S.focus))
        if pick != S.focus:
            S.focus = pick
            S.branch = None
            st.rerun()


# ------------------------------------------------------------------ live mode
def live_body() -> None:
    try:
        stt = api.live_state()
    except api.ApiError as e:
        st.error(str(e))
        return
    status = stt["status"]
    st.html(f"<div class='nv-status'>sensor {'<span class=\"nv-pill ok\">capturing</span>' if status.get('running') else '<span class=\"nv-pill\">stopped</span>'}"
            f" iface {status.get('iface') or status.get('replay') or '-'} · packets {status.get('packets', 0):,} · "
            f"flows buffered {status.get('flows_buffered', 0):,} · ticks {status.get('ticks', 0)} · "
            f"inference {status.get('last_tick_ms') or '-'} ms"
            + (f" · <span class='nv-pill atk'>{status['error']}</span>" if status.get("error") else "") + "</div>")
    ov = stt.get("overview")
    if not status.get("running"):
        st.info(
            "The live sensor is not running. It captures on the machine running the API, so start the "
            "backend there with a capture interface, then press **Start sensor**:\n\n"
            "- Linux sensor (root / CAP_NET_RAW): `NV_LIVE_IFACE=wlp0s20f3 uvicorn src.api.main:app --host 0.0.0.0`\n"
            "- Windows needs Npcap installed; use the adapter name, e.g. `NV_LIVE_IFACE=\"Wi-Fi\"`\n"
            "- No network / rehearsal: `NV_LIVE_REPLAY_PCAP=demo/fallback_pcap/live_demo.pcap`\n\n"
            "Point this dashboard at a remote sensor with `NV_API_URL=http://<sensor>:8000`.")
        return
    if not ov:
        st.info("Sensor running - waiting for the first 60 s window of live traffic ...")
        return
    hosts = sorted(ov["hosts"], key=lambda hh: -hh["peak"])
    focus = S.get("live_focus") or hosts[0]["host"]
    if focus not in {hh["host"] for hh in hosts}:
        focus = hosts[0]["host"]
    left, right = st.columns([1.05, 1])
    with left:
        snap = api.live_topology()
        clicked = topology_view(snap, key="topo-live", height=540, selected=focus)
        if clicked:
            S.live_focus = clicked
    with right:
        S.live_focus = st.selectbox("Host", [hh["host"] for hh in hosts],
                                    index=[hh["host"] for hh in hosts].index(focus), key="live_host")
        series = stt["series"].get(S.live_focus, [])
        st.plotly_chart(live_figure(series, ov["threshold"], ov["horizon_s"]), use_container_width=True,
                        config={"displayModeBar": False}, key="live-chart")
        cur = next(hh for hh in hosts if hh["host"] == S.live_focus)
        if cur["peak"] >= ov["threshold"]:
            ctx = api.live_decision_context(S.live_focus)
            if not S.get("op_token"):
                st.warning("Enter the operator token in the sidebar - Accept/Modify apply a REAL firewall "
                           "rule on the sensor and are refused without it.")
            choice, action = decision_panel(ctx, key="live-dec",
                                            fetch_narration=lambda: api.live_narration(S.live_focus))
            if choice:
                try:
                    S.live_result = api.live_decide(S.live_focus, choice, action, S.get("op_token"))
                    S.live_error = None
                except api.ApiError as e:
                    S.live_error = str(e)
            if S.get("live_error"):                     # persists across the 4 s refreshes
                st.error(f"Decision not applied - {S.live_error}")
        else:
            drivers_block(api.live_explain(S.live_focus), "Current drivers (integrated gradients)")
        if S.get("live_result"):
            counterfactual_panel(S.live_result)
            if series:
                mb = S.live_result.get("measured_before")
                st.html(f"<div class='nv-status'>measured risk at decision {mb if mb is not None else '-'} → "
                        f"now {series[-1]['risk']:.1%} (re-measured on live traffic)</div>")
        if stt.get("actions"):
            st.dataframe(pd.DataFrame([{"host": a["host"], "choice": a["choice"], "action": a["action"]["label"],
                                        "applied": a["enforcement"].get("applied"),
                                        "message": a["enforcement"].get("message")} for a in stt["actions"]]),
                         hide_index=True, use_container_width=True)


def live_mode() -> None:
    c1, _ = st.columns([1, 5])
    if c1.button("Start sensor", type="primary"):
        try:
            api.live_start()
        except api.ApiError as e:
            st.error(f"{e}  - set NV_LIVE_IFACE on the API host (or NV_LIVE_REPLAY_PCAP to rehearse).")
    st.fragment(run_every=4)(live_body)()


if mode == "CSV Upload":
    file_mode("csv")
elif mode == "PCAP Upload":
    file_mode("pcap")
else:
    live_mode()
