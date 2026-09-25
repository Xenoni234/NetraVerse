"""Accept / Modify / Reject panel (FR14/FR15). Rule-engine output is the headline;
driving features and (optional) narration sit underneath as details."""
from __future__ import annotations

import html

import streamlit as st


def drivers_block(drivers: list[dict], title: str = "Why the model thinks so") -> None:
    if not drivers:
        st.caption("No attribution available for this window.")
        return
    rows = []
    for d in drivers:
        sign = "+" if d["attribution"] > 0 else "−"
        cls = "nv-up" if d["attribution"] > 0 else "nv-down"
        rows.append(f"<div class='nv-drv'><span class='{cls}'>{sign}{abs(d['attribution']):.3f}</span>"
                    f"<span>{html.escape(d['sentence'])}</span></div>")
    st.html(f"<div class='nv-card'><div class='nv-h'>{html.escape(title)}</div>{''.join(rows)}</div>")


def narration_block(first: dict, fetch) -> None:
    """Secondary, clearly-labelled narration. Polls in its own fragment so a slow LLM never blocks."""
    state = {"n": first}

    def body():
        n = state["n"]
        if n.get("status") == "pending":
            try:
                n = state["n"] = fetch()
            except Exception:
                pass
        src = n.get("source", "template")
        label = ("Analyst narration - local LLM, descriptive only (the rule engine made the decision)"
                 if src.startswith("ollama") else "Analyst narration - template (local LLM off or unavailable)")
        with st.expander(label, expanded=True):
            if n.get("status") == "pending":
                st.caption("Local model is writing the note ...")
            st.write(n.get("text", ""))
            if n.get("latency_ms"):
                st.caption(f"{src} · {n['latency_ms']} ms")

    st.fragment(run_every=2 if first.get("status") == "pending" else None)(body)()


def decision_panel(ctx: dict, *, key: str, fetch_narration=None):
    """Returns (choice, action_id) when the analyst clicks, else (None, None)."""
    rec = ctx["recommended"]
    stage = ctx["stage"]
    c = ctx["context"]
    victims = ", ".join(c.get("victims") or []) or "-"
    st.html(
        "<div class='nv-card nv-decision'>"
        f"<div class='nv-h'>Decision point · {html.escape(stage['tactic'])}"
        f"{' (' + stage['tactic_id'] + ')' if stage.get('tactic_id') else ''}</div>"
        f"<div class='nv-kv'><span>alerting host</span><b class='nv-mono'>{html.escape(ctx['host'])}</b>"
        f"<span>role</span><b>{html.escape(c.get('role', '-'))}</b>"
        f"<span>attacker</span><b class='nv-mono'>{html.escape(str(c.get('attacker')))}</b>"
        f"<span>victim(s)</span><b class='nv-mono'>{html.escape(victims)}</b>"
        f"<span>forecast peak</span><b class='nv-mono'>{ctx['risk']:.0%}</b></div>"
        f"<div class='nv-rec'>Recommended: <b>{html.escape(rec['label'])}</b></div>"
        f"<div class='nv-why'>{html.escape(rec['rationale'])}</div></div>")
    alts = rec.get("alternatives", [])
    choice, action = None, None
    b1, b2, b3 = st.columns(3)
    with b1:
        if st.button("Accept", key=f"{key}-accept", use_container_width=True, type="primary"):
            choice, action = "accept", rec["id"]
    with b2:
        opt = st.selectbox("Alternative action", options=[a["id"] for a in alts],
                           format_func=lambda i: next(a["label"] for a in alts if a["id"] == i),
                           key=f"{key}-alt", label_visibility="collapsed")
        if st.button("Modify", key=f"{key}-modify", use_container_width=True):
            choice, action = "modify", opt
    with b3:
        if st.button("Reject", key=f"{key}-reject", use_container_width=True):
            choice, action = "reject", None
    with st.expander("Evidence (integrated-gradients attribution)", expanded=False):
        drivers_block(ctx.get("driving_features", []), "Top driving features")
    if fetch_narration is not None:
        narration_block(ctx.get("narration") or {}, fetch_narration)
    return choice, action
