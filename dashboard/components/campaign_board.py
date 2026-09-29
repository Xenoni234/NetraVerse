"""Campaign board: every host the model is currently alerting on, so several simultaneous attacks
and their mitigations are visible at once (the 'mitigate one, the next keeps running' view)."""
from __future__ import annotations

import streamlit as st

from dashboard.components.state_graph import STAGE_COLORS


def campaign_board(hosts: list[dict], threshold: float, window_s: int,
                   contained: set | None = None, title: str = "Active campaigns") -> None:
    contained = contained or set()
    rows = [h for h in hosts if h.get("first_alert_step") is not None or h.get("peak", 0) >= threshold]
    rows = sorted(rows, key=lambda h: -h.get("peak", 0))[:10]
    if not rows:
        st.html("<div class='nv-card'><div class='nv-h'>Active campaigns</div>"
                "<div style='color:#6E7478;font-size:12px'>No host above the alert threshold yet.</div></div>")
        return
    body = []
    for h in rows:
        host = h["host"]
        is_c = host in contained
        stg = int(h.get("stage", 0))
        col = STAGE_COLORS[stg] if 0 <= stg < len(STAGE_COLORS) else "#9AA0A6"
        peak = h.get("peak", 0.0)
        al = h.get("first_alert_step")
        when = f"t+{al * window_s // 60} min" if al is not None else "-"
        lead = h.get("compromise_lead_s")
        lead_txt = f"{lead}s" if lead is not None and lead > 0 else "-"
        action = h.get("recommended_action") or {}
        action_txt = action.get("label", "-")
        status = ("<span class='nv-pill ok'>contained</span>" if is_c
                  else "<span class='nv-pill atk'>alerting</span>")
        bar = (f"<div style='background:#202426;border-radius:3px;height:7px;width:90px'>"
               f"<div style='background:{col};height:7px;border-radius:3px;width:{int(peak * 90)}px'></div></div>")
        body.append(
            f"<tr><td class='nv-mono'>{host}</td>"
            f"<td style='color:{col}'>{h.get('stage_name', '-')}</td>"
            f"<td>{bar}</td><td class='nv-mono'>{peak:.0%}</td>"
                    f"<td>{when}</td><td class='nv-mono'>{lead_txt}</td><td>{action_txt}</td><td>{status}</td></tr>")
    st.html(f"""<div class='nv-card'><div class='nv-h'>{title}</div>
      <table class='nv-board'><tr><th>host</th><th>stage</th><th>risk</th><th></th>
      <th>first alert</th><th>lead time</th><th>recommended action</th><th>status</th></tr>{''.join(body)}</table></div>""")
