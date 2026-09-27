"""What-if action menu: the recommended containment and its alternatives side by side, with what
each one does and whether it FULLY contains the source (so the risk drop is real, not partial)."""
from __future__ import annotations

import csv
import io

import streamlit as st

FULL = {"block_source", "isolate_host"}          # actions our live containment treats as full
SCOPE = {
    "block_source": "drops all traffic from the source",
    "isolate_host": "quarantines the host completely",
    "block_pair": "cuts only this attacker->victim path",
    "rate_limit": "throttles to ~10% (partial)",
    "block_egress": "blocks the outbound channel",
    "throttle_egress": "throttles the outbound channel",
    "monitor": "watch only, no containment",
}


def whatif_panel(ctx: dict, title: str = "What-if: containment options") -> None:
    rec = ctx.get("recommended")
    if not rec:
        return
    opts = [rec] + list(rec.get("alternatives", []))
    rows = []
    for i, a in enumerate(opts):
        kind = a.get("kind", "")
        tag = ("<span class='nv-pill ok'>full contain</span>" if kind in FULL
               else "<span class='nv-pill'>partial</span>" if kind not in ("monitor",)
               else "<span class='nv-pill'>monitor</span>")
        star = " &#9733;" if i == 0 else ""
        rows.append(f"<tr><td>{a.get('label', kind)}{star}</td>"
                    f"<td style='color:#8a9095'>{SCOPE.get(kind, '')}</td><td>{tag}</td></tr>")
    st.html(f"""<div class='nv-card'><div class='nv-h'>{title}</div>
      <table class='nv-board'><tr><th>action</th><th>effect</th><th>containment</th></tr>
      {''.join(rows)}</table>
      <div style='font-size:11px;color:#6E7478;margin-top:4px'>&#9733; recommended. Only full-contain
      actions drive the live risk to zero when applied; partial ones reduce but do not clear it.</div></div>""")


def audit_csv(decisions: list[dict]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["host", "choice", "action", "kind", "applied", "message", "at"])
    for d in decisions:
        enf = d.get("enforcement", {})
        act = d.get("action", {})
        w.writerow([d.get("host"), d.get("choice"), act.get("label"), act.get("kind"),
                    enf.get("applied"), enf.get("message"), d.get("at")])
    return buf.getvalue().encode("utf-8")
