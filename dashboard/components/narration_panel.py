"""Analyst narration card: the local-LLM (or template fallback) plain-English read of the alert."""
from __future__ import annotations

import streamlit as st


def narration_panel(fetch, title: str = "Analyst narration") -> None:
    try:
        got = fetch() or {}
    except Exception:
        got = {}
    if isinstance(got, str):
        got = {"text": got}
    text = got.get("text")
    if not text:
        return
    src = got.get("source", "template")
    st.html(f"<div class='nv-card'><div class='nv-h'>{title} "
            f"<span class='nv-pill'>{src}</span></div>"
            f"<div style='font:13px/1.55 var(--nv-sans);color:#d0d4d6'>{text}</div></div>")
