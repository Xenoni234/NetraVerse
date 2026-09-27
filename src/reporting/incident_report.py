"""One-click PDF incident report (FR12). Built from a finished analysis - the same numbers the
dashboard shows (forecast, early-warning lead, MITRE stage, decision + enforcement, evidence), so
the report never states anything the model did not actually produce. Pure-python (fpdf2), offline."""
from __future__ import annotations

import time

from fpdf import FPDF

def _txt(s) -> str:
    """Core PDF fonts are latin-1 only; drop anything they cannot encode (arrows, middots, ...)."""
    return str(s).replace("->", "->").encode("latin-1", "replace").decode("latin-1")


INK = (18, 22, 24)
TEAL = (31, 122, 122)
GREY = (110, 116, 120)
BAD = (176, 63, 44)
GOOD = (75, 138, 94)
LIGHT = (238, 240, 240)


class _Report(FPDF):
    def header(self) -> None:
        self.set_fill_color(*INK)
        self.rect(0, 0, self.w, 20, "F")
        self.set_xy(10, 5)
        self.set_font("Helvetica", "B", 15)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, "NetraVerse  -  Incident Report")
        self.set_font("Helvetica", "", 9)
        self.set_xy(10, 5)
        self.set_text_color(150, 200, 200)
        self.cell(self.w - 20, 10, "SIH PS 26153  -  world-model attack forecasting", align="R")
        self.ln(18)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*GREY)
        self.cell(0, 8, "Generated offline by NetraVerse. Forecasts are model output; enforcement "
                        "reflects real firewall state.", align="C")


def _h(pdf: _Report, text: str) -> None:
    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(*TEAL)
    pdf.cell(0, 7, text)
    pdf.ln(7)
    pdf.set_draw_color(*TEAL)
    pdf.line(pdf.get_x(), pdf.get_y(), pdf.w - 10, pdf.get_y())
    pdf.ln(2)
    pdf.set_text_color(*INK)


def _kv(pdf: _Report, pairs: list[tuple[str, str]]) -> None:
    pdf.set_font("Helvetica", "", 9.5)
    for k, v in pairs:
        pdf.set_text_color(*GREY)
        pdf.cell(55, 6, k)
        pdf.set_text_color(*INK)
        pdf.set_font("Helvetica", "B", 9.5)
        pdf.cell(0, 6, str(v))
        pdf.set_font("Helvetica", "", 9.5)
        pdf.ln(6)


def build_pdf(svc, a, title: str = "Live session", decisions: list | None = None) -> bytes:
    ov = svc.overview(a)
    ws = ov["window_s"]
    alerting = [h for h in ov["hosts"] if h["first_alert_step"] is not None]
    pdf = _Report()
    pdf.set_auto_page_break(True, margin=16)
    pdf.add_page()

    _h(pdf, "Summary")
    _kv(pdf, [
        ("Source", f"{title}  ({ov.get('filename') or ov['source']})"),
        ("Generated", time.strftime("%Y-%m-%d %H:%M:%S")),
        ("Model", f"{ov['model']['checkpoint'].split('/')[-1]}  -  trained on "
                  f"{', '.join(ov['model']['trained_on'])}"),
        ("Window / horizon", f"{ws}s window, {ov['horizon_s']}s forecast horizon"),
        ("Alert threshold", f"{ov['threshold']:.3f}"),
        ("Hosts / flows / duration", f"{ov['n_hosts']} hosts, {ov['n_flows']:,} flows, "
                                     f"{ov['n_steps'] * ws // 60} min"),
        ("Attacks detected", f"{len(alerting)} alerting host(s)"),
    ])

    _h(pdf, "Attacks detected  (early-warning lead measured to the compromise)")
    pdf.set_font("Helvetica", "B", 8.5)
    pdf.set_fill_color(*LIGHT)
    cols = [("Victim host", 34), ("Forecast stage", 40), ("Peak risk", 20), ("First alert", 22),
            ("Early-warning lead", 40)]
    for name, wdt in cols:
        pdf.cell(wdt, 7, name, border=0, fill=True)
    pdf.ln(7)
    pdf.set_font("Helvetica", "", 8.5)
    for h in alerting[:12]:
        tl = svc.timeline(a, h["host"])
        cl = tl.get("compromise_lead_s")
        early = tl.get("recon_before_compromise") and cl is not None and cl > 0
        lead = (f"+{cl}s ({cl // 60} min) during recon" if early
                else "at onset" if tl.get("lead_time_s") is not None else "-")
        al = h["first_alert_step"]
        pdf.cell(34, 6, str(h["host"]))
        pdf.cell(40, 6, str(h["stage_name"]))
        pdf.set_text_color(*(BAD if h["peak"] >= ov["threshold"] else INK))
        pdf.cell(20, 6, f"{h['peak']:.0%}")
        pdf.set_text_color(*INK)
        pdf.cell(22, 6, f"t+{al * ws // 60} min")
        pdf.set_text_color(*(GOOD if early else GREY))
        pdf.cell(40, 6, lead)
        pdf.set_text_color(*INK)
        pdf.ln(6)
    if not alerting:
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 6, "No host crossed the alert threshold in this capture.")
        pdf.ln(6)

    decisions = list(decisions if decisions is not None else getattr(a, "decisions", []))
    if decisions:
        _h(pdf, "Analyst decisions & enforcement")
        pdf.set_font("Helvetica", "", 8.5)
        for d in decisions[-8:]:
            enf = d.get("enforcement", {})
            state = ("APPLIED" if enf.get("applied") else
                     "rejected" if d["choice"] == "reject" else "not enforced")
            pdf.set_x(10)
            pdf.set_text_color(*(GOOD if enf.get("applied") else GREY))
            pdf.cell(24, 6, f"[{d['choice'].upper()}]")
            pdf.set_text_color(*INK)
            pdf.multi_cell(pdf.w - pdf.r_margin - pdf.get_x(), 6,
                           _txt(f"{d['action']['label']}  ->  {state}. {enf.get('message', '')}"))

    if alerting:
        _h(pdf, f"Evidence for {alerting[0]['host']}  (integrated-gradients drivers)")
        pdf.set_font("Helvetica", "", 8.5)
        try:
            drivers = svc.explain_step(a, alerting[0]["host"], alerting[0]["first_alert_step"])
        except Exception:
            drivers = []
        for d in drivers[:6]:
            attr = d.get("attribution", 0.0)
            pdf.set_x(10)
            pdf.set_text_color(*(BAD if attr > 0 else GOOD))
            pdf.cell(16, 6, f"{attr:+.3f}")
            pdf.set_text_color(*INK)
            pdf.multi_cell(pdf.w - pdf.r_margin - pdf.get_x(), 6,
                           _txt(d.get("sentence") or d.get("feature", "")))

    out = pdf.output()
    return bytes(out)
