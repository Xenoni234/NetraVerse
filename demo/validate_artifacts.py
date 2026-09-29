"""Validate bundled campaign artifacts against the real ingestion/model path."""
from __future__ import annotations

from pathlib import Path

from src.api.service import get_service
from src.features.fusion import from_csv, from_pcap


ROOT = Path(__file__).resolve().parents[1]
CSV = ROOT / "demo" / "samples" / "netraverse_campaign.csv"
PCAP = ROOT / "demo" / "fallback_pcap" / "netraverse_campaign.pcap"


def validate(*, raise_on_error: bool = True) -> dict:
    errors: list[str] = []
    svc = get_service()
    csv_a = svc.analyze(from_csv(CSV, min_flows=3), filename=CSV.name, aid="validate-csv")
    csv_ov = svc.overview(csv_a)
    timelines = [svc.timeline(csv_a, h["host"]) for h in csv_ov["hosts"]
                 if h.get("truth_attack_steps")]
    campaign_timelines = [t for t in timelines if str(t.get("host", "")).startswith("10.20.")]
    positive_leads = [t for t in campaign_timelines if (t.get("compromise_lead_s") or 0) > 0]
    out_of_range = [t for t in positive_leads
                    if not 60 <= int(t["compromise_lead_s"]) <= 300]
    alert_steps = {t.get("first_alert_step") for t in positive_leads if t.get("first_alert_step") is not None}
    if len(positive_leads) < 7:
        errors.append("CSV has fewer than seven generated campaign hosts with positive compromise lead time.")
    if out_of_range:
        errors.append("CSV contains a compromise lead outside the required 60-300 second window.")
    if len(alert_steps) < 2:
        errors.append("CSV does not contain multiple distinct alert timelines.")

    focus = next((t for t in positive_leads if t.get("first_alert_step") is not None), None)
    if focus is not None:
        step = int(focus["first_alert_step"])
        res = svc.decide(csv_a, focus["host"], step, "accept", None, live=False)
        if res["delta"]["peak_after"] >= res["delta"]["peak_before"]:
            errors.append("Accepted CSV counterfactual did not lower peak forecast risk.")
        svc.reset_branch(csv_a)

    pcap_a = svc.analyze(from_pcap(PCAP), filename=PCAP.name, aid="validate-pcap")
    pcap_ov = svc.overview(pcap_a)
    pcap_alerts = [h for h in pcap_ov["hosts"] if h.get("first_alert_step") is not None]
    if len(pcap_alerts) < 2:
        errors.append("PCAP does not produce multiple alerting hosts.")
    pcap_timelines = [svc.timeline(pcap_a, h["host"]) for h in pcap_ov["hosts"]
                      if h.get("truth_attack_steps")]
    pcap_leads = [t for t in pcap_timelines if (t.get("compromise_lead_s") or 0) > 0]
    if len(pcap_leads) < 3:
        errors.append("PCAP does not expose at least three positive forecast lead windows.")
    if any(not 60 <= int(t["compromise_lead_s"]) <= 300 for t in pcap_leads):
        errors.append("PCAP contains a compromise lead outside the required 60-300 second window.")

    result = {"csv": csv_ov, "pcap": pcap_ov,
              "positive_compromise_leads": len(positive_leads),
              "pcap_positive_leads": len(pcap_leads),
              "distinct_alert_steps": len(alert_steps), "errors": errors}
    if errors and raise_on_error:
        raise RuntimeError("Artifact validation failed: " + " | ".join(errors))
    return result


if __name__ == "__main__":
    result = validate()
    print({"csv_hosts": result["csv"]["n_hosts"], "csv_steps": result["csv"]["n_steps"],
           "pcap_hosts": result["pcap"]["n_hosts"], "pcap_steps": result["pcap"]["n_steps"],
           "positive_compromise_leads": result["positive_compromise_leads"],
           "pcap_positive_leads": result["pcap_positive_leads"],
           "distinct_alert_steps": result["distinct_alert_steps"]})
