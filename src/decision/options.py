"""Ranked decision options with model-simulated impact.

Instead of one silent stored rule, the theater offers the operator several
containment options — each **ranked by its own counterfactual Δrisk** (run the
world model as if that action were applied) and explained in plain language.
This is what turns "here is a recommendation" into "here are 3 options; option A
drops risk 92% and prevents the attack, option B drops 40%…".

Fast + deterministic: the ranking is the real simulated risk drop; the
explanation is templated from the MITRE stage playbook + the simulated numbers
(no per-option LLM call, so it stays snappy). An optional LLM enrichment can be
layered on the top option by the caller.
"""

from __future__ import annotations

from typing import Any

import pandas as pd

from src.inference.counterfactual import compare_timelines, mitigated_timeline
from src.mitre.stage_mapping import STAGE_NAMES, stage_defence

#: Candidate actions to offer per stage id. Source-side containments apply to
#: every alert; stage-specific ones are added where they fit.
_COMMON = ["block_source_ip", "rate_limit", "isolate_host"]
_STAGE_EXTRA = {
    3: ["restrict_east_west"],          # LATERAL_MOVEMENT
    4: ["block_destination_ip"],        # C2
    5: ["block_destination_ip"],        # EXFILTRATION
    6: ["rate_limit"],                  # IMPACT (already common)
}

_ACTION_LABEL = {
    "block_source_ip": "Block the source IP",
    "rate_limit": "Rate-limit the host",
    "isolate_host": "Isolate the host",
    "restrict_east_west": "Restrict east-west traffic",
    "block_destination_ip": "Block the destination IP",
    "block_attack_port": "Block the attack port",
}


def _top_destination(flows: pd.DataFrame, host: str) -> str | None:
    """The IP the host talks to most — the block_destination_ip target (C2/exfil)."""
    if flows.empty or "src_ip" not in flows or "dst_ip" not in flows:
        return None
    out = flows.loc[flows["src_ip"].astype(str) == str(host), "dst_ip"].astype(str)
    return out.value_counts().idxmax() if len(out) else None


def rank_options(
    flows: pd.DataFrame,
    host: str,
    stage_id: int,
    cut_ts: pd.Timestamp,
    fc: Any,
    *,
    threshold: float,
    entity_granularity: str = "src_ip",
    horizon_col: str = "risk_k4",
    baseline_timeline: pd.DataFrame | None = None,
) -> list[dict[str, Any]]:
    """Return decision options ranked by simulated risk drop (best first)."""
    # Baseline once (unmitigated re-forecast) so every option compares fairly.
    if baseline_timeline is None:
        baseline_timeline = mitigated_timeline(
            flows, host, "noop", cut_ts, fc, target_ip="",
            entity_granularity=entity_granularity,
        )
    dest = _top_destination(flows, host)
    playbook = stage_defence(int(stage_id))
    candidates = list(dict.fromkeys(_COMMON + _STAGE_EXTRA.get(int(stage_id), [])))

    options: list[dict[str, Any]] = []
    for action_type in candidates:
        target = dest if action_type == "block_destination_ip" else host
        if not target:
            continue
        mit = mitigated_timeline(
            flows, host, action_type, cut_ts, fc, target_ip=target,
            entity_granularity=entity_granularity,
        )
        cmp = compare_timelines(baseline_timeline, mit, threshold=threshold,
                                cut_ts=cut_ts, horizon_col=horizon_col)
        options.append({
            "action_type": action_type,
            "label": _ACTION_LABEL.get(action_type, action_type.replace("_", " ")),
            "target_ip": target,
            "ttl_seconds": 300,
            "expected_risk_drop": cmp["risk_drop"],
            "peak_before": cmp["peak_before"],
            "peak_after": cmp["peak_after"],
            "prevented": cmp["prevented"],
            "explanation": _explain(action_type, target, cmp, stage_id, playbook),
            "comparison": cmp,
        })

    # Best = prevents the attack, then largest risk drop, then least disruptive.
    disruption = {"rate_limit": 0, "block_attack_port": 1, "block_source_ip": 2,
                  "block_destination_ip": 2, "restrict_east_west": 3, "isolate_host": 4}
    options.sort(key=lambda o: (not o["prevented"], -o["expected_risk_drop"],
                                disruption.get(o["action_type"], 9)))
    if options:
        options[0]["recommended"] = True
    return options


def _explain(action_type: str, target: str, cmp: dict, stage_id: int, playbook: dict) -> str:
    stage = STAGE_NAMES.get(int(stage_id), "the attack")
    drop = int(round(cmp["risk_drop"] * 100))
    verb = {
        "block_source_ip": f"Dropping all traffic from {target} removes the attacker's flows",
        "isolate_host": f"Quarantining {target} cuts it off from the network",
        "rate_limit": f"Throttling {target} starves the {stage.lower()} of the volume it needs",
        "restrict_east_west": f"Blocking {target}'s internal traffic stops lateral spread",
        "block_destination_ip": f"Blocking traffic to {target} severs the {stage.lower()} channel",
        "block_attack_port": f"Blocking the attack port on {target} shuts the exploited service",
    }.get(action_type, f"Applying {action_type} on {target}")
    tail = (f", cutting forecast risk ~{drop}% and preventing compromise."
            if cmp["prevented"] else
            f", cutting forecast risk ~{drop}% (risk stays elevated — consider a stronger action).")
    return verb + tail


__all__ = ["rank_options"]
