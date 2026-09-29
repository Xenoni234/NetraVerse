"""Deterministic, local-only scenario catalog shared by rehearsal and validation.

The catalog deliberately works with canonical flow rows rather than packets.  This
keeps the rehearsal path on the same ``FLOW_COLUMNS`` contract used by CSV, PCAP
and live ingestion while guaranteeing that it never opens a socket or captures
traffic.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from src.features.schema import FLOW_COLUMNS


@dataclass(frozen=True)
class ScenarioSpec:
    id: str
    name: str
    template_pair: tuple[str, str]
    attack_label: str
    description: str


SCENARIOS: tuple[ScenarioSpec, ...] = (
    ScenarioSpec("reconnaissance", "Reconnaissance", ("10.13.37.5", "10.20.0.11"),
                 "PortScan", "Port and service probing with a visible ramp before access."),
    ScenarioSpec("initial-access", "Initial Access", ("10.13.37.7", "10.20.0.13"),
                 "SSH-Patator", "Repeated short service connections representing credential abuse."),
    ScenarioSpec("lateral-movement", "Lateral Movement", ("10.13.37.6", "10.20.0.12"),
                 "Infiltration", "A pivot-like fan-out to a second internal service path."),
    ScenarioSpec("command-and-control", "Command and Control", ("10.13.37.5", "10.20.0.11"),
                 "Botnet beacon", "Periodic outbound beacon-shaped traffic with a preceding scan."),
    ScenarioSpec("exfiltration", "Exfiltration", ("10.13.37.7", "10.20.0.13"),
                 "Exfiltration", "A sustained outbound transfer profile after initial access."),
    ScenarioSpec("impact", "Impact", ("10.13.37.8", "10.20.0.14"),
                 "DoS slowloris", "A high-volume availability-impact profile."),
)

_SAFE_IPS = {
    "reconnaissance": ("10.50.0.11", "10.60.0.11"),
    "initial-access": ("10.50.0.12", "10.60.0.12"),
    "lateral-movement": ("10.50.0.13", "10.60.0.13"),
    "command-and-control": ("10.50.0.14", "10.60.0.14"),
    "exfiltration": ("10.50.0.15", "10.60.0.15"),
    "impact": ("10.50.0.16", "10.60.0.16"),
}


def scenario_specs() -> list[dict]:
    return [{"id": s.id, "name": s.name, "description": s.description,
             "attacker": _SAFE_IPS[s.id][0], "victim": _SAFE_IPS[s.id][1]}
            for s in SCENARIOS]


def get_scenario(scenario_id: str) -> ScenarioSpec:
    key = str(scenario_id).strip().lower()
    for spec in SCENARIOS:
        if spec.id == key:
            return spec
    choices = ", ".join(s.id for s in SCENARIOS)
    raise ValueError(f"Unknown rehearsal scenario {scenario_id!r}; choose one of: {choices}.")


def _seed_path(root: Path | None = None) -> Path:
    root = root or Path(__file__).resolve().parents[1]
    return root / "demo" / "samples" / "netraverse_campaign.csv"


def campaign_flows(*, root: Path | None = None) -> pd.DataFrame:
    """Return the four validated campaign pairs on one safe timeline."""
    path = _seed_path(root)
    if not path.exists():
        raise FileNotFoundError(f"Rehearsal seed capture is missing: {path}")
    seed = pd.read_csv(path)
    pairs = {
        "10.13.37.5": "10.50.0.11", "10.20.0.11": "10.60.0.11",
        "10.13.37.6": "10.50.0.12", "10.20.0.12": "10.60.0.12",
        "10.13.37.7": "10.50.0.13", "10.20.0.13": "10.60.0.13",
        "10.13.37.8": "10.50.0.14", "10.20.0.14": "10.60.0.14",
        "10.13.37.9": "10.50.0.15", "10.20.0.15": "10.60.0.15",
        "10.13.37.10": "10.50.0.16", "10.20.0.16": "10.60.0.16",
        "10.13.37.11": "10.50.0.17", "10.20.0.17": "10.60.0.17",
    }
    campaign_ips = set(pairs)
    out = seed[seed["src_ip"].isin(campaign_ips) & seed["dst_ip"].isin(campaign_ips)].copy()
    if out.empty:
        raise ValueError("No campaign seed flows found in the bundled artifact.")
    t0 = float(out["ts_start"].min())
    out["ts_start"] = out["ts_start"].astype(float) - t0
    out["ts_end"] = out["ts_end"].astype(float) - t0
    out["src_ip"] = out["src_ip"].replace(pairs)
    out["dst_ip"] = out["dst_ip"].replace(pairs)
    return out[list(FLOW_COLUMNS)].sort_values("ts_end", kind="stable").reset_index(drop=True)


def scenario_flows(scenario_id: str, *, root: Path | None = None,
                   include_campaign: bool = False) -> pd.DataFrame:
    """Return one deterministic scenario rebased to zero seconds.

    The bundled campaign is already validated against the current checkpoint.
    Selecting its real feature profiles and only remapping identity/time gives the
    rehearsal the same model-facing feature distribution without replaying packets.
    """
    spec = get_scenario(scenario_id)
    if include_campaign:
        return campaign_flows(root=root)
    path = _seed_path(root)
    if not path.exists():
        raise FileNotFoundError(f"Rehearsal seed capture is missing: {path}")
    seed = pd.read_csv(path)
    src, dst = spec.template_pair
    pair = seed[(seed["src_ip"].isin([src, dst])) & (seed["dst_ip"].isin([src, dst]))].copy()
    if pair.empty:
        raise ValueError(f"No seed flows found for scenario {spec.id} ({src} -> {dst}).")

    t0 = float(pair["ts_start"].min())
    pair["ts_start"] = pair["ts_start"].astype(float) - t0
    pair["ts_end"] = pair["ts_end"].astype(float) - t0
    attacker, victim = _SAFE_IPS[spec.id]
    pair["src_ip"] = pair["src_ip"].replace({src: attacker, dst: victim})
    pair["dst_ip"] = pair["dst_ip"].replace({src: attacker, dst: victim})

    # Preserve the reconnaissance precursor where the seed has one, then map the
    # later labelled rows to the selected ATT&CK family for honest upload labels.
    labels = pair["label"].astype(str)
    is_recon = labels.str.lower().str.contains("scan|recon", regex=True)
    pair.loc[(labels.str.len() > 0) & ~is_recon & (labels.str.lower() != "benign"), "label"] = spec.attack_label
    return pair[list(FLOW_COLUMNS)].sort_values("ts_end", kind="stable").reset_index(drop=True)


__all__ = ["SCENARIOS", "ScenarioSpec", "campaign_flows", "get_scenario", "scenario_flows", "scenario_specs"]
