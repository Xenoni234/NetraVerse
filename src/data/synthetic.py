"""Deterministic, safe synthetic network-state episode generation.

This module generates canonical state windows only; it does not execute attacks,
open sockets, or emit malicious packets. It is intended for augmentation and
self-supervised experiments in an authorized lab.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Final

import numpy as np
import pandas as pd

from src.data.windowing import MODEL_COLUMNS, STATE_FEATURE_COLUMNS, MASK_COLUMNS, WINDOW_SECONDS
from src.mitre.stage_mapping import C2, EXFILTRATION, IMPACT, INITIAL_ACCESS, LATERAL_MOVEMENT, RECON

SYNTHETIC_SOURCE: Final[str] = "synthetic"


@dataclass(frozen=True)
class EpisodeSpec:
    scenario: str
    seed: int = 1337
    entity_count: int = 2
    warmup_windows: int = 20
    preparation_windows: int = 6
    attack_windows: int = 20
    recovery_windows: int = 15
    start: str = "2026-01-01T00:00:00Z"

    @property
    def total_windows(self) -> int:
        return self.warmup_windows + self.preparation_windows + self.attack_windows + self.recovery_windows


STAGE_BY_SCENARIO: Final[dict[str, int]] = {
    "recon": RECON,
    "initial_access": INITIAL_ACCESS,
    "lateral_movement": LATERAL_MOVEMENT,
    "c2": C2,
    "exfiltration": EXFILTRATION,
    "impact": IMPACT,
}


def _base_frame(spec: EpisodeSpec) -> pd.DataFrame:
    rng = np.random.default_rng(spec.seed)
    n = spec.total_windows
    start = pd.Timestamp(spec.start, tz="UTC")
    rows: list[dict] = []
    onset = spec.warmup_windows + spec.preparation_windows
    end = onset + spec.attack_windows
    stage = STAGE_BY_SCENARIO.get(spec.scenario.lower())
    if stage is None:
        raise ValueError(f"Unknown scenario {spec.scenario!r}; choose {sorted(STAGE_BY_SCENARIO)}")

    for entity_no in range(spec.entity_count):
        entity = f"synthetic-host-{entity_no + 1}"
        for t in range(n):
            phase = "benign" if t < onset else "attack" if t < end else "recovery"
            scale = 1.0 + 0.08 * rng.normal()
            row = {c: 0.0 for c in STATE_FEATURE_COLUMNS}
            row.update({c: 1.0 for c in MASK_COLUMNS})
            row.update({
                "n_flows": max(1.0, 8 * scale + rng.normal()),
                "n_pkts_fwd": max(1.0, 20 * scale + rng.normal()),
                "n_pkts_bwd": max(1.0, 18 * scale + rng.normal()),
                "bytes_fwd": max(1.0, 1800 * scale + 100 * rng.normal()),
                "bytes_bwd": max(1.0, 1600 * scale + 100 * rng.normal()),
                "flows_per_sec": max(0.0, 8 / WINDOW_SECONDS * scale),
                "pkts_per_sec": max(0.0, 38 / WINDOW_SECONDS * scale),
                "bytes_per_sec": max(0.0, 3400 / WINDOW_SECONDS * scale),
                "frac_tcp": 0.75, "frac_udp": 0.20, "frac_icmp": 0.05,
                "mean_flow_duration_s": 0.15, "mean_iat_s": 0.8,
                "mean_pkt_len": 90.0, "fwd_bwd_ratio": 1.1,
                "mean_fwd_pkt_len": 92.0, "mean_bwd_pkt_len": 88.0,
            })
            if phase == "attack":
                row.update(_stage_signal(spec.scenario.lower(), t - onset, rng))
            elif phase == "recovery":
                row["baseline_deviation"] = max(0.0, 2.0 - 0.15 * (t - end))
            label = int(phase == "attack")
            rows.append({
                **row,
                "entity_id": entity,
                "campaign_id": f"synthetic-{spec.seed}",
                "dataset": "synthetic_phase6",
                "window_start": start + pd.Timedelta(seconds=t * WINDOW_SECONDS),
                "binary_label": label,
                "attack_family": spec.scenario,
                "attt_stage": stage if label else 0,
                "attack_onset": int(t == onset),
                "onset_left_censored": 0,
                "episode_id": f"episode-{spec.seed}-{spec.scenario}",
                "scenario": spec.scenario,
                "source_kind": SYNTHETIC_SOURCE,
                "generator_seed": spec.seed,
            })
    return pd.DataFrame(rows)


def _stage_signal(scenario: str, elapsed: int, rng: np.random.Generator) -> dict[str, float]:
    strength = 1.0 + min(elapsed / 10.0, 2.0)
    signal: dict[str, float] = {"baseline_deviation": 2.5 * strength}
    if scenario == "recon":
        signal.update({"n_distinct_dst_ip": 8 * strength, "n_distinct_dst_port": 18 * strength,
                       "dst_port_entropy": 3.5, "syn_count": 15 * strength,
                       "failed_conn_ratio": 0.75, "new_peer_count": 6 * strength})
    elif scenario == "initial_access":
        signal.update({"failed_conn_ratio": 0.65, "syn_count": 10 * strength,
                       "n_flows": 25 * strength, "trajectory_velocity": 1.2})
    elif scenario == "lateral_movement":
        signal.update({"n_distinct_dst_ip": 12 * strength, "new_peer_count": 8 * strength,
                       "fan_out_count": 12 * strength, "n_flows": 22 * strength})
    elif scenario == "c2":
        signal.update({"n_flows": 4.0, "mean_iat_s": 5.0, "idle_s": 8.0,
                       "dst_ip_entropy": 0.2, "bytes_per_sec": 250 * strength})
    elif scenario == "exfiltration":
        signal.update({"bytes_total": 150_000 * strength, "bytes_per_sec": 5_000 * strength,
                       "n_pkts_fwd": 800 * strength, "fwd_bwd_ratio": 6.0})
    elif scenario == "impact":
        signal.update({"n_flows": 180 * strength, "flows_per_sec": 6 * strength,
                       "pkts_per_sec": 300 * strength, "failed_conn_ratio": 0.9,
                       "syn_count": 220 * strength})
    for key in list(signal):
        signal[key] = float(max(0.0, signal[key] + rng.normal(0, max(0.01, abs(signal[key]) * 0.04))))
    return signal


def generate_episode(spec: EpisodeSpec) -> pd.DataFrame:
    """Generate one reproducible canonical episode."""
    return _base_frame(spec)


def generate_dataset(specs: list[EpisodeSpec]) -> pd.DataFrame:
    """Generate and concatenate independent episodes with provenance."""
    if not specs:
        raise ValueError("At least one episode specification is required")
    return pd.concat([generate_episode(s) for s in specs], ignore_index=True)


def write_bundle(frame: pd.DataFrame, directory: Path, specs: list[EpisodeSpec]) -> dict[str, str]:
    """Write canonical windows, a flow-compatible CSV, and a PCAP manifest.

    No packet capture is fabricated. The manifest records that an external
    authorized replay/extraction step is required for PCAP-level validation.
    """
    directory.mkdir(parents=True, exist_ok=True)
    windows_path = directory / "synthetic_windows.parquet"
    csv_path = directory / "synthetic_canonical_flows.csv"
    manifest_path = directory / "pcap_replay_manifest.json"
    frame.to_parquet(windows_path, index=False)
    frame.to_csv(csv_path, index=False)
    manifest_path.write_text(json.dumps({
        "status": "not_generated",
        "reason": "PCAP replay requires an authorized external lab tool",
        "episodes": [asdict(s) for s in specs],
    }, indent=2), encoding="utf-8")
    return {"windows": str(windows_path), "flows": str(csv_path), "pcap_manifest": str(manifest_path)}


__all__ = ["EpisodeSpec", "STAGE_BY_SCENARIO", "generate_episode", "generate_dataset", "write_bundle"]
