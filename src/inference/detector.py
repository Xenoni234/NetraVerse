"""Present-state detector — engine #1 of the dual-engine design.

The forecaster (engine #2) scores the *predicted future*. This detector scores
the **current** 30-second window: "is this host attacking / compromised *now*?".
It has two jobs:

1. **Catch fast / no-ramp attacks** the forecaster cannot anticipate (a
   single-burst scan or exploit with no runway).
2. **Anchor ground truth for self-calibration** — the detector's verdict at
   window *t* is the label for the forecast that was issued at *t-K*.

It is deliberately transparent (not a black box): a graded probability built
from the same auditable observed features as :func:`infer_behavioral_stage`,
plus a human-readable ``signature`` naming what fired. Fully offline, CPU-only.
The detector never acts; it annotates.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Mapping

from src.mitre.stage_mapping import (
    BENIGN,
    C2,
    EXFILTRATION,
    IMPACT,
    INITIAL_ACCESS,
    LATERAL_MOVEMENT,
    RECON,
    STAGE_NAMES,
)


@dataclass(frozen=True)
class DetectorVerdict:
    """One present-state verdict for a host window."""

    attack_now: float          # 0..1 probability an attack is in progress now
    stage: int                 # most likely ATT&CK stage id (0 = BENIGN)
    stage_name: str
    signature: str             # human-readable evidence, e.g. "port fan-out 42, entropy 4.1"
    scores: dict[str, float]   # per-stage evidence scores, for auditing

    def to_json(self) -> dict[str, Any]:
        return {
            "attack_now": round(self.attack_now, 4),
            "stage": self.stage,
            "stage_name": self.stage_name,
            "signature": self.signature,
            "scores": {k: round(v, 3) for k, v in self.scores.items()},
        }


def _f(row: Mapping[str, Any], name: str) -> float:
    try:
        return float(row.get(name, 0.0) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _ramp(value: float, lo: float, hi: float) -> float:
    """Linear 0->1 as value goes lo->hi, clamped."""
    if hi <= lo:
        return 1.0 if value >= hi else 0.0
    return max(0.0, min(1.0, (value - lo) / (hi - lo)))


def score_present(row: Mapping[str, Any]) -> DetectorVerdict:
    """Score one observed 30-second host window for attack-in-progress + stage.

    Each stage contributes an evidence score in [0, 1] built from the observed
    fan-out / flag / volume / timing features. The strongest stage wins;
    ``attack_now`` is a soft function of that winning evidence so a strong,
    specific signature yields high confidence while ambiguous traffic stays low.
    """
    n_flows = _f(row, "n_flows")
    flows_ps = _f(row, "flows_per_sec")
    pkts_ps = _f(row, "pkts_per_sec")
    bytes_ps = _f(row, "bytes_per_sec")
    syn = _f(row, "syn_count")
    failed = _f(row, "failed_conn_ratio")
    dst_ports = _f(row, "n_distinct_dst_port")
    dst_ips = _f(row, "n_distinct_dst_ip")
    new_peers = _f(row, "new_peer_count")
    port_entropy = _f(row, "dst_port_entropy")
    fwd_bwd = _f(row, "fwd_bwd_ratio")
    mean_iat = _f(row, "mean_iat_s")
    idle = _f(row, "idle_s")

    scores: dict[str, float] = {}

    # RECON — wide destination-port fan-out (port scan).
    scores["RECON"] = max(
        _ramp(dst_ports, 8, 60),
        0.6 * _ramp(port_entropy, 1.5, 5.0) + 0.4 * _ramp(new_peers, 2, 10),
    )

    # INITIAL_ACCESS — repeated failed service connections on few ports.
    scores["INITIAL_ACCESS"] = (
        _ramp(failed, 0.4, 0.9)
        * _ramp(syn, 3, 30)
        * (1.0 if dst_ports <= 5 else 0.4)
    )

    # LATERAL_MOVEMENT — internal fan-out to new peers without a broad port scan.
    scores["LATERAL_MOVEMENT"] = (
        _ramp(dst_ips, 4, 25) * _ramp(new_peers, 3, 15)
        * (0.5 if dst_ports > 20 else 1.0)
    )

    # C2 — periodic, low-volume traffic with long idle / inter-arrival gaps.
    scores["C2"] = (
        _ramp(mean_iat, 2.0, 20.0) * _ramp(idle, 2.0, 20.0)
        * (1.0 if 1.0 <= n_flows <= 12.0 else 0.3)
    )

    # EXFILTRATION — large, asymmetric outbound volume.
    scores["EXFILTRATION"] = _ramp(bytes_ps, 5_000, 500_000) * _ramp(fwd_bwd, 2.0, 8.0)

    # IMPACT — high SYN / packet pressure (flood).
    scores["IMPACT"] = max(
        _ramp(pkts_ps, 50, 2_000) * _ramp(syn, 50, 2_000),
        _ramp(flows_ps, 4, 50),
    )

    stage_by_name = {
        "RECON": RECON, "INITIAL_ACCESS": INITIAL_ACCESS,
        "LATERAL_MOVEMENT": LATERAL_MOVEMENT, "C2": C2,
        "EXFILTRATION": EXFILTRATION, "IMPACT": IMPACT,
    }
    top_name = max(scores, key=scores.get)
    top_score = scores[top_name]

    # Squash the winning evidence into a probability: 0.5 evidence -> ~0.5.
    attack_now = 1.0 / (1.0 + math.exp(-6.0 * (top_score - 0.5)))
    if top_score < 0.15:
        stage, stage_name, attack_now = BENIGN, STAGE_NAMES.get(BENIGN, "BENIGN"), min(attack_now, 0.1)
        signature = "no specific attack signature in the current window"
    else:
        stage = stage_by_name[top_name]
        stage_name = STAGE_NAMES.get(stage, top_name)
        signature = _signature(top_name, row)

    return DetectorVerdict(
        attack_now=attack_now, stage=stage, stage_name=stage_name,
        signature=signature, scores=scores,
    )


def _signature(stage_name: str, row: Mapping[str, Any]) -> str:
    """A short, human-readable evidence string for the winning stage."""
    if stage_name == "RECON":
        return (f"port fan-out {_f(row,'n_distinct_dst_port'):.0f} dst-ports, "
                f"entropy {_f(row,'dst_port_entropy'):.1f}, {int(_f(row,'new_peer_count'))} new peers")
    if stage_name == "INITIAL_ACCESS":
        return (f"{_f(row,'failed_conn_ratio')*100:.0f}% failed connections, "
                f"{int(_f(row,'syn_count'))} SYN on <=5 ports")
    if stage_name == "LATERAL_MOVEMENT":
        return (f"internal fan-out to {_f(row,'n_distinct_dst_ip'):.0f} hosts, "
                f"{int(_f(row,'new_peer_count'))} never-seen peers")
    if stage_name == "C2":
        return (f"periodic low-volume beacon: mean IAT {_f(row,'mean_iat_s'):.1f}s, "
                f"idle {_f(row,'idle_s'):.1f}s")
    if stage_name == "EXFILTRATION":
        return (f"asymmetric egress {_f(row,'bytes_per_sec')/1000:.0f} KB/s, "
                f"fwd/bwd ratio {_f(row,'fwd_bwd_ratio'):.1f}")
    if stage_name == "IMPACT":
        return (f"flood pressure {_f(row,'pkts_per_sec'):.0f} pkt/s, "
                f"{int(_f(row,'syn_count'))} SYN")
    return "attack signature present"


__all__ = ["DetectorVerdict", "score_present"]
