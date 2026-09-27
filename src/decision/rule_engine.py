"""Deterministic decision engine (FR14, R9): MITRE stage + driving features -> action.

No LLM is involved here. The table is small and auditable; every recommendation
carries a one-line rationale built from the same evidence the analyst sees.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from src.mitre.mitre_lookup import stage_info

ACTION_KINDS = {
    "block_source": "Block all traffic from {target}",
    "block_pair": "Block {target} -> {peer}{port}",
    "isolate_host": "Isolate host {target}",
    "rate_limit": "Rate-limit {target} to 10% of its flows",
    "block_egress": "Block egress from {target} to {peer}",
    "throttle_egress": "Throttle outbound traffic of {target} to 10%",
    "monitor": "Monitor only (no containment)",
}


@dataclass
class Action:
    id: str
    kind: str
    target: str | None = None
    peer: str | None = None
    peers: list[str] = field(default_factory=list)
    port: int | None = None
    ttl_s: int = 300
    label: str = ""
    rationale: str = ""
    alternatives: list["Action"] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["alternatives"] = [a.to_dict() for a in self.alternatives]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Action":
        d = dict(d)
        alts = [cls.from_dict(a) for a in d.pop("alternatives", [])]
        return cls(**d, alternatives=alts)


def _mk(kind: str, target=None, peer=None, peers=None, port=None, rationale="") -> Action:
    port_txt = f":{port}" if port else ""
    label = ACTION_KINDS[kind].format(target=target, peer=peer or ", ".join(peers or []) or "peers",
                                      port=port_txt)
    aid = "-".join(str(p) for p in (kind, target, peer or "", port or "") if p != "")
    return Action(id=aid, kind=kind, target=target, peer=peer, peers=list(peers or []), port=port,
                  label=label, rationale=rationale)


def _has(drivers: list[dict], *names: str) -> bool:
    top = {d["feature"] for d in drivers[:5] if d.get("attribution", 0) > 0}
    return any(n in top for n in names)


def recommend(stage: int, driving_features: list[dict], context: dict) -> Action:
    """context: {host, role, attacker, victims, c2_peers, top_port}."""
    host = context.get("host")
    attacker = context.get("attacker") or host
    victims = [v for v in context.get("victims", []) if v != attacker]
    victim = victims[0] if victims else (host if host != attacker else None)
    port = context.get("top_port")
    peers = [p for p in context.get("c2_peers", []) if p != host][:5]
    name = stage_info(stage)["tactic"]
    monitor = _mk("monitor", rationale="Keep watching; risk is forecast but no containment is applied.")

    if stage == 1:   # Reconnaissance
        why = ("port-scan signature (many ports/destinations, mostly unanswered)"
               if _has(driving_features, "out_distinct_dport", "out_dport_entropy", "out_failed_ratio",
                       "in_distinct_dport", "out_small_flow_ratio")
               else "probing behaviour ahead of an intrusion")
        rec = _mk("block_source", attacker, rationale=f"{name}: {attacker} shows a {why}; "
                  "blocking it before it picks a target stops the kill chain at step one.")
        alts = [_mk("rate_limit", attacker, rationale="Slows the scan while keeping the host reachable."),
                _mk("block_pair", attacker, victim, port=None,
                    rationale="Shields only the host being probed.") if victim else None]
    elif stage == 2:  # Initial access (brute force / exploit)
        rec = _mk("block_pair", attacker, victim, port=port,
                  rationale=f"{name}: repeated short connections from {attacker} to {victim}"
                            f"{':' + str(port) if port else ''} match credential brute-force/exploit "
                            "attempts; cutting that service path prevents the foothold.")
        alts = [_mk("block_source", attacker, rationale="Blocks the attacker on every service."),
                _mk("rate_limit", attacker, rationale="Makes guessing impractically slow."),
                _mk("isolate_host", victim, rationale="Protects the target if it may already be hit.")
                if victim else None]
    elif stage == 3:  # Lateral movement
        pivot = host if context.get("role") == "attacker" else attacker
        rec = _mk("isolate_host", pivot, rationale=f"{name}: {pivot} is reaching new internal peers; "
                  "isolating the pivot stops the spread to further hosts.")
        alts = [_mk("block_pair", pivot, victim, rationale="Cuts only the current hop.") if victim else None,
                _mk("block_source", pivot, rationale="Drops everything the pivot sends and receives.")]
    elif stage == 4:  # Command and control
        tgt = host
        rec = _mk("block_egress", tgt, peers=peers or ([attacker] if attacker != tgt else []),
                  rationale=f"{name}: {tgt} keeps a beacon-like channel to external peers; "
                            "blocking that egress severs the operator's control.")
        alts = [_mk("isolate_host", tgt, rationale="Quarantines the infected host completely."),
                _mk("throttle_egress", tgt, rationale="Degrades the channel while you investigate.")]
    elif stage == 5:  # Exfiltration
        rec = _mk("throttle_egress", host, rationale=f"{name}: outbound volume from {host} is abnormal; "
                  "throttling caps how much data can leave.")
        alts = [_mk("block_egress", host, peers=peers, rationale="Stops the transfer to the receiving peers."),
                _mk("isolate_host", host, rationale="Full containment of the leaking host.")]
    elif stage == 6:  # Impact (DoS/DDoS)
        rec = _mk("rate_limit", attacker, rationale=f"{name}: {attacker} is flooding {victim or 'a service'}; "
                  "rate-limiting keeps the service available.")
        alts = [_mk("block_source", attacker, rationale="Drops the flood source entirely."),
                _mk("block_pair", attacker, victim, port=port, rationale="Protects only the targeted service.")
                if victim else None]
    else:
        return monitor
    rec.alternatives = [a for a in alts if a is not None] + [monitor]
    return rec


def all_actions(rec: Action) -> list[Action]:
    return [rec] + list(rec.alternatives)
