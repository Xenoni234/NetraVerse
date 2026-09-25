"""Apply a decision (architecture.md section 5: ``action_executor.apply(action, live)``).

File mode: no system change - the counterfactual engine replays the traffic
with the action applied. Live mode (FR17, R13): a real nftables rule with a TTL
on the sensor, guarded so management addresses can never be blocked.

Env:
  NV_ENFORCE=1           actually run nft (otherwise dry-run: rules are logged, not applied)
  NV_PROTECTED_IPS       comma list never to block (sensor, dashboard PC, gateway ...)
  NV_NFT_TABLE           default "netraverse"
"""
from __future__ import annotations

import ipaddress
import os
import shlex
import subprocess
import time
from dataclasses import dataclass, field

from src.decision.rule_engine import Action

DEFAULT_PROTECTED = "127.0.0.1,100.72.80.52,100.81.46.8,192.168.0.203,192.168.0.1"


@dataclass
class Enforcement:
    action_id: str
    live: bool
    applied: bool
    dry_run: bool
    commands: list[str] = field(default_factory=list)
    message: str = ""
    expires_at: float | None = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _protected() -> set[str]:
    return {s.strip() for s in os.environ.get("NV_PROTECTED_IPS", DEFAULT_PROTECTED).split(",") if s.strip()}


def _valid_ip(ip: str | None) -> bool:
    try:
        ipaddress.ip_address(str(ip))
        return True
    except ValueError:
        return False


def nft_commands(action: Action) -> list[str]:
    t = os.environ.get("NV_NFT_TABLE", "netraverse")
    base = [f"nft add table inet {t}",
            f"nft 'add chain inet {t} forward {{ type filter hook forward priority -10; }}'",
            f"nft 'add chain inet {t} input {{ type filter hook input priority -10; }}'",
            f"nft 'add chain inet {t} output {{ type filter hook output priority -10; }}'"]
    tgt, peer = action.target, action.peer
    rules: list[str] = []

    def rule(match: str, verdict: str = "drop") -> None:
        for chain in ("forward", "input", "output"):
            rules.append(f"nft add rule inet {t} {chain} {match} {verdict} comment \"nv:{action.id}\"")

    if action.kind in ("block_source", "isolate_host"):
        rule(f"ip saddr {tgt}"); rule(f"ip daddr {tgt}")
    elif action.kind == "block_pair":
        port = f" tcp dport {action.port}" if action.port else ""
        rule(f"ip saddr {tgt} ip daddr {peer}{port}"); rule(f"ip saddr {peer} ip daddr {tgt}")
    elif action.kind == "rate_limit":
        rule(f"ip saddr {tgt} limit rate over 20/second", "drop")
    elif action.kind == "block_egress":
        for p in action.peers or ([peer] if peer else []):
            rule(f"ip saddr {tgt} ip daddr {p}")
    elif action.kind == "throttle_egress":
        rule(f"ip saddr {tgt} limit rate over 100 kbytes/second", "drop")
    return base + rules if rules else []


def apply(action: Action, live: bool = False) -> Enforcement:
    if action.kind == "monitor":
        return Enforcement(action.id, live, False, True, message="Monitor only - nothing applied.")
    if not live:
        return Enforcement(action.id, False, True, True,
                           message="Simulated: traffic replayed with the action applied.")
    ips = [action.target, action.peer, *action.peers]
    ips = [i for i in ips if i]
    bad = [i for i in ips if not _valid_ip(i)]
    if bad:
        return Enforcement(action.id, True, False, True, message=f"Refused: invalid IP {bad}.")
    guard = [i for i in ips if i in _protected()]
    if guard and action.kind in ("block_source", "isolate_host", "block_pair", "rate_limit"):
        return Enforcement(action.id, True, False, True,
                           message=f"Refused: {guard} is a protected management address.")
    cmds = nft_commands(action)
    enforce = os.environ.get("NV_ENFORCE", "0") == "1"
    if not enforce:
        return Enforcement(action.id, True, False, True, cmds,
                           "Dry-run (NV_ENFORCE!=1): rule shown, not applied.")
    for c in cmds:
        res = subprocess.run(["sudo", "-n", "sh", "-c", c], capture_output=True, text=True, timeout=10)
        if res.returncode != 0 and "add table" not in c and "add chain" not in c:
            return Enforcement(action.id, True, False, False, cmds, f"nft failed: {res.stderr.strip()}")
    return Enforcement(action.id, True, True, False, cmds, "Rule applied on the sensor.",
                       expires_at=time.time() + action.ttl_s)


def revoke(action_id: str) -> list[str]:
    """Delete every rule tagged with this action id (TTL expiry or operator undo)."""
    t = os.environ.get("NV_NFT_TABLE", "netraverse")
    out = subprocess.run(["sudo", "-n", "nft", "-a", "list", "table", "inet", t],
                         capture_output=True, text=True, timeout=10).stdout
    chain, cmds = None, []
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("chain "):
            chain = s.split()[1]
        if f"nv:{action_id}" in s and "# handle" in s:
            h = s.rsplit("# handle", 1)[1].strip()
            cmds.append(f"nft delete rule inet {t} {chain} handle {shlex.quote(h)}")
    for c in cmds:
        subprocess.run(["sudo", "-n", "sh", "-c", c], capture_output=True, text=True, timeout=10)
    return cmds
