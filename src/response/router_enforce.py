"""Router-side enforcement — push a real block at the gateway for network-wide
containment, so an attack strictly between two other devices can be stopped even
though the sensor is not in its path.

Enforcement is a **real** SSH command to the router (OpenWrt/nft/iptables). It is
env-driven and inert until configured, so the sensor's own nftables enforcement
always works on its own; the router is an additive second point of control.

Env:
  NETRAVERSE_ROUTER_ENABLE   "1" to enable router enforcement (default off)
  NETRAVERSE_ROUTER_HOST     router IP (default 192.168.0.1)
  NETRAVERSE_ROUTER_USER     ssh user (e.g. root)
  NETRAVERSE_ROUTER_PASSWORD ssh password (uses sshpass; or use a key instead)
  NETRAVERSE_ROUTER_KEY      path to an ssh private key (alternative to password)
  NETRAVERSE_ROUTER_FW       firewall backend: "nft" | "iptables" (default nft)

Each action's rule is tagged with the action id (nft table ``nv_<id>`` / an
iptables comment) so rollback is deterministic. The block is by source IP on the
FORWARD path (traffic the router routes between/through devices).
"""

from __future__ import annotations

import os
import shlex
import subprocess
from typing import Any


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


class RouterExecutor:
    """Apply/rollback a block on the gateway over SSH. No-op unless enabled."""

    def __init__(
        self,
        *,
        enabled: bool | None = None,
        host: str | None = None,
        user: str | None = None,
        password: str | None = None,
        key: str | None = None,
        firewall: str | None = None,
        timeout: float = 8.0,
    ):
        self.enabled = (_env("NETRAVERSE_ROUTER_ENABLE", "0") == "1") if enabled is None else bool(enabled)
        self.host = host or _env("NETRAVERSE_ROUTER_HOST", "192.168.0.1")
        self.user = user or _env("NETRAVERSE_ROUTER_USER", "root")
        self.password = password if password is not None else _env("NETRAVERSE_ROUTER_PASSWORD")
        self.key = key if key is not None else _env("NETRAVERSE_ROUTER_KEY")
        self.firewall = firewall or _env("NETRAVERSE_ROUTER_FW", "nft")
        self.timeout = timeout

    def _ssh(self, remote_cmd: str) -> str:
        base = ["ssh", "-o", "BatchMode=no", "-o", "StrictHostKeyChecking=accept-new",
                "-o", f"ConnectTimeout={int(self.timeout)}"]
        if self.key:
            base += ["-i", self.key, "-o", "BatchMode=yes"]
        target = f"{self.user}@{self.host}"
        cmd = base + [target, remote_cmd]
        if self.password and not self.key:
            cmd = ["sshpass", "-e"] + cmd
        env = dict(os.environ)
        if self.password and not self.key:
            env["SSHPASS"] = self.password
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=self.timeout + 5, env=env, check=False)
        if result.returncode != 0:
            raise RuntimeError((result.stderr or result.stdout or "router ssh failed").strip())
        return result.stdout.strip()

    def _table(self, action_id: str) -> str:
        return f"nv_{action_id[:16]}"

    def apply(self, action: dict[str, Any]) -> dict[str, Any]:
        if not self.enabled:
            return {"enabled": False, "note": "router enforcement not configured"}
        ip = action["target_ip"]
        table = self._table(action["action_id"])
        if self.firewall == "iptables":
            cmd = (f"iptables -I FORWARD -s {shlex.quote(ip)} -j DROP "
                   f"-m comment --comment {shlex.quote(table)}")
        else:  # nft (OpenWrt 22.03+)
            fam = "ip6" if ":" in ip else "ip"
            cmd = (f"nft add table inet {table} && "
                   f"nft add chain inet {table} fwd '{{ type filter hook forward priority -50; policy accept; }}' && "
                   f"nft add rule inet {table} fwd {fam} saddr {ip} counter drop")
        out = self._ssh(cmd)
        return {"enabled": True, "host": self.host, "firewall": self.firewall,
                "table": table, "rule": cmd, "output": out}

    def rollback(self, action: dict[str, Any]) -> dict[str, Any]:
        if not self.enabled:
            return {"enabled": False}
        table = self._table(action["action_id"])
        if self.firewall == "iptables":
            cmd = (f"iptables -S FORWARD | grep -- '--comment {table}' | "
                   f"sed 's/^-A/-D/' | while read -r r; do iptables $r; done; true")
        else:
            cmd = f"nft delete table inet {table} 2>/dev/null; true"
        out = self._ssh(cmd)
        return {"enabled": True, "host": self.host, "rolled_back": True, "output": out}


class CompositeExecutor:
    """Apply/rollback on the sensor (nft) and, additively, the router.

    A router failure does not fail the whole action — the sensor block still
    stands and the router error is recorded for the operator.
    """

    def __init__(self, sensor: Any, router: RouterExecutor | None = None):
        self.sensor = sensor
        self.router = router or RouterExecutor()

    def apply(self, action: dict[str, Any]) -> dict[str, Any]:
        result = self.sensor.apply(action)
        try:
            result["router"] = self.router.apply(action)
        except Exception as exc:  # noqa: BLE001 - report, do not undo the sensor block
            result["router"] = {"enabled": self.router.enabled, "error": str(exc)}
        return result

    def rollback(self, action: dict[str, Any]) -> None:
        self.sensor.rollback(action)
        try:
            self.router.rollback(action)
        except Exception:  # noqa: BLE001 - sensor rollback already succeeded
            pass


__all__ = ["RouterExecutor", "CompositeExecutor"]
