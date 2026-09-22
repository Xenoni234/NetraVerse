"""Safe, auditable response actions for the live demonstration.

The browser can request only one of the small set of actions declared in
``ACTION_TYPES``.  Commands are built by this module; arbitrary shell input is
never accepted.  The default is dry-run.  Real nftables changes require both an
``enforce`` request and ``NETRAVERSE_LIVE_ENFORCE=1`` on the server.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ACTION_TYPES = {
    "block_source_ip",
    "block_destination_ip",
    "block_attack_port",
    "rate_limit",
    "restrict_east_west",
    "isolate_host",
}
MAX_TTL_SECONDS = 3600
PREVIEW_TTL_SECONDS = 600
_ID_RE = re.compile(r"^[a-f0-9]{8,32}$")


class ActionValidationError(ValueError):
    """Raised when a response request is unsafe or malformed."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None = None) -> str:
    return (value or _now()).isoformat().replace("+00:00", "Z")


def _parse_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError as exc:
        raise ActionValidationError("target_ip must be a valid IPv4 or IPv6 address") from exc


def _parse_port(value: Any, *, required: bool = False) -> int | None:
    if value is None or value == "":
        if required:
            raise ActionValidationError("target_port is required for this action")
        return None
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ActionValidationError("target_port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ActionValidationError("target_port must be between 1 and 65535")
    return port


class NftablesExecutor:
    """Apply one response in an isolated nftables table.

    A per-action table makes rollback deterministic: deleting the table removes
    every rule created by that action without depending on a fragile rule handle.
    """

    def __init__(self, *, nft_binary: str = "nft", timeout: float = 5.0, sudo: bool | None = None):
        self.nft_binary = nft_binary
        self.timeout = timeout
        # Real enforcement usually needs root; prepend sudo unless told otherwise
        # (set up passwordless `sudo nft` on the sensor so this never prompts).
        self.sudo = (os.environ.get("NETRAVERSE_NFT_SUDO", "1") == "1") if sudo is None else bool(sudo)

    @staticmethod
    def _table_name(action_id: str) -> str:
        return f"nv_{action_id[:16]}"

    def _run(self, args: list[str]) -> str:
        cmd = (["sudo", "-n"] if self.sudo else []) + [self.nft_binary, *args]
        try:
            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("nftables binary was not found on the monitored server") from exc
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or exc.stdout or "nftables command failed").strip()
            raise RuntimeError(detail) from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("nftables command timed out") from exc
        return result.stdout.strip()

    def apply(self, action: dict[str, Any]) -> dict[str, Any]:
        action_id = action["action_id"]
        table = self._table_name(action_id)
        target_ip = action["target_ip"]
        port = action.get("target_port")
        action_type = action["action_type"]

        self._run(["add", "table", "inet", table])
        hook = "output" if action_type == "block_destination_ip" else "input"
        chain = "filter"
        self._run([
            "add", "chain", "inet", table, chain,
            f"{{ type filter hook {hook} priority -50; policy accept; }}",
        ])

        family_flag = "ip6" if ":" in target_ip else "ip"
        # Port controls target the monitored destination host on inbound traffic;
        # source/destination-IP controls retain their original directions.
        direction = "daddr" if action_type in {"block_destination_ip", "block_attack_port", "rate_limit"} else "saddr"
        rule = ["add", "rule", "inet", table, chain, family_flag, direction, target_ip]
        if action_type in {"block_attack_port", "rate_limit"}:
            rule.extend(["tcp", "dport", str(port)])
        if action_type == "rate_limit":
            rule.extend(["limit", "rate", "20/second", "burst", "40", "accept"])
        else:
            rule.extend(["counter", "drop"])
        self._run(rule)
        if action_type == "rate_limit":
            # The chain policy is accept, so explicitly drop packets that did
            # not match the bounded accept rule.
            overflow = ["add", "rule", "inet", table, chain, family_flag, direction, target_ip,
                        "tcp", "dport", str(port), "counter", "drop"]
            self._run(overflow)
        return {"table": table, "chain": chain, "hook": hook, "rule": "nft " + " ".join(rule[1:])}

    def rollback(self, action: dict[str, Any]) -> None:
        self._run(["delete", "table", "inet", self._table_name(action["action_id"])])


class ActionStore:
    """Durable preview/approval/rollback state for live response actions."""

    def __init__(
        self,
        path: Path | str,
        *,
        dry_run: bool = True,
        enforce_enabled: bool | None = None,
        management_ips: set[str] | None = None,
        executor: NftablesExecutor | None = None,
    ):
        self.path = Path(path)
        self.dry_run = bool(dry_run)
        self.enforce_enabled = (
            bool(enforce_enabled)
            if enforce_enabled is not None
            else os.environ.get("NETRAVERSE_LIVE_ENFORCE", "0") == "1"
        )
        self.management_ips = {str(ipaddress.ip_address(ip)) for ip in (management_ips or set())}
        self.executor = executor or NftablesExecutor()
        self._lock = threading.RLock()
        self._records: dict[str, dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                self._records = {str(k): dict(v) for k, v in data.items() if isinstance(v, dict)}
        except (OSError, ValueError):
            # A corrupt audit file must not prevent the monitoring UI from
            # starting.  The next write replaces it with a valid store.
            self._records = {}

    def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(self._records, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)

    def _validate(self, payload: dict[str, Any]) -> dict[str, Any]:
        action_type = str(payload.get("action_type", ""))
        if action_type not in ACTION_TYPES:
            raise ActionValidationError(f"unsupported action_type: {action_type or '<empty>'}")
        target_ip = _parse_ip(payload.get("target_ip", ""))
        needs_port = action_type in {"block_attack_port", "rate_limit"}
        port = _parse_port(payload.get("target_port"), required=needs_port)
        if action_type == "block_source_ip" and target_ip in self.management_ips:
            raise ActionValidationError("refusing to block a protected management IP")
        try:
            ttl = int(payload.get("ttl_seconds", 300))
        except (TypeError, ValueError) as exc:
            raise ActionValidationError("ttl_seconds must be an integer") from exc
        if not 1 <= ttl <= MAX_TTL_SECONDS:
            raise ActionValidationError(f"ttl_seconds must be between 1 and {MAX_TTL_SECONDS}")
        host = str(payload.get("host", "")).strip()
        alert_id = str(payload.get("alert_id", "")).strip()
        reason = str(payload.get("reason", "")).strip()
        if not host or not alert_id or not reason:
            raise ActionValidationError("host, alert_id and reason are required")
        mode = str(payload.get("mode", "dry_run"))
        if mode not in {"dry_run", "enforce"}:
            raise ActionValidationError("mode must be dry_run or enforce")
        return {
            "host": host, "alert_id": alert_id, "action_type": action_type,
            "target_ip": target_ip, "target_port": port, "ttl_seconds": ttl,
            "reason": reason[:500], "mode": mode,
        }

    def preview(self, payload: dict[str, Any], *, operator: str) -> dict[str, Any]:
        clean = self._validate(payload)
        action_id = uuid.uuid4().hex
        created = _now()
        record = {
            **clean, "preview_id": action_id, "action_id": action_id,
            "operator": operator, "created_at": _iso(created),
            "expires_at": _iso(created + timedelta(seconds=PREVIEW_TTL_SECONDS)),
            "status": "preview",
            "applied": False, "rollback_available": False,
            "dry_run": self.dry_run or clean["mode"] != "enforce" or not self.enforce_enabled,
            "rule": self._rule_summary(clean, action_id),
        }
        with self._lock:
            self._records[action_id] = record
            self._persist()
        return dict(record)

    @staticmethod
    def _rule_summary(clean: dict[str, Any], action_id: str) -> str:
        scope = f"{clean['target_ip']}:{clean['target_port']}" if clean.get("target_port") else clean["target_ip"]
        return f"{clean['action_type']} {scope} for {clean['ttl_seconds']}s (rule nv_{action_id[:16]})"

    def approve(self, preview_id: str, *, operator: str) -> dict[str, Any]:
        if not _ID_RE.match(preview_id):
            raise ActionValidationError("invalid preview_id")
        with self._lock:
            self._expire_locked()
            record = self._records.get(preview_id)
            if record is None:
                raise KeyError("preview not found")
            if record["status"] != "preview":
                raise ActionValidationError("preview is no longer approvable")
            if _now() > datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00")):
                record["status"] = "expired"
                self._persist()
                raise ActionValidationError("preview has expired")
            record["approved_at"] = _iso()
            record["operator"] = operator
            try:
                if record["dry_run"]:
                    record["status"] = "dry_run"
                    record["applied"] = False
                    record["rollback_available"] = False
                else:
                    record["executor"] = self.executor.apply(record)
                    record["status"] = "applied"
                    record["applied"] = True
                    record["rollback_available"] = True
            except Exception as exc:  # noqa: BLE001 - persist a visible failure state
                record["status"] = "failed"
                record["error"] = str(exc)
                self._persist()
                raise RuntimeError(str(exc)) from exc
            record["expires_at"] = _iso(_now() + timedelta(seconds=record["ttl_seconds"]))
            self._persist()
            return dict(record)

    def rollback(self, action_id: str, *, operator: str) -> dict[str, Any]:
        if not _ID_RE.match(action_id):
            raise ActionValidationError("invalid action_id")
        with self._lock:
            self._expire_locked()
            record = self._records.get(action_id)
            if record is None:
                raise KeyError("action not found")
            if record.get("status") not in {"applied", "dry_run"}:
                raise ActionValidationError("action is not active")
            if record.get("applied"):
                try:
                    self.executor.rollback(record)
                except Exception as exc:  # noqa: BLE001
                    record["rollback_error"] = str(exc)
                    self._persist()
                    raise RuntimeError(str(exc)) from exc
            record["status"] = "rolled_back"
            record["rollback_at"] = _iso()
            record["rollback_operator"] = operator
            record["rollback_available"] = False
            self._persist()
            return dict(record)

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            self._expire_locked()
            return sorted((dict(v) for v in self._records.values()), key=lambda x: x.get("created_at", ""), reverse=True)

    def get(self, action_id: str) -> dict[str, Any] | None:
        with self._lock:
            self._expire_locked()
            record = self._records.get(action_id)
            return dict(record) if record else None

    def _expire_locked(self) -> None:
        """Enforce TTLs when the store is observed, without a background thread."""
        changed = False
        now = _now()
        for record in self._records.values():
            if record.get("status") not in {"applied", "dry_run"}:
                continue
            expires = record.get("expires_at")
            if not expires or now <= datetime.fromisoformat(str(expires).replace("Z", "+00:00")):
                continue
            if record.get("applied"):
                try:
                    self.executor.rollback(record)
                    record["rollback_at"] = _iso(now)
                except Exception as exc:  # noqa: BLE001 - keep visible for operator review
                    record["rollback_error"] = str(exc)
                    continue
            record["status"] = "expired"
            record["rollback_available"] = False
            changed = True
        if changed:
            self._persist()


__all__ = ["ACTION_TYPES", "ActionStore", "ActionValidationError", "NftablesExecutor"]
