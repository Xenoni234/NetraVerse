"""Dynamic LAN discovery for the live network view.

Enumerates every device currently on the monitored subnet and returns a roster
the topology view and the network-forecast API consume. Design goals:

- **No device cap.** Whatever is on the ``/24`` (or the sensor's actual prefix)
  is discovered; the topology is built around the real count.
- **Best-effort and layered.** Prefer ``nmap -sn`` (fast, does reverse-DNS and
  MAC vendor), fall back to a scapy ARP sweep, then to a plain ping sweep read
  back from the kernel ARP/neighbour table. Any one of these alone still yields
  a usable roster.
- **Fully offline.** Only the local subnet is touched; vendor lookup uses OUI
  files already on the host (nmap / ieee-data / arp-scan) when present.
- **Truthful.** ``has_telemetry`` starts False; the forecaster join marks the
  hosts we actually have flow windows for. Discovered-but-unmonitored devices
  stay visible but are not claimed to be forecast.

Runs on the Linux sensor (uses ``ip``, ``ping``, optionally ``nmap``/scapy).
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Iterable

from src.data.paths import REPORTS_DIR

#: Where the live roster is written for the API / topology to read.
DEFAULT_NETWORK_JSON: Path = REPORTS_DIR / "live" / "network.json"

#: System OUI databases to try, in order, for MAC -> vendor resolution.
_OUI_FILES: tuple[str, ...] = (
    "/usr/share/nmap/nmap-mac-prefixes",
    "/var/lib/ieee-data/oui.txt",
    "/usr/share/ieee-data/oui.txt",
    "/usr/share/arp-scan/ieee-oui.txt",
)

_MAC_RE = re.compile(r"([0-9a-f]{2}[:-]){5}[0-9a-f]{2}", re.IGNORECASE)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Device:
    """One discovered host on the monitored network."""

    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    role: str = "device"          # gateway | sensor | device
    last_seen: str = field(default_factory=_utc_now)
    has_telemetry: bool = False   # set True by the forecaster join
    source: str = "arp"           # how it was discovered: nmap | arp | ping

    def to_json(self) -> dict:
        return asdict(self)


@dataclass
class NetworkContext:
    """The subnet we are monitoring, derived from the sensor's own routing."""

    cidr: str                     # e.g. "192.168.0.0/24"
    gateway: str | None           # e.g. "192.168.0.1"
    sensor_ip: str | None         # this host's address on that subnet
    interface: str | None         # e.g. "wlp0s20f3"

    def to_json(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Sensor / subnet context
# --------------------------------------------------------------------------- #
def _run(cmd: list[str], timeout: float = 10.0) -> str:
    """Run a command and return stdout ('' on any failure); never raises."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def local_network(prefer_interface: str | None = None) -> NetworkContext:
    """Derive the monitored subnet from the host's default route.

    Uses ``ip -j route``/``ip -j addr`` (JSON) when available, and falls back to
    a UDP-socket trick for the primary source IP. Ignores virtual bridges
    (docker/virbr) and the Tailscale overlay by preferring the default-route
    interface.
    """
    gateway: str | None = None
    interface: str | None = prefer_interface
    sensor_ip: str | None = None

    # Default route → gateway + egress interface.
    routes = _run(["ip", "-j", "route", "show", "default"])
    try:
        for entry in json.loads(routes or "[]"):
            gateway = entry.get("gateway") or gateway
            if not prefer_interface:
                interface = entry.get("dev") or interface
            if entry.get("prefsrc"):
                sensor_ip = entry["prefsrc"]
            if gateway and interface:
                break
    except (json.JSONDecodeError, TypeError):
        pass

    # The interface's IPv4 + prefix length → the subnet CIDR.
    cidr: str | None = None
    addrs = _run(["ip", "-j", "addr", "show"] + (["dev", interface] if interface else []))
    try:
        for iface in json.loads(addrs or "[]"):
            dev = iface.get("ifname")
            if interface and dev != interface:
                continue
            for info in iface.get("addr_info", []):
                if info.get("family") != "inet":
                    continue
                local, prefix = info.get("local"), info.get("prefixlen")
                if local and prefix is not None:
                    sensor_ip = sensor_ip or local
                    net = ipaddress.ip_network(f"{local}/{prefix}", strict=False)
                    cidr = str(net)
                    interface = interface or dev
                    break
            if cidr:
                break
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    if sensor_ip is None:
        # Last resort: the source IP the kernel would use for an off-link dest.
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((gateway or "8.8.8.8", 80))
            sensor_ip = s.getsockname()[0]
            s.close()
        except OSError:
            pass
    if cidr is None and sensor_ip is not None:
        cidr = str(ipaddress.ip_network(f"{sensor_ip}/24", strict=False))

    return NetworkContext(cidr=cidr or "192.168.0.0/24", gateway=gateway,
                          sensor_ip=sensor_ip, interface=interface)


# --------------------------------------------------------------------------- #
# Vendor (OUI) + hostname resolution
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=1)
def _oui_table() -> dict[str, str]:
    """Build a MAC-prefix -> vendor map from whatever OUI file exists locally."""
    table: dict[str, str] = {}
    for path in _OUI_FILES:
        p = Path(path)
        if not p.exists():
            continue
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # nmap format: "0016B6 Cisco-Linksys"; ieee "00-16-B6   (hex) Vendor"
            m = re.match(r"^([0-9A-Fa-f]{2}[-: ]?[0-9A-Fa-f]{2}[-: ]?[0-9A-Fa-f]{2})\s+(.*)$", line)
            if not m:
                continue
            prefix = re.sub(r"[^0-9A-Fa-f]", "", m.group(1)).upper()[:6]
            vendor = m.group(2).replace("(hex)", "").strip()
            if len(prefix) == 6 and vendor:
                table.setdefault(prefix, vendor)
        if table:
            break
    return table


def _vendor_for(mac: str | None) -> str | None:
    if not mac:
        return None
    prefix = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()[:6]
    return _oui_table().get(prefix)


def _hostname_for(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


# --------------------------------------------------------------------------- #
# Discovery backends
# --------------------------------------------------------------------------- #
def _kernel_neighbours(interface: str | None) -> dict[str, str]:
    """Read the current ARP/neighbour table -> {ip: mac} for IPv4 REACHABLE/STALE."""
    out = _run(["ip", "-j", "neigh", "show"] + (["dev", interface] if interface else []))
    result: dict[str, str] = {}
    try:
        for n in json.loads(out or "[]"):
            ip, mac, state = n.get("dst"), n.get("lladdr"), n.get("state", [])
            if not ip or not mac or ":" not in ip and "." not in ip:
                continue
            if "." not in ip:  # skip IPv6 for the roster keys
                continue
            if isinstance(state, list) and "FAILED" in state:
                continue
            result[ip] = mac.lower()
    except (json.JSONDecodeError, TypeError):
        pass
    return result


def _ping(ip: str) -> bool:
    return bool(_run(["ping", "-c", "1", "-W", "1", ip], timeout=3.0))


def _ping_sweep(cidr: str, workers: int = 64) -> None:
    """Warm the ARP table by pinging every host in the subnet (parallel)."""
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in net.hosts()]
    if len(hosts) > 1024:  # guard against absurd prefixes
        hosts = hosts[:1024]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(_ping, hosts))


def _have(cmd: str) -> bool:
    return bool(_run(["bash", "-lc", f"command -v {cmd}"]).strip())


def _nmap_sweep(cidr: str) -> dict[str, Device]:
    """Use ``nmap -sn`` (ping scan) with XML-ish grep output; empty on failure."""
    if not _have("nmap"):
        return {}
    out = _run(["nmap", "-sn", "-n", "--max-retries", "1", cidr], timeout=60.0)
    devices: dict[str, Device] = {}
    current_ip: str | None = None
    for line in out.splitlines():
        m_ip = re.search(r"Nmap scan report for ([\d.]+)", line)
        if m_ip:
            current_ip = m_ip.group(1)
            devices[current_ip] = Device(ip=current_ip, source="nmap")
            continue
        m_mac = re.search(r"MAC Address: ([0-9A-Fa-f:]{17})\s*(?:\((.*)\))?", line)
        if m_mac and current_ip:
            devices[current_ip].mac = m_mac.group(1).lower()
            if m_mac.group(2):
                devices[current_ip].vendor = m_mac.group(2).strip()
    return devices


def _scapy_arp(cidr: str, interface: str | None, timeout: float = 3.0) -> dict[str, str]:
    """Active ARP sweep via scapy -> {ip: mac}. Empty if scapy/L2 send fails."""
    try:
        from scapy.all import ARP, Ether, srp  # type: ignore
    except Exception:
        return {}
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
            timeout=timeout, verbose=False, iface=interface,
        )
    except Exception:
        return {}
    return {rcv.psrc: rcv.hwsrc.lower() for _, rcv in ans}


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def discover(ctx: NetworkContext | None = None, *, resolve_hostnames: bool = True) -> list[Device]:
    """Discover every reachable device on the monitored subnet.

    Layered: nmap -> scapy ARP -> ping sweep + kernel neighbours, merged. Vendor
    and hostname are enriched from local data only. Returns devices sorted by IP.
    """
    ctx = ctx or local_network()
    cidr = ctx.cidr
    merged: dict[str, Device] = {}

    # 1) nmap (richest: ip + mac + vendor in one pass)
    for ip, dev in _nmap_sweep(cidr).items():
        merged[ip] = dev

    # 2) active ARP (fills MACs nmap may lack without root)
    for ip, mac in _scapy_arp(cidr, ctx.interface).items():
        d = merged.setdefault(ip, Device(ip=ip, source="arp"))
        d.mac = d.mac or mac

    # 3) ping sweep -> kernel neighbour table (works everywhere, no privileges)
    if len(merged) <= 1:
        _ping_sweep(cidr)
    for ip, mac in _kernel_neighbours(ctx.interface).items():
        if ip not in ipaddress.ip_network(cidr, strict=False):
            continue
        d = merged.setdefault(ip, Device(ip=ip, source="ping"))
        d.mac = d.mac or mac

    # Always include the sensor itself, even if it never ARPs itself.
    if ctx.sensor_ip and ctx.sensor_ip not in merged:
        merged[ctx.sensor_ip] = Device(ip=ctx.sensor_ip, source="self")

    # Enrich + classify.
    def _finish(dev: Device) -> Device:
        dev.vendor = dev.vendor or _vendor_for(dev.mac)
        if resolve_hostnames and not dev.hostname:
            dev.hostname = _hostname_for(dev.ip)
        dev.role = _role_for(dev.ip, ctx)
        dev.last_seen = _utc_now()
        return dev

    with ThreadPoolExecutor(max_workers=32) as pool:
        devices = list(pool.map(_finish, merged.values()))

    return sorted(devices, key=lambda d: tuple(int(o) for o in d.ip.split(".")))


def _role_for(ip: str, ctx: NetworkContext) -> str:
    if ctx.gateway and ip == ctx.gateway:
        return "gateway"
    if ctx.sensor_ip and ip == ctx.sensor_ip:
        return "sensor"
    return "device"


def _links(devices: Iterable[Device], ctx: NetworkContext) -> list[dict]:
    """Star topology: every device links to the gateway (real L2 default path)."""
    hub = ctx.gateway or (ctx.sensor_ip or "")
    return [{"a": d.ip, "b": hub} for d in devices if d.ip != hub and hub]


def network_snapshot(ctx: NetworkContext | None = None, **kw) -> dict:
    """Discover and return a JSON-ready roster (devices + links + context)."""
    ctx = ctx or local_network()
    devices = discover(ctx, **kw)
    return {
        "generated_at": _utc_now(),
        "subnet": ctx.cidr,
        "gateway": ctx.gateway,
        "sensor": ctx.sensor_ip,
        "interface": ctx.interface,
        "device_count": len(devices),
        "devices": [d.to_json() for d in devices],
        "links": _links(devices, ctx),
    }


def write_network_json(snapshot: dict, path: Path | str = DEFAULT_NETWORK_JSON) -> Path:
    """Atomically write the roster the API/topology reads."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    tmp.replace(path)
    return path
