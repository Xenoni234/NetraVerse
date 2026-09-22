"""Live LAN discovery — enumerate the real devices on the monitored network.

The forecaster already runs per host; this package supplies the *roster* of
hosts to forecast over and to draw in the topology. It is deliberately
best-effort and offline: it never contacts the internet, only the local subnet.
"""

from src.discovery.lan_scan import (
    Device,
    NetworkContext,
    discover,
    local_network,
    network_snapshot,
    write_network_json,
)

__all__ = [
    "Device",
    "NetworkContext",
    "discover",
    "local_network",
    "network_snapshot",
    "write_network_json",
]
