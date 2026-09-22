"""Discover the real devices on the monitored LAN and refresh network.json.

Runs on the Linux sensor. Enumerates the whole subnet (no device cap), enriches
with vendor/hostname, and writes ``reports/live/network.json`` — the roster the
topology view and ``/api/network/forecast`` read. Loops on an interval so the
topology tracks devices joining/leaving; ``--once`` for a single snapshot.

    python scripts/discover_network.py --interval 30

Fully offline: only the local subnet is contacted.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.discovery.lan_scan import (  # noqa: E402
    DEFAULT_NETWORK_JSON,
    local_network,
    network_snapshot,
    write_network_json,
)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Discover LAN devices for the live topology")
    ap.add_argument("--output", default=str(DEFAULT_NETWORK_JSON),
                    help="where to write the roster JSON")
    ap.add_argument("--interval", type=int, default=30, help="seconds between rescans")
    ap.add_argument("--interface", default=None,
                    help="force the monitored interface (default: the box's default-route dev)")
    ap.add_argument("--no-hostnames", action="store_true",
                    help="skip reverse-DNS (faster on quiet networks)")
    ap.add_argument("--once", action="store_true", help="single scan then exit")
    args = ap.parse_args(argv)

    ctx = local_network(prefer_interface=args.interface)
    print(f"[discover] subnet={ctx.cidr} gateway={ctx.gateway} "
          f"sensor={ctx.sensor_ip} iface={ctx.interface}")

    while True:
        snap = network_snapshot(ctx, resolve_hostnames=not args.no_hostnames)
        path = write_network_json(snap, args.output)
        named = sum(1 for d in snap["devices"] if d.get("hostname"))
        print(f"[discover] {snap['device_count']} devices "
              f"({named} named) -> {path}")
        if args.once:
            return 0
        time.sleep(max(5, args.interval))


if __name__ == "__main__":
    raise SystemExit(main())
