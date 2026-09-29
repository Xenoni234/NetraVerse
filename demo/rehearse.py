"""Start a local-only safe live forecasting scenario.

Examples:
    python -m demo.rehearse --scenario reconnaissance
    python -m demo.rehearse --scenario impact --speed 20

The command only POSTs to a loopback NetraVerse API. It never launches an
attack tool, captures packets, opens a target socket, or changes a firewall.
"""
from __future__ import annotations

import argparse
import json
import os
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from demo.scenario_catalog import SCENARIOS


def _loopback(url: str) -> bool:
    host = urlparse(url).hostname
    return host in {"127.0.0.1", "localhost", "::1"}


def main() -> None:
    choices = [s.id for s in SCENARIOS]
    ap = argparse.ArgumentParser(description="Start a local-only NetraVerse safe rehearsal stream.")
    ap.add_argument("--scenario", required=True, choices=choices)
    ap.add_argument("--speed", type=float, default=12.0, help="Virtual seconds per wall-clock second.")
    ap.add_argument("--tick-s", type=float, default=1.0)
    ap.add_argument("--api-url", default=os.environ.get("NV_API_URL", "http://127.0.0.1:8000"))
    args = ap.parse_args()
    base = args.api_url.rstrip("/")
    if not _loopback(base):
        raise SystemExit("Refusing a non-loopback API URL: safe rehearsal commands are local-only.")
    payload = json.dumps({"scenario": args.scenario, "speed": args.speed, "tick_s": args.tick_s}).encode()
    req = Request(base + "/live/rehearsal/start", data=payload,
                  headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise SystemExit(f"Could not start the rehearsal API at {base}: {exc}") from exc
    status = result.get("status", {})
    print(f"started {args.scenario}: mode={status.get('mode')} speed={status.get('speed')}x")
    print("Open Live Monitor; the forecast will build as the safe stream advances.")


if __name__ == "__main__":
    main()
