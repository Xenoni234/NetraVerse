"""Shared helper for the launch_*.py sensor triggers."""
from __future__ import annotations

import json
import sys
import time
import urllib.request

URL = "http://localhost:8600/api/live/trigger"


def launch(scenario: str, title: str, mitre: str, src: str, dst: str) -> None:
    print(f"\n  NETRAVERSE :: live sensor  eth0")
    print(f"  campaign   : {title}")
    print(f"  technique  : {mitre}")
    print(f"  source     : {src}  ->  target {dst}")
    for step in ("arming campaign profile", "streaming flows to sensor", "handing off to world model"):
        print(f"  [+] {step} ...")
        time.sleep(0.4)
    req = urllib.request.Request(URL, data=json.dumps({"scenario": scenario, "src": src, "dst": dst}).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            ev = json.loads(r.read())
        print(f"  [ok] campaign #{ev['id']} live - watch the console\n")
    except OSError as e:
        print(f"  [x] console not reachable at {URL}: {e}")
        sys.exit(1)
