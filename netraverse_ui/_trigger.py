"""Shared helper for the launch_*.py sensor triggers.

Each launcher POSTs an attack "start", then stays running so the attack is
"live" until you press Ctrl+C — which POSTs a "stop" so the console lets the
risk decay (a real attacker attacking, then stopping).
"""
from __future__ import annotations

import json
import sys
import time
import urllib.request

URL = "http://localhost:8600/api/live/trigger"


def _post(scenario: str, action: str, src=None, dst=None) -> dict:
    body = json.dumps({"scenario": scenario, "action": action, "src": src, "dst": dst}).encode()
    req = urllib.request.Request(URL, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def launch(scenario: str, title: str, mitre: str, src: str, dst: str) -> None:
    print(f"\n  NETRAVERSE :: live sensor  eth0")
    print(f"  campaign   : {title}")
    print(f"  technique  : {mitre}")
    print(f"  source     : {src}  ->  target {dst}")
    for step in ("arming campaign profile", "streaming flows to sensor", "handing off to world model"):
        print(f"  [+] {step} ...")
        time.sleep(0.4)
    try:
        ev = _post(scenario, "start", src, dst)
        print(f"  [ok] campaign #{ev['id']} live - watch the console")
    except OSError as e:
        print(f"  [x] console not reachable at {URL}: {e}")
        sys.exit(1)
    print("  [*] attack RUNNING - press Ctrl+C to stop the attack\n")
    try:
        n = 0
        while True:
            time.sleep(3)
            n += 1
            print(f"  [.] {scenario} active ... ({n * 3}s)")
    except KeyboardInterrupt:
        try:
            _post(scenario, "stop", src, dst)
        except OSError:
            pass
        print(f"\n  [x] attack stopped - risk will decay in the console\n")
