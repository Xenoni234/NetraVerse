"""Record an operator-controlled live validation marker in UTC.

This deliberately does not launch traffic or execute a response.  It gives the
operator a reliable attack start/stop timestamp for lead-time measurement.
"""

from __future__ import annotations

import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Record a live validation marker")
    parser.add_argument("--scenario", required=True,
                        choices=["benign", "recon", "initial_access", "execution", "c2",
                                 "lateral_movement", "impact"])
    parser.add_argument("--phase", required=True, choices=["start", "stop"])
    parser.add_argument("--host", default="100.72.80.52")
    parser.add_argument("--expected-stage", default="")
    parser.add_argument("--note", default="")
    parser.add_argument("--output", default="reports/live/test_runs.jsonl")
    args = parser.parse_args(argv)
    record = {
        "run_id": uuid.uuid4().hex[:16], "scenario": args.scenario, "phase": args.phase,
        "host": args.host, "expected_stage": args.expected_stage,
        "note": args.note, "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")
    print(json.dumps(record))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
