"""Regenerate and validate the bundled campaign CSV and PCAP."""
from __future__ import annotations

from demo.make_demo_scenario import main as make_campaign
from demo.validate_artifacts import validate


def main() -> None:
    make_campaign()
    result = validate()
    print(f"validated: {result['positive_compromise_leads']} positive compromise leads; "
          f"{result['distinct_alert_steps']} distinct alert timelines")


if __name__ == "__main__":
    main()
