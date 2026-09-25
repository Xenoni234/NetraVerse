#!/usr/bin/env bash
# Full rehearsed kill-chain: recon -> brute force -> lateral probe, with pauses so the
# dashboard shows the curve building. Record the sensor side with tcpdump for the R12 fallback PCAP:
#   sudo tcpdump -i <iface> -w demo/fallback_pcap/live_demo.pcap host <target>
set -euo pipefail; D="$(dirname "$0")"; T="${1:?target ip}"
"$D/01_recon.sh" "$T"; sleep 90
"$D/02_bruteforce.sh" "$T" "${2:-testuser}"; sleep 60
[ -n "${3:-}" ] && "$D/03_lateral.sh" "$3" || true
