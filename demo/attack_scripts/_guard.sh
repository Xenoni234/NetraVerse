#!/usr/bin/env bash
# R11: only ever attack devices on your own private lab network.
set -euo pipefail
require_private() {
  local ip="$1"
  if [[ ! "$ip" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.) ]]; then
    echo "Refusing: $ip is not an RFC1918 address. Only target devices you own." >&2; exit 2
  fi
  if [[ "${NV_I_OWN_THIS_TARGET:-}" != "yes" ]]; then
    echo "Set NV_I_OWN_THIS_TARGET=yes to confirm $ip is your own lab device." >&2; exit 2
  fi
}
