#!/usr/bin/env bash
# Stage 3 - Simulated lateral movement: from the "compromised" host, probe other internal peers.
# Run ON the lab victim (or a VM standing in for it). usage: NV_I_OWN_THIS_TARGET=yes ./03_lateral.sh 192.168.0.0/28
source "$(dirname "$0")/_guard.sh"; NET="${1:?cidr}"; require_private "${NET%%/*}"
nmap -sT -T3 -p 22,139,445,3389,5985 "$NET"
